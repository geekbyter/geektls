package engine

// 会话级证书材料：自持信任库（CA bundle）与客户端证书（mTLS）。
// 语义与 requests 对齐：verify=<path|PEM> **替换**系统信任库（不叠加），
// cert=<path|PEM> 可为"证书+私钥同文件"（requests 的同文件形态）。
// 全部在 NewSession 解析完毕 —— 配置错误当场报，不留到首次握手才发现。

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	utlsb "github.com/bogdanfinn/utls"
	utls "github.com/refraction-networking/utls"
)

// certMaterial 空（nil）= 完全走系统默认：系统根证书 + 不发客户端证书。
type certMaterial struct {
	rootCAs *x509.CertPool
	// 同一份证书要喂给两套 TLS 栈：TCP 侧 refraction/utls、QUIC 内层
	// bogdanfinn/utls（两家的 Certificate 是各自定义的同形结构体）。
	certsTCP  []utls.Certificate
	certsQUIC []utlsb.Certificate
}

func (m *certMaterial) rootPool() *x509.CertPool {
	if m == nil {
		return nil
	}
	return m.rootCAs
}

func (m *certMaterial) tcpCerts() []utls.Certificate {
	if m == nil {
		return nil
	}
	return m.certsTCP
}

func (m *certMaterial) quicCerts() []utlsb.Certificate {
	if m == nil {
		return nil
	}
	return m.certsQUIC
}

// certPEM 是一段证书/私钥材料：既可以是 PEM 文本本身，也可以是文件路径
// （路径形态下若指向目录，按 requests 的 capath 语义加载目录内证书文件）。
type certPEM struct {
	label string // 报错时用："ca_bundle" / "client_cert" / "client_key"
	value string
}

func (c certPEM) empty() bool { return strings.TrimSpace(c.value) == "" }

// load 返回 PEM 字节；来源标识用于错误信息与 key 配对提示。
func (c certPEM) load() (data []byte, from string, err error) {
	v := strings.TrimSpace(c.value)
	if v == "" {
		return nil, "", nil
	}
	if strings.Contains(v, "-----BEGIN") {
		return []byte(v), c.label + " (inline PEM)", nil
	}
	fi, err := os.Stat(v)
	if err != nil {
		return nil, "", fmt.Errorf("%s: 既不是 PEM 文本也读不到文件: %w", c.label, err)
	}
	if !fi.IsDir() {
		b, err := os.ReadFile(v)
		if err != nil {
			return nil, "", fmt.Errorf("%s: read %s: %w", c.label, v, err)
		}
		return b, v, nil
	}
	// 目录：只收 *.pem/*.crt/*.cer（顺序按名字定，保证可复现）。
	names, err := os.ReadDir(v)
	if err != nil {
		return nil, "", fmt.Errorf("%s: read dir %s: %w", c.label, v, err)
	}
	var out []byte
	var files []string
	for _, e := range names {
		if e.IsDir() {
			continue
		}
		switch strings.ToLower(filepath.Ext(e.Name())) {
		case ".pem", ".crt", ".cer":
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)
	for _, n := range files {
		b, err := os.ReadFile(filepath.Join(v, n))
		if err != nil {
			return nil, "", fmt.Errorf("%s: read %s: %w", c.label, n, err)
		}
		out = append(out, b...)
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf("%s: 目录 %s 内没有 .pem/.crt/.cer 证书文件", c.label, v)
	}
	return out, v, nil
}

func loadCertMaterial(opts SessionOptions) (*certMaterial, error) {
	m := &certMaterial{}

	if cp := (certPEM{label: "ca_bundle", value: opts.CaBundle}); !cp.empty() {
		data, from, err := cp.load()
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("ca_bundle: %s 内没有解析成功的 PEM 证书", from)
		}
		m.rootCAs = pool
	}

	certPEMStr, keyPEMStr := opts.ClientCert, opts.ClientKey
	if certPEMStr == "" {
		if keyPEMStr != "" {
			return nil, fmt.Errorf("client_key 需要与 client_cert 同时提供")
		}
		return m, nil
	}

	certData, _, err := (certPEM{label: "client_cert", value: certPEMStr}).load()
	if err != nil {
		return nil, err
	}
	var keyData []byte
	if kp := (certPEM{label: "client_key", value: keyPEMStr}); !kp.empty() {
		keyData, _, err = kp.load()
		if err != nil {
			return nil, err
		}
	} else {
		// requests 形态：私钥与证书同文件 ⇒ 从 cert 材料里拆出私钥段。
		var certBlocks []byte
		certBlocks, keyData = splitCertKeyPEM(certData)
		if keyData == nil {
			return nil, fmt.Errorf("client_cert: 未找到私钥段，且没有提供 client_key（支持证书+私钥同文件）")
		}
		certData = certBlocks
	}

	c, err := tls.X509KeyPair(certData, keyData)
	if err != nil {
		return nil, fmt.Errorf("client_cert/client_key 配对失败: %w", err)
	}
	m.certsTCP = []utls.Certificate{{
		Certificate: c.Certificate,
		PrivateKey:  c.PrivateKey,
		Leaf:        c.Leaf,
	}}
	m.certsQUIC = []utlsb.Certificate{{
		Certificate: c.Certificate,
		PrivateKey:  c.PrivateKey,
		Leaf:        c.Leaf,
	}}
	return m, nil
}

// splitCertKeyPEM 把混在一起的 PEM 块拆成"仅证书块"与"第一个私钥块"。
func splitCertKeyPEM(data []byte) (certs, key []byte) {
	var keyFound bool
	for {
		b, rest := pem.Decode(data)
		if b == nil {
			break
		}
		data = rest
		enc := pem.EncodeToMemory(b)
		switch {
		case strings.Contains(b.Type, "PRIVATE KEY") && !keyFound:
			key = enc
			keyFound = true
		case strings.Contains(b.Type, "CERTIFICATE"):
			certs = append(certs, enc...)
		}
	}
	return certs, key
}
