// Package tlscore 封装 uTLS：ClientHello 构造与握手。
//
// 目录名为 core/tls 但包名刻意叫 tlscore，避免与标准库 crypto/tls 混淆。
// P1-T1 仅为集成基线：默认 HelloChrome_Auto 预设；逐字段控制在 P1-T2 落地。
package tlscore

import (
	"fmt"
	"net"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
)

// DefaultDialTimeout 是 Dial 的默认 TCP 连接超时。
const DefaultDialTimeout = 10 * time.Second

// Handshake 在已建立的 conn 上以 uTLS 完成一次客户端握手。
//
// cfg 为 nil 时使用空配置（调用方通常至少要设置 ServerName）；
// spec 为 nil 时使用 utls.HelloChrome_Auto 预设，否则套用给定 ClientHelloSpec。
// 返回的 UConn 已完成握手，可直接读写；失败时 conn 由调用方关闭。
//
// 注意 1：自定义 spec 必须以 utls.HelloCustom 为基底——用浏览器预设 ID 时
// uTLS 会在 Handshake 时重新 applyPresetByID 覆盖掉自定义 spec（实测坑）。
//
// 注意 2（**spec 单次使用**）：uTLS 的 ApplyPreset 会把状态**回写进传入的
// ClientHelloSpec 对象**，该契约写在 uTLS 自己的注释里（u_parrots.go:2764：
// "It is advised to use different specs and avoid any shared state"）。
// 本地实测到的回写点（core/tls/spec_reuse_test.go 的快照断言）：
//
//	SNI(0)        0 字节 → 本次握手用的主机名（跨主机复用会残留上一台主机名）
//	key_share(51) 占位   → 真实密钥数据（下次握手公私钥不匹配 → 握手失败）
//
// 因此**同一份 spec 不能跨连接复用**：第二次握手会以 `tls: internal error`
// 失败。请每次握手重新 CompileDetail（engine 即如此：core/engine/dial.go
// 每次拨号重新编译）。本函数在失败时会对这一误用给出针对性提示。
func Handshake(conn net.Conn, cfg *utls.Config, spec *utls.ClientHelloSpec) (uconn *utls.UConn, err error) {
	// uTLS 有几条路径会 **panic 而不是返回错误**（实测）：
	//   1) 会话缓存命中票据、但 spec 里没有 pre_shared_key(41) 占位 →
	//      u_session_controller.go:128 "initPskExt failed ..."；
	//   2) 缓存里的会话状态异常/不完整 → handshake_client.go:441 空指针（nil deref）。
	// 这是网络侧可达的路径，让调用进程崩溃不如转成错误：库边界统一兜住并把
	// panic 值带进错误信息（未识别 panic 亦如此，属"意外"语义，便于上报）。
	defer func() {
		if r := recover(); r != nil {
			uconn, err = nil, fmt.Errorf("tlscore: 握手内部 panic 已转为错误（uTLS 已知路径，请上报: %v）", r)
		}
	}()

	if cfg == nil {
		cfg = &utls.Config{}
	} else {
		cfg = cfg.Clone()
	}
	// 空 PSK 扩展（无票据的占位）线上省略——Chrome 语义；不设的话带
	// pre_shared_key 占位的 spec 在无票据时会被 uTLS 报错。
	cfg.OmitEmptyPsk = true
	helloID := utls.HelloChrome_Auto
	if spec != nil {
		helloID = utls.HelloCustom
	}
	uconn = utls.UClient(conn, cfg, helloID)
	if spec != nil {
		if err := uconn.ApplyPreset(spec); err != nil {
			return nil, err
		}
	}
	if err := uconn.Handshake(); err != nil {
		// 把"spec 被复用"这一最常见误用从 uTLS 的 `tls: internal error`
		// 变成可行动的提示（只在签名吻合时附加，不改错误本身）。
		if specHasLiteralSNI(spec) && strings.Contains(err.Error(), "internal error") {
			return nil, fmt.Errorf("%w\n  提示：该 spec 的 SNI 扩展已带主机名，疑似上一轮握手回写（spec 被跨连接复用）。"+
				"请每次握手重新 CompileDetail —— 详见 core/tls/spec_reuse_test.go", err)
		}
		return nil, err
	}
	return uconn, nil
}

// specHasLiteralSNI 判断 spec 的 SNI 扩展是否已带主机名——CompileDetail 的
// 新鲜产物只有空占位（sni:"auto"），握手后才会被 uTLS 回写成实际主机名。
func specHasLiteralSNI(spec *utls.ClientHelloSpec) bool {
	if spec == nil {
		return false
	}
	for _, e := range spec.Extensions {
		if sni, ok := e.(*utls.SNIExtension); ok && sni.ServerName != "" {
			return true
		}
	}
	return false
}

// Dial 建立 TCP 连接并在其上完成 uTLS 握手；任一步失败都会关闭底层连接。
func Dial(addr string, cfg *utls.Config, spec *utls.ClientHelloSpec) (*utls.UConn, error) {
	conn, err := net.DialTimeout("tcp", addr, DefaultDialTimeout)
	if err != nil {
		return nil, err
	}
	uconn, err := Handshake(conn, cfg, spec)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return uconn, nil
}
