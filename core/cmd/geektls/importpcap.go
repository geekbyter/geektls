// geektls import-pcap：从 Wireshark/tcpdump 的抓包文件里提取 TLS ClientHello
// 与 TCP SYN 形态，落成 E1p 记录（可直接喂 gen-profiles 生成预设，或喂
// check-profile / clienthello_hex 装载重放）。
//
// v0.2.0 起解析核下沉到 core/pcapimport（CLI 与三语言绑定共用同一核）；
// 本文件只剩 CLI 壳：参数解析、读文件、skipped 打到 stderr、JSON 输出。
// 行为与输出与下沉前逐字节一致（importpcap_test.go 原样作回归）。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	pcapimport "github.com/geekbyter/geektls/core/pcapimport"
)

const importPcapUsage = `geektls import-pcap — 从 Wireshark/tcpdump 抓包提取指纹记录（E1p）

用法：
  geektls import-pcap --pcap <文件> [选项]

选项：
  --pcap <文件>       pcap 或 pcapng（Wireshark 默认保存格式）
  --stream <n>        取第 n 条含 ClientHello 的流（默认 1）
  --all               导出全部含 ClientHello 的流（输出 JSON 数组）
  --tcp-only          不要求 ClientHello，只导 TCP 形态（SYN/TTL/窗口/选项）
  --ua "<UA 串>"      补 user-agent（pcap 里看不到 HTTP 头——它在 TLS 隧道内；
                      给了它，输出记录可直接喂 gen-profiles 生成预设）
  --name <记录名>     默认取 pcap 文件名（去扩展名）
  -o <文件>           输出到文件（默认 stdout）

说明：
  - 输出的 clienthello_hex 是 record 原始字节，可直接：
      geektls check-profile "$(jq -r .clienthello_hex out.json)"
      geektls request <url> --clienthello-hex "$(jq -r .clienthello_hex out.json)"
  - 三语言绑定有等价入口（v0.2.0 起，同一解析核）：Python geektls.import_pcap /
    Node importPcap / Go geektls.ImportPcap。
  - 拒绝的流会在 stderr 说明原因（resumption / 缺 SYN / 抓包缺口 / 无 CH）。
`

func importPcapUsageErr(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "geektls: "+format+"\n\n"+importPcapUsage, args...)
	return 2
}

// 与核类型的兼容别名：既有测试（importpcap_test.go）按这些名字断言，保持不变。
type (
	pcapFingerprintRecord = pcapimport.Record
	recordTCP             = pcapimport.TCPInfo
	recordHTTP2           = pcapimport.HTTP2Info
)

// TCP 标志位（测试合成帧用；与 core/pcapimport 内部同值）。
const (
	flagFIN = 0x01
	flagSYN = 0x02
	flagRST = 0x04
	flagACK = 0x10
)

// 核函数的 CLI 兼容委托（测试直接调用；正式路径走 cmdImportPcap → Import）。
func parseTCPOptions(b []byte) (mss, wscale int, order []string) {
	return pcapimport.ParseTCPOptions(b)
}

func extractClientHelloRecord(stream []byte) ([]byte, error) {
	return pcapimport.ExtractClientHelloRecord(stream)
}

func cmdImportPcap(args []string, stdout, stderr io.Writer) int {
	var (
		pcapPath, ua, name, outPath string
		streamN                     = 1
		all, tcpOnly                bool
	)
	for i := 0; i < len(args); i++ {
		next := func() (string, bool) {
			if i+1 >= len(args) {
				return "", false
			}
			i++
			return args[i], true
		}
		switch args[i] {
		case "--pcap":
			v, ok := next()
			if !ok {
				return importPcapUsageErr(stderr, "import-pcap --pcap 需要文件路径")
			}
			pcapPath = v
		case "--stream":
			v, ok := next()
			if !ok {
				return importPcapUsageErr(stderr, "import-pcap --stream 需要数字")
			}
			n := 0
			if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 1 {
				return importPcapUsageErr(stderr, "import-pcap --stream 需要正整数（收到 %q）", v)
			}
			streamN = n
		case "--all":
			all = true
		case "--tcp-only":
			tcpOnly = true
		case "--ua":
			v, ok := next()
			if !ok {
				return importPcapUsageErr(stderr, "import-pcap --ua 需要 UA 串")
			}
			ua = v
		case "--name":
			v, ok := next()
			if !ok {
				return importPcapUsageErr(stderr, "import-pcap --name 需要记录名")
			}
			name = v
		case "-o":
			v, ok := next()
			if !ok {
				return importPcapUsageErr(stderr, "import-pcap -o 需要文件路径")
			}
			outPath = v
		default:
			return importPcapUsageErr(stderr, "import-pcap: 未知参数 %q", args[i])
		}
	}
	if pcapPath == "" {
		return importPcapUsageErr(stderr, "import-pcap 需要 --pcap <文件>")
	}
	if all && streamN != 1 {
		return importPcapUsageErr(stderr, "--all 与 --stream 不能同时给")
	}
	if name == "" {
		base := filepath.Base(pcapPath)
		name = strings.TrimSuffix(base, filepath.Ext(base))
	}

	data, err := os.ReadFile(pcapPath)
	if err != nil {
		fmt.Fprintf(stderr, "geektls: 读取 %s: %v\n", pcapPath, err)
		return 1
	}

	res, err := pcapimport.Import(data, pcapimport.Options{
		Name:       name,
		SourceBase: filepath.Base(pcapPath),
		UA:         ua,
		Stream:     streamN,
		All:        all,
		TCPOnly:    tcpOnly,
	})
	if err != nil {
		fmt.Fprintf(stderr, "geektls: %v\n", err)
		return 1
	}
	for _, r := range res.Skipped {
		fmt.Fprintf(stderr, "geektls: 跳过 %s\n", r)
	}
	if len(res.Records) == 0 {
		fmt.Fprintf(stderr, "geektls: 没有可导出的流（--tcp-only 可放宽 ClientHello 要求）\n")
		return 1
	}

	var out []byte
	if all {
		out, err = json.MarshalIndent(res.Records, "", "  ")
	} else {
		// 核已按 Stream 挑好：非 all 时 Records 恰为选中的那一条。
		out, err = json.MarshalIndent(res.Records[0], "", "  ")
	}
	if err != nil {
		fmt.Fprintf(stderr, "geektls: %v\n", err)
		return 1
	}
	out = append(out, '\n')

	if outPath != "" {
		if err := os.WriteFile(outPath, out, 0o644); err != nil {
			fmt.Fprintf(stderr, "geektls: 写 %s: %v\n", outPath, err)
			return 1
		}
		fmt.Fprintf(stderr, "geektls: 已写入 %s（kind=e1p_pcap，grade=E1p）\n", outPath)
		return 0
	}
	_, _ = stdout.Write(out)
	return 0
}
