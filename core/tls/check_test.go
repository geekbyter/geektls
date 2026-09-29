package tlscore

// CheckProfile 四种入参形态的覆盖（P1-T6 FFI 的核心逻辑，纯 Go 可测）。

import (
	"strings"
	"testing"
)

const testJA3 = "771,4865-4866-4867,0-10-11,29-23,0"

const testJA4R = "t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601"

func TestCheckProfileBareJA3(t *testing.T) {
	r, err := CheckProfile(testJA3)
	if err != nil {
		t.Fatalf("CheckProfile: %v", err)
	}
	// JA3 入口应回算出同结构 JA3（version 恒 771）
	if !strings.HasPrefix(r.JA3, "771,4865-4866-4867,") {
		t.Errorf("ja3 = %q", r.JA3)
	}
	if len(r.JA3Hash) != 32 {
		t.Errorf("ja3_hash = %q", r.JA3Hash)
	}
	if len(r.Warnings) == 0 {
		t.Error("JA3 entry must carry loss warnings")
	}
	if r.WireLen <= 0 {
		t.Errorf("wire_len = %d", r.WireLen)
	}
	// JA4 结构：t 标志 + 10 字符 a 段 + 两段 12 字符 hash
	parts := strings.Split(r.JA4, "_")
	if len(parts) != 3 || len(parts[0]) != 10 || len(parts[1]) != 12 || len(parts[2]) != 12 {
		t.Errorf("ja4 = %q malformed", r.JA4)
	}
}

func TestCheckProfileBareJA4R(t *testing.T) {
	r, err := CheckProfile(testJA4R)
	if err != nil {
		t.Fatalf("CheckProfile: %v", err)
	}
	// JA4R 的 ciphers/extensions 是排序的；JA4 对这两段本来就排序哈希，
	// 因此 JA4R → detail → JA4 应当完全还原原指纹。
	if r.JA4 != "t13d1516h2_8daaf6152771_e5627efa2ab1" {
		t.Errorf("ja4 = %q, want FoxIO spec example value", r.JA4)
	}
}

func TestCheckProfileWrappedEntries(t *testing.T) {
	for name, input := range map[string]string{
		"wrapped ja3":  `{"ja3":"` + testJA3 + `"}`,
		"wrapped ja4r": `{"ja4r":"` + testJA4R + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CheckProfile(input); err != nil {
				t.Fatalf("CheckProfile: %v", err)
			}
		})
	}
}

func TestCheckProfileFullJSON(t *testing.T) {
	input := `{"name":"t","tls":{"detail":{
	  "ciphers":["0x1301","0x1302"],
	  "extensions":[
	    {"type":0,"sni":"example.com"},
	    {"type":16,"alpn":["h2"]},
	    {"type":43,"versions":["0x0304"]},
	    {"type":13,"sig_algs":["0x0403"]}
	  ]}}}`
	r, err := CheckProfile(input)
	if err != nil {
		t.Fatalf("CheckProfile: %v", err)
	}
	// 自洽归一（core/profiles/replay.go）：该 detail 声明了 TLS 1.3 却没有
	// pre_shared_key(41) 占位 ⇒ 补一个空占位并告警（占位不计入 JA3/JA4、无票据时不上线）。
	if len(r.Warnings) != 1 || r.Warnings[0].Code != "psk_placeholder_added" {
		t.Errorf("detail path 应只报 psk_placeholder_added，实际 %+v", r.Warnings)
	}
	if !strings.HasPrefix(r.JA4, "t13d") {
		t.Errorf("ja4 = %q, want TLS1.3 + SNI-d flag", r.JA4)
	}
}

func TestCheckProfileErrors(t *testing.T) {
	for name, input := range map[string]string{
		"empty":         "",
		"garbage":       "not-a-fingerprint",
		"bad json":      `{"ja3":`,
		"no detail":     `{"name":"x","tls":{}}`,
		"ja3 bad inner": `{"ja3":"771"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := CheckProfile(input); err == nil {
				t.Error("expected error")
			}
		})
	}
}
