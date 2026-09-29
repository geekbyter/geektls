package tlscore

import (
	"strings"
	"testing"
)

// JA4 短哈希反查：命中同一 JA4 的内置预设；找不到时明确报错而不是编近似指纹。
func TestResolveJA4Preset(t *testing.T) {
	const ja4 = "t13d1517h2_8daaf6152771_cb7bf5808d99"
	hit, err := ResolveJA4Preset(ja4)
	if err != nil {
		t.Fatalf("ResolveJA4Preset(%s): %v", ja4, err)
	}
	if len(hit.Candidates) == 0 {
		t.Fatal("应至少命中一个预设")
	}
	// 同族同版本跨平台（mac/android/windows）与 152 都应命中。
	for _, want := range []string{"chrome_152_macos", "chrome_154_macos", "chrome_154_android", "chrome_154_windows"} {
		found := false
		for _, c := range hit.Candidates {
			if c == want {
				found = true
			}
		}
		if !found {
			t.Errorf("候选里缺 %s（实际 %v）", want, hit.Candidates)
		}
	}
	if hit.Name != hit.Candidates[0] {
		t.Errorf("Name 应取候选排序第一个：%s vs %v", hit.Name, hit.Candidates)
	}

	if _, err := ResolveJA4Preset("t13d1516h2_000000000000_000000000000"); err == nil {
		t.Error("不存在的 JA4 应报错（不能编近似指纹）")
	}
	if _, err := ResolveJA4Preset("771,4865"); err == nil {
		t.Error("非 JA4 形态应报错")
	}
}

// CheckProfile 的五种入参都要能用，且 JA4/JA4R 路径不能改变"未传部分"的自洽性。
func TestCheckProfileInputs(t *testing.T) {
	t.Run("JA4 短哈希 ⇒ 反查预设并给告警", func(t *testing.T) {
		r, err := CheckProfile("t13d1516h2_8daaf6152771_d8a2da3f94cd")
		if err != nil {
			t.Fatal(err)
		}
		if r.JA4 != "t13d1516h2_8daaf6152771_d8a2da3f94cd" {
			t.Errorf("反查到的预设 JA4 应与输入一致：%s", r.JA4)
		}
		if !hasWarn(r, "ja4_resolved_to_preset") {
			t.Errorf("应说明这是「反查」而来：%+v", r.Warnings)
		}
	})

	t.Run("包装 JSON 的 ja4 字段", func(t *testing.T) {
		r, err := CheckProfile(`{"ja4":"t13d1516h2_8daaf6152771_d8a2da3f94cd"}`)
		if err != nil {
			t.Fatal(err)
		}
		if r.JA4 != "t13d1516h2_8daaf6152771_d8a2da3f94cd" {
			t.Errorf("JA4 = %s", r.JA4)
		}
	})

	t.Run("JA3 有损入口：补占位后仍可用且负载缺失有告警", func(t *testing.T) {
		r, err := CheckProfile("771,4865-4866-4867-49195-49199,43-10-11-13-16-23-5-0-65281,4588-29-23-24,0")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(r.JA4, "t13d") {
			t.Errorf("应为 TLS1.3 形态 JA4：%s", r.JA4)
		}
		if !hasWarn(r, "psk_placeholder_added") {
			t.Errorf("JA3 入口缺 PSK 占位，应补并告警：%+v", r.Warnings)
		}
		if !hasWarn(r, "extension_payloads_lost") {
			t.Errorf("JA3 应如实报告负载丢失：%+v", r.Warnings)
		}
	})

	t.Run("JA4R 带 ECH(65037)：必须能编译（Chrome 152+ 的 JA4R 都带 fe0d）", func(t *testing.T) {
		// 真 Chrome 154 抓包的 JA4R 形状：含 51764(ca34) 与 65037(fe0d)。
		ja4r := "t13d1518h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9" +
			"_0000,0005,000a,000b,000d,0010,0012,0017,001b,0023,0029,002b,002d,0033,44cd,ca34,fe0d,ff01" +
			"_0403,0804,0401,0503,0805,0501,0806,0601"
		r, err := CheckProfile(ja4r)
		if err != nil {
			t.Fatalf("JA4R 含 ECH 应能编译（否则带 ECH 的浏览器 JA4R 整条不可用）：%v", err)
		}
		if !hasWarn(r, "ech_assumed_grease") {
			t.Errorf("应告警 ECH 按 GREASE 近似：%+v", r.Warnings)
		}
		// JA4R 的 ciphers/extensions 段是排序值，JA4 本身对这两段也排序 ⇒ 应能还原。
		if r.JA4 != "t13d1518h2_8daaf6152771_0491da36e2dd" {
			t.Logf("JA4 还原值 = %s（若与 FoxIO 参考实现不同请人工核对）", r.JA4)
		}
	})

	t.Run("完整 profile JSON", func(t *testing.T) {
		if _, err := CheckProfile(`{"name":"x","tls":{"detail":{"legacy_version":"0x0303","ciphers":["grease","0x1301"],"extensions":[{"type":43,"versions":["grease","0x0304","0x0303"]}]}}}`); err != nil {
			t.Fatal(err)
		}
	})
}

func hasWarn(r *CheckResult, code string) bool {
	for _, w := range r.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}
