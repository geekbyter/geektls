package engine

// 身份自洽（G9 的后半）：调用方自己写了 `user-agent` 时，把**客户端提示**
//（`sec-ch-ua` / `sec-ch-ua-platform` / `sec-ch-ua-mobile`）校正到与该 UA 一致。
//
// 为什么只动这些、不动 TLS：
//   - 客户端提示是**与 UA 同源**的信息（同一浏览器同一次会话里必须自洽），改了 UA
//     却留着旧平台提示，是"自相矛盾"的明显信号 —— 这是能自动修好的部分；
//   - JA3/JA4/H2 指纹是 ClientHello/帧层的字节，**不能因为一个 header 就凭空改**：
//     凭空改出来的指纹不属于任何真实浏览器，比不一致更糟。想要"UA 与 TLS 也一致"，
//     正确做法是**换用同平台变体预设**（如 chrome_154 的 `_windows` / `_macos` /
//     `_android` 变体，它们的 TLS 真的不同），本库对此**如实告警**而不是伪造。
//
// 取值（SessionOptions.IdentitySync）：
//
//	""/"auto"  默认：UA 与预设身份不一致时校正客户端提示，并在响应 `warnings`
//	           里如实说明"TLS/H2 仍是该预设"。
//	"off"      完全不动（旧行为：identity 表原样注入，冲突也不提示）。

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	identitySyncAuto = "auto"
	identitySyncOff  = "off"
)

func normalizeIdentitySync(v string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "":
		return identitySyncAuto, nil
	case identitySyncAuto:
		return identitySyncAuto, nil
	case identitySyncOff, "none", "keep":
		return identitySyncOff, nil
	default:
		return "", fmt.Errorf("engine: identity_sync 取值 %q 未知（want auto / off）", v)
	}
}

// uaFacts 是从 UA 里能读出的"基础事实"（只取客户端提示需要的几项）。
type uaFacts struct {
	platform string // Windows / macOS / Linux / Android / iOS / Chrome OS
	mobile   bool
	major    string // Chromium 家族的主版本号（sec-ch-ua 的 v="…"）
	chromium bool   // 是否 Chromium 家族（只有它才有 sec-ch-ua*）
	raw      string
}

var (
	reChromeVer = regexp.MustCompile(`(?:Chrome|CriOS|Chromium|Edg|EdgA|EdgiOS|OPR)/(\d+)`)
	reSecChUaV  = regexp.MustCompile(`v="\d+"`)
)

// parseUA 解析常见浏览器 UA。解析不出平台就返回零值（调用方据此跳过硬改）。
func parseUA(ua string) uaFacts {
	f := uaFacts{raw: ua}
	l := strings.ToLower(ua)
	switch {
	case strings.Contains(l, "windows"):
		f.platform = "Windows"
	case strings.Contains(l, "android"):
		f.platform = "Android"
	case strings.Contains(l, "iphone"), strings.Contains(l, "ipad"), strings.Contains(l, "ipod"):
		f.platform = "iOS"
	case strings.Contains(l, "cros"):
		f.platform = "Chrome OS"
	case strings.Contains(l, "macintosh"), strings.Contains(l, "mac os x"):
		f.platform = "macOS"
	case strings.Contains(l, "linux"):
		f.platform = "Linux"
	}
	f.mobile = strings.Contains(l, "mobile") || f.platform == "Android" || f.platform == "iOS"

	// Chromium 家族：sec-ch-ua* 才存在（Firefox/Safari 不发这些头，也不该硬塞）
	if m := reChromeVer.FindStringSubmatch(ua); m != nil {
		f.chromium = true
		f.major = m[1]
	}
	return f
}

// syncClientHints 把 identity 注入的客户端提示校正到调用方 UA 的事实上。
// 返回被改写的头名（用于告警文案）；没有可改正的项时返回 nil。
func syncClientHints(injected [][2]string, facts uaFacts) []string {
	if !facts.chromium || facts.platform == "" {
		return nil
	}
	var changed []string
	for i, kv := range injected {
		switch strings.ToLower(kv[0]) {
		case "sec-ch-ua-platform":
			want := `"` + facts.platform + `"`
			if kv[1] != want {
				injected[i] = [2]string{kv[0], want}
				changed = append(changed, kv[0])
			}
		case "sec-ch-ua-mobile":
			want := "?0"
			if facts.mobile {
				want = "?1"
			}
			if kv[1] != want {
				injected[i] = [2]string{kv[0], want}
				changed = append(changed, kv[0])
			}
		case "sec-ch-ua":
			// 品牌结构保留（含 GREASE 品牌），只把版本号换成调用方 UA 的主版本
			if facts.major != "" {
				want := reSecChUaV.ReplaceAllString(kv[1], `v="`+facts.major+`"`)
				if want != kv[1] {
					injected[i] = [2]string{kv[0], want}
					changed = append(changed, kv[0])
				}
			}
		}
	}
	return changed
}

// identityUAConflict 判断调用方给的 UA 是否与**预设身份**冲突。
// 返回（预设 UA, 调用方 UA, 是否冲突）。
//
// 注意比的是 idHeaders（profile.identity 的完整表），不是"实际注入的那些"——
// 调用方自己给了 user-agent 时同名头不会被注入，拿注入结果去比会永远比不到。
func identityUAConflict(idHeaders, userHeaders [][2]string) (string, string, bool) {
	userUA := ""
	for _, kv := range userHeaders {
		if equalFoldASCII(kv[0], "user-agent") {
			userUA = kv[1]
			break
		}
	}
	if userUA == "" {
		return "", "", false
	}
	presetUA := ""
	for _, kv := range idHeaders {
		if equalFoldASCII(kv[0], "user-agent") {
			presetUA = kv[1]
			break
		}
	}
	if presetUA == "" || presetUA == userUA {
		return presetUA, userUA, false
	}
	return presetUA, userUA, true
}
