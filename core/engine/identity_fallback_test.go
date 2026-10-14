package engine

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/geekbyter/geektls/core/profiles"
)

// ja3FromPresetForTest 从内置预设的 detail 生成"真实形态"的 JA3 串（ciphers
// 数值化、扩展类型剔除 GREASE、groups/points 十进制）——模拟有损入口的真实输入。
func ja3FromPresetForTest(t *testing.T, name string) string {
	t.Helper()
	p, err := profiles.Get(name)
	if err != nil {
		t.Fatal(err)
	}
	isGrease := func(v uint16) bool { return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v) }
	hex16 := func(s string) (uint16, bool) {
		s = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x")
		if s == "" || s == "grease" {
			return 0, false
		}
		v, err := strconv.ParseUint(s, 16, 16)
		if err != nil {
			return 0, false
		}
		return uint16(v), true
	}
	d := p.TLS.Detail
	var ciphers, exts, groups, points []string
	for _, c := range d.Ciphers {
		if v, ok := hex16(c); ok && !isGrease(v) {
			ciphers = append(ciphers, fmt.Sprintf("%d", v))
		}
	}
	for _, e := range d.Extensions {
		if isGrease(e.Type) {
			continue
		}
		exts = append(exts, fmt.Sprintf("%d", e.Type))
		if e.Type == 10 {
			for _, g := range e.Groups {
				if gv, ok := hex16(g); ok && !isGrease(gv) {
					groups = append(groups, fmt.Sprintf("%d", gv))
				}
			}
		}
		if e.Type == 11 {
			for _, pf := range e.PointFormats {
				points = append(points, fmt.Sprintf("%d", pf))
			}
		}
	}
	return fmt.Sprintf("771,%s,%s,%s,%s",
		strings.Join(ciphers, "-"), strings.Join(exts, "-"),
		strings.Join(groups, "-"), strings.Join(points, "-"))
}

func profileFromJA3ForTest(t *testing.T, ja3 string) *profiles.Profile {
	t.Helper()
	p, _, err := profiles.FromJA3(ja3)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func extOf(p *profiles.Profile, t0 uint16) (profiles.Extension, bool) {
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type == t0 {
			return e, true
		}
	}
	return profiles.Extension{}, false
}

// TestIdentityAutoFallbackOnJA3：ja3 入口（无 identity、载荷为通用默认）建会话时：
// 载荷按最相似预设替换/补全、identity 自动借用、两类告警齐备、调用方 profile
// 不被污染（43 仍是 FromJA3 的通用默认）。
func TestIdentityAutoFallbackOnJA3(t *testing.T) {
	p := profileFromJA3ForTest(t, ja3FromPresetForTest(t, "chrome_154_windows"))
	s, err := NewSession(p, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.profile.Identity == nil || len(s.profile.Identity.Headers) == 0 {
		t.Fatal("identity 未自动兜底")
	}
	if s.identDisabled {
		t.Error("identDisabled 不应为 true")
	}
	hasBorrow, hasIdent := false, false
	for _, w := range s.identWarns {
		if strings.HasPrefix(w, "payload_borrowed") {
			hasBorrow = true
		}
		if strings.HasPrefix(w, "identity_auto") {
			hasIdent = true
		}
	}
	if !hasBorrow || !hasIdent {
		t.Errorf("告警不全: %v", s.identWarns)
	}
	// 载荷替换/补全生效：43 有 versions、51 有 key_shares，且 43 不再是通用默认。
	if v43, ok := extOf(s.profile, 43); !ok || len(v43.Versions) == 0 {
		t.Errorf("43 载荷缺失: %+v", v43)
	} else if fmt.Sprint(v43.Versions) == fmt.Sprint([]string{"0x0304", "0x0303"}) {
		t.Errorf("43 载荷仍是 FromJA3 的通用默认（未替换）: %v", v43.Versions)
	}
	if ks51, ok := extOf(s.profile, 51); !ok || len(ks51.KeyShares) == 0 {
		t.Errorf("51 载荷缺失: %+v", ks51)
	}
	// 调用方对象不被污染。
	if p.Identity != nil {
		t.Error("原 profile 被写入 identity")
	}
	for _, e := range p.TLS.Detail.Extensions {
		if e.Type == 43 {
			if fmt.Sprint(e.Versions) != fmt.Sprint([]string{"0x0304", "0x0303"}) {
				t.Errorf("原 profile 被污染: 43.Versions = %v", e.Versions)
			}
		}
	}
}

// TestIdentityExplicitAndDisabled：显式 identity= 预设 / 头表 / false 三态。
func TestIdentityExplicitAndDisabled(t *testing.T) {
	p := profileFromJA3ForTest(t, ja3FromPresetForTest(t, "chrome_154_windows"))

	want, err := profiles.Get("chrome_154_windows")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(p, SessionOptions{Identity: json.RawMessage(`"chrome_154_windows"`)})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.profile.Identity == nil || len(s.profile.Identity.Headers) != len(want.Identity.Headers) {
		t.Error("显式预设 identity 未生效")
	}

	s2, err := NewSession(p, SessionOptions{Identity: json.RawMessage(`false`)})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if s2.profile.Identity != nil {
		t.Error("identity=false 应保持无身份")
	}
	if !s2.identDisabled {
		t.Error("identDisabled 应为 true")
	}
	// 载荷借用不受 identity=false 影响（该开关只关 HTTP 身份）。
	if v43, ok := extOf(s2.profile, 43); !ok || fmt.Sprint(v43.Versions) == fmt.Sprint([]string{"0x0304", "0x0303"}) {
		t.Error("identity=false 下载荷借用仍应生效")
	}

	s3, err := NewSession(p, SessionOptions{Identity: json.RawMessage(`{"User-Agent":"X-Test/1"}`)})
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if s3.profile.Identity == nil || len(s3.profile.Identity.Headers) != 1 ||
		s3.profile.Identity.Headers[0][0] != "User-Agent" || s3.profile.Identity.Headers[0][1] != "X-Test/1" {
		t.Errorf("头表 identity 未生效: %+v", s3.profile.Identity)
	}

	// 非法形态：identity=true 报错；不存在的预设名报错。
	if _, err := NewSession(p, SessionOptions{Identity: json.RawMessage(`true`)}); err == nil {
		t.Error("identity=true 应报错")
	}
	if _, err := NewSession(p, SessionOptions{Identity: json.RawMessage(`"no_such_preset"`)}); err == nil {
		t.Error("未知预设名应报错")
	}
}

// TestIdentityPresetProfileUntouched：preset/profile 自带 identity 时不触发自动
// 兜底告警，身份与载荷都原样保留。
func TestIdentityPresetProfileUntouched(t *testing.T) {
	p, err := profiles.Get("chrome_154_windows")
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSession(p, SessionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.profile.Identity == nil || len(s.profile.Identity.Headers) == 0 {
		t.Fatal("预设 identity 丢失")
	}
	for _, w := range s.identWarns {
		if strings.HasPrefix(w, "identity_auto") || strings.HasPrefix(w, "payload_borrowed") {
			t.Errorf("预设装载不应触发低层兜底告警: %v", w)
		}
	}
}

// TestFillHTTPSelfCheck：HTTP 层自检填充与告警开关（T-I8）。
func TestFillHTTPSelfCheck(t *testing.T) {
	s := &Session{}
	sc := SelfCheck{}
	w := s.fillHTTPSelfCheck(&sc, [][2]string{{"Accept", "*/*"}, {"user-agent", "Mozilla/5.0"}}, true)
	if w != "" || sc.GoDefaultUA || sc.UserAgent != "Mozilla/5.0" || sc.HeaderCount != 2 {
		t.Errorf("有 UA 场景: warn=%q sc=%+v", w, sc)
	}
	sc2 := SelfCheck{}
	w2 := s.fillHTTPSelfCheck(&sc2, [][2]string{{"Accept", "*/*"}}, true)
	if w2 == "" || !sc2.GoDefaultUA || sc2.UserAgent != "" || sc2.HeaderCount != 1 {
		t.Errorf("无 UA 场景: warn=%q sc=%+v", w2, sc2)
	}
	sc3 := SelfCheck{}
	if w3 := s.fillHTTPSelfCheck(&sc3, [][2]string{{"Accept", "*/*"}}, false); w3 != "" {
		t.Errorf("显式关闭身份时不应告警: %q", w3)
	}
	if !sc3.GoDefaultUA {
		t.Error("显式关闭时自检仍应如实记录 GoDefaultUA")
	}
}
