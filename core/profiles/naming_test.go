package profiles

// 预设命名规范守门（2026-09-30 统一）与旧名别名自洽。
//
// 规范：`<家族>_<版本>[_<变体>][_<平台>]`
//   - 浏览器族（chrome / edge / firefox / **safari**）**必须**带平台后缀：
//     它们都跨平台并存 —— Safari 同时有 macOS 与 iOS 形态（`safari_18_6_ios`），
//     不加后缀说不清是哪一个 ⇒ macOS 写 `_macos`、iOS 写 `_ios`；
//   - Safari 的平台后缀只允许 `macos` / `ios`；
//   - 工具 / App 族留空（平台无法判定 —— "确实缺失的留空"）。

import (
	"reflect"
	"strings"
	"testing"
)

var platformSuffixes = map[string]bool{
	"windows": true, "macos": true, "linux": true, "android": true, "ios": true,
}

// browserFamiliesWithPlatform 必须带平台后缀的家族。
var browserFamiliesWithPlatform = map[string]bool{
	"chrome": true, "edge": true, "firefox": true, "safari": true,
}

func familyOf(name string) string {
	if i := strings.IndexByte(name, '_'); i > 0 {
		return name[:i]
	}
	return name
}

func platformOf(name string) string {
	parts := strings.Split(name, "_")
	last := parts[len(parts)-1]
	if platformSuffixes[last] {
		return last
	}
	return ""
}

func TestPresetNamingConvention(t *testing.T) {
	names := List()
	if len(names) == 0 {
		t.Fatal("内置预设为空")
	}
	var browsersChecked int
	for _, n := range names {
		fam := familyOf(n)
		if browserFamiliesWithPlatform[fam] {
			if platformOf(n) == "" {
				t.Errorf("%s 缺平台后缀（%s 跨平台并存，规范要求写成 %s_<版本>_<平台>）", n, fam, fam)
			}
			browsersChecked++
		}
		if fam == "safari" {
			// Safari 只允许 macos / ios（两者真实并存；windows/linux/android 不存在）
			if p := platformOf(n); p != "" && p != "ios" && p != "macos" {
				t.Errorf("%s 的 Safari 平台后缀 %q 不合法（只允许 macos / ios）", n, p)
			}
		}
	}
	if browsersChecked < 100 {
		t.Fatalf("只检查到 %d 条浏览器预设，样本太少（守门可能失效）", browsersChecked)
	}
}

// 别名自洽：旧名与规范名必须取到**同一份**形态，且规范名真的存在于内置集。
func TestLegacyAliasesResolve(t *testing.T) {
	if len(legacyPresetAliases) == 0 {
		t.Fatal("别名表为空（改名后旧引用会直接失效）")
	}
	all := map[string]bool{}
	for _, n := range List() {
		all[n] = true
	}
	for old, canon := range legacyPresetAliases {
		if !all[canon] {
			t.Errorf("别名 %s → %s：规范名不在内置集里", old, canon)
			continue
		}
		if all[old] {
			t.Errorf("别名 %s 与规范名 %s 同时存在（旧文件没删干净）", old, canon)
		}
		a, err := Get(old)
		if err != nil {
			t.Errorf("旧名 %s 取不到：%v", old, err)
			continue
		}
		b, err := Get(canon)
		if err != nil {
			t.Fatalf("规范名 %s 取不到：%v", canon, err)
		}
		if a.Name != b.Name || !reflect.DeepEqual(a.TLS, b.TLS) {
			t.Errorf("旧名 %s 与 %s 不是同一形态（name %s vs %s）", old, canon, a.Name, b.Name)
		}
		if got := AliasOf(canon); got != old {
			t.Errorf("AliasOf(%s) = %q, want %q", canon, got, old)
		}
	}
}
