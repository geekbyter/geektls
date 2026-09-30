package profiles

// 预设命名规范与旧名兼容（2026-09-30 统一）。
//
// 规范（详见 docs/03-profile-format.md §预设命名）：
//
//	<家族>_<版本>[_<变体>][_<平台>]
//
//   - 平台后缀取值 windows / macos / linux / android / ios；**能判定就必须写**。
//   - **Safari 也带 `_macos`**：Safari 同时存在于 macOS 与 iOS（`safari_18_6_ios`），
//     不加后缀说不清是哪一个 ⇒ macOS 写 `_macos`，iOS 写 `_ios`。
//   - 工具/App 族（okhttp / curl / postman / charles / unity…）无法判定平台，**留空**
//     （"确实缺失的留空"）。
//   - 变体标记（如 `chrome_101_109_safe_windows` 的 `safe`）排平台之前。
//
// 存量已按规范改名 7 条（chrome_131/133/150、firefox_120/135 补 `_windows`；
// safari_16 补 `_macos`）。**`safari_18` 更进一步**：它的旧形态是"无实测来源的历史
// 构造"（13 扩展、wire ≈2.9KB，与真机差得远），2026-09-30 直接删除，旧名 `safari_18`
// 的别名改指**实测导航形态** `safari_18_macos`（同一真机形态的独立复现，JA4 与实测
// 18.6 逐字符相同）—— 这是**行为变化**：用旧名发出的字节会变成实测形态，这是刻意的
// （留着一个明知不对的形态比改名更糟）。
//
// 旧名走下面的别名表继续可用 —— 仓库里对这些手写预设的引用有 200+ 处（docs/测试/
// 绑定示例），别名让它们不必一次性迁移；**新代码请用规范名**。

// legacyPresetAliases 旧名 → 规范名。
//
// 契约：旧名必须**永远**取到规范名指向的那份形态（映射只增不删；`safari_18` 那次是
// 唯一一次"目标形态被替换"，理由是旧形态本身是错的）。
var legacyPresetAliases = map[string]string{
	"chrome_131":  "chrome_131_windows",
	"chrome_133":  "chrome_133_windows",
	"chrome_150":  "chrome_150_windows",
	"firefox_120": "firefox_120_windows",
	"firefox_135": "firefox_135_windows",
	"safari_16":   "safari_16_macos",
	"safari_18":   "safari_18_macos",
}

// canonicalPresetName 把旧名映射到规范名；已经是规范名/未知名原样返回。
func canonicalPresetName(name string) string {
	if canon, ok := legacyPresetAliases[name]; ok {
		return canon
	}
	return name
}

// AliasOf 返回该规范名对应的旧名（用于文档/工具展示；无旧名返回空串）。
func AliasOf(canonical string) string {
	for old, canon := range legacyPresetAliases {
		if canon == canonical {
			return old
		}
	}
	return ""
}
