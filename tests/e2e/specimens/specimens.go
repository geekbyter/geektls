// Package specimens 收纳真实浏览器 ClientHello 标本（本地冻结数据，见 data.go）。
//
// 用途：
//  1. 语料回归测试——标本 hex 走「解析 → 编译 → 重放 → 独立解析器对拍」；
//  2. profile 生成——从真实抓包直接产出预设，替代手写转录。
//
// 数据由 cmd/extract-specimens 生成后本地冻结：升级上游包不会改变我们的基线。
package specimens

// Item 是一个具名标本。
type Item struct {
	Name     string // 如 "chrome_152_macos"
	Family   string // chrome / edge / firefox / safari
	Version  string // 主版本号，如 "152"
	Platform string // macOS / Windows

	Hex string // ClientHello 原始字节（hex，含 5 字节 TLS record 头）

	H2Settings [][2]uint32 // 同一抓包的 HTTP/2 SETTINGS（有序，[id, value]）
	H2ConnFlow uint32      // 同一抓包的连接级 WINDOW_UPDATE 增量

	// Headers 是同一抓包的**真实常规请求头**（有序，不含伪头）。
	// 来自 E1 真浏览器记录时用它直接当 identity（真实 UA-CH 比合成值保真）；
	// 为空时由生成器按族/版本/平台合成。
	Headers [][2]string
}

// All 返回全部标本（顺序稳定）。
func All() []Item { return all }

// ByName 按名查找标本。
func ByName(name string) (Item, bool) {
	for _, it := range all {
		if it.Name == name {
			return it, true
		}
	}
	return Item{}, false
}
