package profiles

import "encoding/json"

// MergePatch 以 base 为底、patch（profile JSON 片段）覆盖，返回合并后的 profile。
//
// 规则与 extends 的深合并一致：对象逐层递归；数组与标量整体替换（不做逐项拼接）；
// patch 里的 "extends" 会被忽略（基底已由调用方确定）。合并结果照常走完整解析与
// 校验（未知字段、非法取值都会报错，不静默吞掉）。用途：从预设或抓包结果出发，
// 只改要改的字段（如增删扩展、替换 ALPN、覆盖身份头），免去手抄全量 profile。
//
// 容错：patch 允许是"JSON 文本再被当成字符串"的形态（绑定层可能二次编码）——
// 先解开一层引号再解析。
func MergePatch(base *Profile, patch []byte) (*Profile, error) {
	if base == nil {
		return nil, &ParseError{Field: "profile_patch", Msg: "基底 profile 为空"}
	}
	if len(patch) == 0 {
		return base, nil
	}
	var s string
	if err := json.Unmarshal(patch, &s); err == nil {
		patch = []byte(s)
	}
	merged, err := mergeJSONDocs(base, patch)
	if err != nil {
		return nil, &ParseError{Field: "profile_patch", Msg: err.Error()}
	}
	return parseWithExtends(merged, nil)
}
