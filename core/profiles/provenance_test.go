package profiles

// 证据等级（grade）是这套预设库的**可信度分层**：
//
//	留空     = 本项目自测（E1 真机抓包 / E1r 字段级实测 / E2 本机可复现）
//	"E2i"    = 谱系内插：由我们的实测锚点 + 逐字段稳定性规则推导，**该版本未实测**，
//	           且区间内所有被比较字段都稳定（可信度较高）
//	"E2i-u"  = 同上，但区间内有字段变化且**边界未知**（可信度较低，需在该区间补锚点）
//	"E3"     = 外部指纹集导入，**未经我们实测**（覆盖面对齐用，不做保真承诺）
//
// 分层的意义：E1 级断言（真机 JA3/JA4、导航头顺序、HEADERS priority…）只允许作用在
// **自测**预设上；否则就是"拿推导出来的数据验证实测"。本测试守住这条边界。

import (
	"strings"
	"testing"
)

func TestPresetProvenance(t *testing.T) {
	var self, interp, interpU, ext int
	byFam := map[string]int{}
	for _, name := range List() {
		p, err := Get(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		fam := name
		if i := strings.Index(name, "_"); i > 0 {
			fam = name[:i]
		}
		switch p.Grade {
		case "":
			self++
			if p.Source != "" {
				t.Errorf("%s: 自测预设不该有 source（%q）", name, p.Source)
			}
		case "E2i", "E2i-u":
			if p.Grade == "E2i" {
				interp++
			} else {
				interpU++
			}
			if !strings.HasPrefix(p.Source, "lineage:") {
				t.Errorf("%s: 谱系预设必须标注 lineage 来源（当前 %q）", name, p.Source)
			}
		case "E3":
			ext++
			if p.Source == "" {
				t.Errorf("%s: E3 预设必须标注来源", name)
			}
			byFam[fam]++
		default:
			t.Errorf("%s: 未知 grade %q（约定：留空=自测，E2i/E2i-u=谱系内插，E3=外部导入）", name, p.Grade)
		}
	}
	t.Logf("预设 %d 个：自测 %d、谱系内插 %d（其中边界未知 %d）、外部导入 %d（族分布 %v）",
		len(List()), self, interp, interpU, ext, byFam)
}

