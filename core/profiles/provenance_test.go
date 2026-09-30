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
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
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

// TestE3SourceTraceable 守住 provenance 的**正向**半边：E3 的 source 不只是"非空"，
// 还必须能回到仓库里真实存在的快照——
//
//	source = "<数据集>/<常量名>"，数据集对应 profiles/evidence/thirdparty/<数据集>.json，
//	常量名必须是该快照里某条记录的 _const。
//
// 为什么值得单独一条：导入器曾经把数据集名写死（换来源不改就会让 source 指向上一个
// 数据集），而旧断言只查"E3 有没有 source"，于是"source 说谎"这件事测试看不见。
// 现在说谎的结果是判红：那个数据集的快照里没有这个常量。
func TestE3SourceTraceable(t *testing.T) {
	dir := filepath.Join("..", "..", "profiles", "evidence", "thirdparty")
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil || len(files) == 0 {
		t.Skipf("evidence 快照目录不可用（%v）——只在仓库内跑本测试才有", err)
	}

	// dataset -> 该快照里的 _const 集合
	consts := map[string]map[string]bool{}
	for _, f := range files {
		base := strings.TrimSuffix(filepath.Base(f), ".json")
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("读快照 %s: %v", f, err)
			continue
		}
		var entries map[string]struct {
			Const string `json:"_const"`
		}
		if err := json.Unmarshal(raw, &entries); err != nil {
			t.Errorf("解析快照 %s: %v", f, err)
			continue
		}
		set := map[string]bool{}
		for _, e := range entries {
			if e.Const != "" {
				set[e.Const] = true
			}
		}
		consts[base] = set
	}

	checked := 0
	datasets := make([]string, 0, len(consts))
	for k := range consts {
		datasets = append(datasets, k)
	}
	for _, name := range List() {
		p, err := Get(name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if p.Grade != "E3" {
			continue
		}
		if msg := e3SourceProblem(p.Source, consts, dir); msg != "" {
			t.Errorf("%s: %s", name, msg)
			continue
		}
		checked++
	}
	// 守门自己要过负例：把 source 写成"上一个数据集"或凭空造常量，必须判红。
	// 只跑正例的守门和一个恒真的断言没法区分——而"A13 的成因"恰恰是这种说谎。
	for _, bad := range []string{
		"", "TLS_CHROME_122", "tls_config-0.0.2/", "/TLS_CHROME_122",
		"tls_config-9.9.9/TLS_CHROME_122", "tls_config-0.0.2/TLS_DEFINITELY_NOT_IN_SNAPSHOT",
	} {
		if e3SourceProblem(bad, consts, dir) == "" {
			t.Errorf("source %q 本应判红却通过了", bad)
		}
	}
	t.Logf("E3 source 可追溯：%d 条逐条回到快照 _const 校验通过（数据集 %v）", checked, datasets)
}

// e3SourceProblem 检查一条 E3 source（"<数据集>/<常量名>"）能否回到仓库里的快照；
// 没问题返回空串。
func e3SourceProblem(source string, consts map[string]map[string]bool, dir string) string {
	dataset, constant, ok := strings.Cut(source, "/")
	if !ok || dataset == "" || constant == "" {
		return "source " + strconv.Quote(source) + " 不符合 \"<数据集>/<常量名>\" 格式"
	}
	set, hasSnapshot := consts[dataset]
	if !hasSnapshot {
		return "source " + strconv.Quote(source) + " 的数据集在 " + dir +
			" 下没有对应快照（换了来源就把 -source 一起改）"
	}
	if !set[constant] {
		return "source " + strconv.Quote(source) + " 指向的常量不在该数据集快照里（source 与来源不符）"
	}
	return ""
}
