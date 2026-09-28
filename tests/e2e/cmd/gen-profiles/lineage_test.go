package main

// 谱系生成的一致性测试（同包，可直接调用内部函数）。
//
// 谱系是"从我们的实测锚点推导未实测版本"的能力，风险全在**推导**上，所以每一步都钉住：
//
//	1. 内插语义：产物骨架必须逐字段等于"≤目标版本的最高锚点"（identity 例外：按版本重算）
//	2. 不外推：窗口外必须拒绝（ErrRefused）
//	3. 骨架变化就拒绝：密码套件在区间内变过时不得内插（Safari 18→26）
//	4. 产物可用：能编译、等级只能是 E2i / E2i-u、来源标 lineage、UA 必须带目标版本号

import (
	"errors"
	"strings"
	"testing"

	"github.com/geektls/core/profiles"
	tlscore "github.com/geektls/core/tls"
)

func TestLineageInterpolationSemantics(t *testing.T) {
	byFam, err := lineageBuild()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for fam, anchors := range byFam {
		for _, v := range gapVersions(anchors) {
			p, _, err := generateAt(fam, anchors, v, false)
			if errors.Is(err, ErrRefused) {
				continue // 按设计拒绝，另有测试覆盖
			}
			if err != nil {
				t.Fatalf("%s@%s: %v", fam, v, err)
			}
			base, _ := anchorBounding(anchors, v)
			if base == nil {
				t.Fatalf("%s@%s: 找不到下界锚点", fam, v)
			}
			// 骨架逐字段等于下界锚点；identity_header_order 允许重算后仍相同
			for _, f := range lineageFields {
				if got, want := f.value(p), f.value(base.prof); got != want {
					t.Errorf("%s@%s: 字段 %s 未取自下界锚点 %s\n  产物: %s\n  锚点: %s",
						fam, v, f.key, base.item.Version, orDash(truncate(got, 110)), orDash(truncate(want, 110)))
				}
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("没有任何可内插版本（锚点或规则是否变了？）")
	}
	t.Logf("校验了 %d 个内插版本的骨架保真", checked)
}

func TestLineageRefusesExtrapolation(t *testing.T) {
	byFam, err := lineageBuild()
	if err != nil {
		t.Fatal(err)
	}
	for fam, anchors := range byFam {
		low := anchors[0].item.Version
		high := anchors[len(anchors)-1].item.Version
		for _, v := range []string{"1", "9999"} {
			if _, _, err := generateAt(fam, anchors, v, false); !errors.Is(err, ErrRefused) {
				t.Errorf("%s: 版本 %s（窗口 %s–%s 之外）本应 ErrRefused，得到 %v", fam, v, low, high, err)
			}
		}
	}
}

func TestLineageRefusesSkeletonChange(t *testing.T) {
	byFam, err := lineageBuild()
	if err != nil {
		t.Fatal(err)
	}
	// Safari 18→26 密码套件变过 ⇒ 19–25 必须拒绝（不能凭空造一套 TLS 栈）
	anchors := byFam["safari"]
	if len(anchors) < 2 {
		t.Skip("无两个 Safari 锚点")
	}
	_, _, err = generateAt("safari", anchors, "22", false)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Safari 22（18 与 26 之间）密码套件已变，本应拒绝，得到 %v", err)
	}
	t.Logf("Safari 22 拒绝原因：%v", err)
}

func TestLineageProductsAreSound(t *testing.T) {
	byFam, err := lineageBuild()
	if err != nil {
		t.Fatal(err)
	}
	total, e2i, e2iu, refused := 0, 0, 0, 0
	for fam, anchors := range byFam {
		for _, v := range gapVersions(anchors) {
			p, _, err := generateAt(fam, anchors, v, false)
			if errors.Is(err, ErrRefused) {
				refused++
				continue
			}
			if err != nil {
				t.Fatalf("%s@%s: %v", fam, v, err)
			}
			total++
			switch p.Grade {
			case "E2i":
				e2i++
			case "E2i-u":
				e2iu++
			default:
				t.Errorf("%s@%s: 内插产物的等级必须是 E2i 或 E2i-u，得到 %q", fam, v, p.Grade)
			}
			if !strings.HasPrefix(p.Source, "lineage:") {
				t.Errorf("%s@%s: 来源未标 lineage（%q）", fam, v, p.Source)
			}
			if _, err := tlscore.CompileDetail(p.TLS.Detail); err != nil {
				t.Errorf("%s@%s: 编译失败: %v", fam, v, err)
			}
			// UA 或 UA-CH 里必须带**目标版本号**，否则一眼假
			if p.Identity == nil || len(p.Identity.Headers) == 0 {
				t.Errorf("%s@%s: 身份头为空（UA 必须按目标版本重算）", fam, v)
			} else if !strings.Contains(strings.Join(headerValuesOf(p), " "), v) {
				t.Errorf("%s@%s: 身份头里找不到目标版本号：%v", fam, v, headerValuesOf(p))
			}
		}
	}
	if total == 0 {
		t.Fatal("没有任何可内插版本")
	}
	t.Logf("内插版本 %d 个（全稳 E2i=%d，含未定界字段 E2i-u=%d），按设计拒绝 %d 个", total, e2i, e2iu, refused)
}

func headerValuesOf(p *profiles.Profile) []string {
	if p.Identity == nil {
		return nil
	}
	out := make([]string, 0, len(p.Identity.Headers))
	for _, kv := range p.Identity.Headers {
		out = append(out, kv[0]+"="+kv[1])
	}
	return out
}
