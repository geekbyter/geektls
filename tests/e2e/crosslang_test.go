// P5-T4 跨语言一致性：同一预设经 Python/Node/Go 三绑定对本地 echo 发请求，
// 收集 selfcheck 指纹断言一致。
//
// chrome_133（扩展洗牌）只比 JA4（JA3 因洗牌逐连接变化，属预期）；
// firefox_120（无洗牌）JA3 hash + JA4 全等。
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	gbt "github.com/geekbyter/geektls/bindings/golang"

	"github.com/geekbyter/geektls/core/engine"
)

type langResult struct {
	JA3Hash string `json:"ja3_hash"`
	JA4     string `json:"ja4"`
	Proto   string `json:"proto"`
}

// buildArtifact 返回当前平台构建产物的路径（不存在返回空串）。
func buildArtifact(name string) string {
	root, _ := filepath.Abs("../..")
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	p := filepath.Join(root, "build", name)
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}

// sharedLibName 返回当前平台的动态库文件名。
func sharedLibName() string {
	switch runtime.GOOS {
	case "windows":
		return "geektls.dll"
	case "darwin":
		return "libgeektls.dylib"
	default:
		return "libgeektls.so"
	}
}

// pythonBin 返回**实际可执行**的 python 解释器。
// 注意：Windows 上 `python3` 常是应用商店的占位入口（LookPath 能命中但执行返回 9009），
// 因此必须试跑一次 --version 才算可用。
func pythonBin() string {
	candidates := []string{"python3", "python"}
	if runtime.GOOS == "windows" {
		candidates = []string{"python", "python3"}
	}
	for _, name := range candidates {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if err := exec.Command(p, "--version").Run(); err == nil {
			return p
		}
	}
	return ""
}

// startEchoBinary 起 Go echo server 子进程，读 READY 行拿地址。
func startEchoBinary(t *testing.T) string {
	t.Helper()
	exe := buildArtifact("echo-server")
	if exe == "" {
		t.Skip("echo-server 未构建（先跑 make build）")
	}
	cmd := exec.Command(exe)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill() })

	line := make([]byte, 256)
	deadline := time.Now().Add(10 * time.Second)
	var got strings.Builder
	for time.Now().Before(deadline) {
		n, err := stdout.Read(line)
		if err != nil {
			break
		}
		got.Write(line[:n])
		if s := got.String(); strings.Contains(s, "READY ") && strings.Contains(s, "\n") {
			return strings.TrimSpace(strings.SplitN(s, " ", 2)[1])
		}
	}
	t.Fatal("echo server did not print READY")
	return ""
}

func runBinding(t *testing.T, lang, base, preset string) langResult {
	t.Helper()
	root, _ := filepath.Abs("../..")
	var cmd *exec.Cmd
	switch lang {
	case "python":
		py := pythonBin()
		if py == "" {
			t.Skip("python 解释器不可用")
		}
		cmd = exec.Command(py, filepath.Join(root, "tests", "e2e", "crosslang", "selfcheck.py"), preset, base)
	case "node":
		if _, err := exec.LookPath("node"); err != nil {
			t.Skip("node 不可用")
		}
		cmd = exec.Command("node", filepath.Join(root, "tests", "e2e", "crosslang", "selfcheck.js"), preset, base)
	}
	cmd.Env = append(os.Environ(),
		"GEEDTLS_LIB="+filepath.Join(root, "build", sharedLibName()),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s binding failed: %v\n%s", lang, err, out)
	}
	var r langResult
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(out))), &r); err != nil {
		t.Fatalf("%s output not JSON: %v\n%s", lang, err, out)
	}
	return r
}

func goBinding(t *testing.T, base, preset string) langResult {
	t.Helper()
	s, err := gbt.NewSession(preset, &gbt.Options{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.Do(&engine.Request{Method: "GET", URL: base + "/echo"})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return langResult{
		JA3Hash: resp.SelfCheck.JA3Hash,
		JA4:     resp.SelfCheck.JA4,
		Proto:   resp.UsedProtocol,
	}
}

func TestCrossLangConsistency(t *testing.T) {
	base := startEchoBinary(t)

	for _, preset := range []string{"chrome_133", "firefox_120"} {
		t.Run(preset, func(t *testing.T) {
			py := runBinding(t, "python", base, preset)
			js := runBinding(t, "node", base, preset)
			go_ := goBinding(t, base, preset)

			fmt.Printf("== %s ==\n", preset)
			fmt.Printf("  python ja4=%s ja3h=%s proto=%s\n", py.JA4, py.JA3Hash, py.Proto)
			fmt.Printf("  node   ja4=%s ja3h=%s proto=%s\n", js.JA4, js.JA3Hash, js.Proto)
			fmt.Printf("  golang ja4=%s ja3h=%s proto=%s\n", go_.JA4, go_.JA3Hash, go_.Proto)

			if py.JA4 != js.JA4 || js.JA4 != go_.JA4 {
				t.Errorf("JA4 mismatch across bindings")
			}
			// chrome 扩展洗牌 → JA3 逐连接变化是预期；firefox 无洗牌必须全等
			if preset == "firefox_120" && (py.JA3Hash != js.JA3Hash || js.JA3Hash != go_.JA3Hash) {
				t.Errorf("JA3 hash mismatch across bindings (no-shuffle preset)")
			}
			if py.Proto != "h2" || js.Proto != "h2" || go_.Proto != "h2" {
				t.Errorf("protocol mismatch: %s %s %s", py.Proto, js.Proto, go_.Proto)
			}
		})
	}
}
