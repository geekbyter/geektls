package profiles

// 预设注册表（P1-T7）：内置预设以 go:embed 随 core 二进制分发。
// 目录式管理（chrome/150/windows.json）与 evidence 归档是后续形态
// （00 文档 §3 的仓库根 profiles/ 目录在 core module 之外，无法 go:embed，
// 故内置预设放 core/profiles/builtin/）。

import (
	"embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed builtin
var builtinFS embed.FS

// List 返回全部内置预设名（排序、去 .json 后缀）。
func List() []string {
	entries, err := builtinFS.ReadDir("builtin")
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, strings.TrimSuffix(e.Name(), ".json"))
		}
	}
	sort.Strings(names)
	return names
}

// Get 按名取预设（解析并校验）。未知名字返回错误。
func Get(name string) (*Profile, error) {
	data, err := readBuiltin(name)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Describe 返回预设展开后的规范 JSON（= 期望值，测试直接消费，02 文档 §1）。
func Describe(name string) ([]byte, error) {
	p, err := Get(name)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(p, "", "  ")
}

func readBuiltin(name string) ([]byte, error) {
	if name == "" || strings.ContainsAny(name, `/\`) {
		return nil, fmt.Errorf("invalid preset name %q", name)
	}
	data, err := builtinFS.ReadFile("builtin/" + name + ".json")
	if err != nil {
		return nil, fmt.Errorf("preset not found: %q", name)
	}
	return data, nil
}
