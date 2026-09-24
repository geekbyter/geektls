// Go 冒烟：经薄封装取版本 JSON，校验 abi==1（与 c-shared 的 gtls_version 同源常量）。
package main

import (
	"encoding/json"
	"fmt"
	"os"

	geektls "github.com/geektls/golang"
)

func main() {
	raw := geektls.Version()
	fmt.Println("geektls version:", raw)

	var v struct {
		ABI int `json:"abi"`
	}
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		fmt.Fprintln(os.Stderr, "smoke: invalid version JSON:", err)
		os.Exit(1)
	}
	if v.ABI != geektls.ABI {
		fmt.Fprintf(os.Stderr, "smoke: abi mismatch: got %d, want %d\n", v.ABI, geektls.ABI)
		os.Exit(1)
	}
	fmt.Println("go smoke OK")
}
