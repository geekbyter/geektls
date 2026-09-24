package profiles

import "testing"

// P7-T3 fuzz：profile 解析层零 panic 保证。种子 = 现有用例 + 畸形样本。

var fuzzSeeds = []string{
	// 正常
	`{"name":"x","tls":{"detail":{"ciphers":["0x1301"],"extensions":[{"type":0,"sni":"auto"}]}}}`,
	`{"name":"chrome_150_windows","tls":{"detail":{"legacy_version":"0x0303","ciphers":["grease","0x1301"],"extensions":[{"type":43,"versions":["grease","0x0304"]},{"type":51,"key_shares":["grease","X25519MLKEM768"]},{"type":65037,"ech":{"mode":"grease"}}],"extension_permutation":true,"grease":{"ciphers":true}}}`,
	// 畸形
	`{`,
	`{"tls":{"detail":{"bogus":1}}}`,
	`{"tls":{"detail":{"ciphers":["zz"]}}}`,
	`{"tls":{"detail":{"ciphers":["0x12345"]}}}`,
	`{"tls":{"detail":{"extensions":[{"type":65535,"data":"ff"}]}}}`,
	`{"tls":{"detail":{"extensions":[{"type":10,"groups":["nope"]}]}}}`,
	`{"tls":{"detail":{"extensions":[{"type":65037,"ech":{"mode":"real","config_list_hex":"zz"}}]}}}`,
	`{"tls":{"detail":{"extensions":[{"type":21,"padding_to":-1}]}}}`,
	`null`, `[]`, `"str"`, `123`, `""`,
	`{"tls":{"detail":{"legacy_version":"0x0303"}}}`,
}

func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		// 契约：返回 error 或 Profile，绝不 panic
		_, _ = Parse(data)
	})
}

var ja3Seeds = []string{
	"771,4865-4866-4867-49195-49196,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0",
	"771,49199,,,",
	"771,4865,0,29,",
	"",
	",,,,",
	"abc,4865,,,",
	"771-772,4865,,,",
	"771,99999,,,",
	"1,2,3,4,5,6",
	"771,4865-,0-,29-,0-",
	"0,0,0,0,0",
	"65535,65535,65535,65535,65535",
}

func FuzzFromJA3(f *testing.F) {
	for _, s := range ja3Seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ja3 string) {
		_, _, _ = FromJA3(ja3)
	})
}

var ja4rSeeds = []string{
	"t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0015,0017,001b,0023,002b,002d,0033,4469,ff01_0403,0804,0401,0503,0805,0501,0806,0601",
	"t13d1516h2_1301_000a_0403",
	"t12i0000_0_0_0",
	"",
	"t13d1516h2",
	"t13d1516h2_zz_b_c",
	"x13d1516h2_a_b_c",
	"t13x1516h2_a_b_c",
	"t13d151h2_a_b_c",
	"q13d9999h2_1301_000a_",
	"t13d1516h2__000a_",
}

func FuzzFromJA4R(f *testing.F) {
	for _, s := range ja4rSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ja4r string) {
		_, _, _ = FromJA4R(ja4r)
	})
}

var hexSeeds = []string{
	"160301004b010000470303" + "0000000000000000000000000000000000000000000000000000000000000000" + "00" + "00021301" + "0100" + "001c" + "0000000d000b0000086578616d706c650a00040002001d" + "fde80102dead",
	"", "zzzz", "16", "1603010000",
	"17030300000000000000",
	"16030100090100000003030000",
	"160301ff010000000303" + "0000000000000000000000000000000000000000000000000000000000000000" + "00" + "00021301" + "0100" + "ffff" + "00",
	// 截断变种（在 fuzz 引擎变异之外手动覆盖）
	"160301004b01",
	"160301004b0100004703030000",
}

func FuzzFromClientHelloHex(f *testing.F) {
	for _, s := range hexSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, hexStr string) {
		_, _, _ = FromClientHelloHex(hexStr)
	})
}
