package profiles

import (
	"strings"
	"testing"
)

// TestParseValidProfile 用 03 文档 schema 的形态走一遍解析。
func TestParseValidProfile(t *testing.T) {
	doc := `{
	  "name": "chrome_150_windows",
	  "extends": "chrome_150",
	  "tls": {
	    "detail": {
	      "legacy_version": "0x0303",
	      "ciphers": ["grease", "0x1301", "0x1302", "0x1303", "0xc02b"],
	      "extensions": [
	        {"type": 0, "sni": "auto"},
	        {"type": 35, "data": ""},
	        {"type": 43, "versions": ["grease", "0x0304", "0x0303"]},
	        {"type": 51, "key_shares": ["grease", "X25519MLKEM768", "X25519"]},
	        {"type": 16, "alpn": ["h2", "http/1.1"]},
	        {"type": 13, "sig_algs": ["0x0403", "0x0804"]},
	        {"type": 21, "padding_to": 512},
	        {"type": 65037, "ech": {"mode": "grease"}}
	      ],
	      "extension_permutation": true,
	      "grease": {"ciphers": true, "extensions": true, "groups": true},
	      "cert_compression": ["brotli"],
	      "alps": true,
	      "record_size_limit": null,
	      "delegated_credentials": null
	    }
	  },
	  "http2": {
	    "settings": [[1, 65536], [2, 0], [4, 6291456], [6, 262144]],
	    "window_update": 15663105,
	    "pseudo_header_order": ["m", "s", "a", "p"]
	  },
	  "http3": {"enabled": true, "quic_version": "0x00000001", "h2_race_ms": 300},
	  "tcp": {"ttl": 128, "mss": 1460, "window_size": 65535, "window_scale": 8},
	  "http1": {"header_order": ["host", "connection"], "header_case": "preserve"},
	  "behavior": {"redirect_max": 10, "cookie_jar": true, "session_resumption": true}
	}`

	p, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Name != "chrome_150_windows" || p.TLS.Detail == nil {
		t.Fatalf("unexpected profile: %+v", p)
	}
	if len(p.TLS.Detail.Extensions) != 8 {
		t.Errorf("extensions = %d, want 8", len(p.TLS.Detail.Extensions))
	}
	if p.HTTP2.WindowUpdate != 15663105 || p.TCP.TTL != 128 || p.Behavior.RedirectMax != 10 {
		t.Errorf("later-phase sections not preserved: %+v", p)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		name    string
		doc     string
		wantSub string
	}{
		{"malformed json", `{`, "malformed JSON"},
		{"unknown field", `{"tls":{"detail":{"bogus":1}}}`, "unknown field"},
		{"bad cipher hex", `{"tls":{"detail":{"ciphers":["zz"]}}}`, "ciphers[0]"},
		{"cipher missing 0x", `{"tls":{"detail":{"ciphers":["1301"]}}}`, "0x prefix"},
		{"unknown group", `{"tls":{"detail":{"extensions":[{"type":10,"groups":["nope"]}]}}}`, "unknown group"},
		{"bad sig alg", `{"tls":{"detail":{"extensions":[{"type":13,"sig_algs":["x"]}]}}}`, "sig_algs"},
		{"bad padding", `{"tls":{"detail":{"extensions":[{"type":21,"padding_to":-1}]}}}`, "padding_to"},
		{"bad ech mode", `{"tls":{"detail":{"extensions":[{"type":65037,"ech":{"mode":"real"}}]}}}`, "ech.mode"},
		{"bad legacy version", `{"tls":{"detail":{"legacy_version":"0303"}}}`, "legacy_version"},
		{"bad cert comp", `{"tls":{"detail":{"cert_compression":["lz4"]}}}`, "cert_compression"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.doc))
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			pe, ok := err.(*ParseError)
			if !ok {
				t.Fatalf("error type = %T, want *ParseError", err)
			}
			if !strings.Contains(pe.Error(), tc.wantSub) {
				t.Errorf("error %q missing %q", pe.Error(), tc.wantSub)
			}
		})
	}
}

func TestParseEmptyDetailOK(t *testing.T) {
	p, err := Parse([]byte(`{"name":"minimal"}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Name != "minimal" {
		t.Errorf("name = %q", p.Name)
	}
}
