package api

import (
	"testing"
	"testing/fstest"
)

func TestEncodingAccepted(t *testing.T) {
	cases := []struct {
		name           string
		acceptEncoding string
		coding         string
		want           bool
	}{
		{"empty header", "", "br", false},
		{"simple br", "br", "br", true},
		{"list with br", "gzip, deflate, br", "br", true},
		{"list with gzip", "gzip, deflate, br", "gzip", true},
		{"gzip only, ask br", "gzip", "br", false},
		{"br disabled with q=0", "br;q=0, gzip", "br", false},
		{"br disabled still serves gzip", "br;q=0, gzip", "gzip", true},
		{"gzip disabled with q=0", "gzip;q=0", "gzip", false},
		{"br with positive q", "br;q=0.5", "br", true},
		{"whitespace and case", " BR ; q=1.0 ", "br", true},
		{"wildcard accepts", "*", "br", true},
		{"wildcard disabled", "*;q=0", "br", false},
		{"wildcard disabled but br explicit", "br, *;q=0", "br", true},
		{"substring false positive guard", "gzip", "br", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := encodingAccepted(tc.acceptEncoding, tc.coding); got != tc.want {
				t.Fatalf("encodingAccepted(%q, %q) = %v, want %v", tc.acceptEncoding, tc.coding, got, tc.want)
			}
		})
	}
}

func TestPickPrecompressed(t *testing.T) {
	subFS := fstest.MapFS{
		"assets/app.js":      {Data: []byte("plain")},
		"assets/app.js.br":   {Data: []byte("brotli")},
		"assets/app.js.gz":   {Data: []byte("gzip")},
		"assets/only.css.gz": {Data: []byte("gzip-only")},
	}

	t.Run("prefers brotli when accepted", func(t *testing.T) {
		enc, data := pickPrecompressed(subFS, "/app.js", "gzip, deflate, br")
		if enc != "br" || string(data) != "brotli" {
			t.Fatalf("got enc=%q data=%q, want br/brotli", enc, data)
		}
	})

	t.Run("br refused with q=0 falls back to gzip", func(t *testing.T) {
		enc, data := pickPrecompressed(subFS, "/app.js", "br;q=0, gzip")
		if enc != "gzip" || string(data) != "gzip" {
			t.Fatalf("got enc=%q data=%q, want gzip/gzip", enc, data)
		}
	})

	t.Run("no compression accepted", func(t *testing.T) {
		enc, _ := pickPrecompressed(subFS, "/app.js", "identity")
		if enc != "" {
			t.Fatalf("got enc=%q, want empty", enc)
		}
	})

	t.Run("only gzip variant exists", func(t *testing.T) {
		enc, data := pickPrecompressed(subFS, "/only.css", "br, gzip")
		if enc != "gzip" || string(data) != "gzip-only" {
			t.Fatalf("got enc=%q data=%q, want gzip/gzip-only", enc, data)
		}
	})

	t.Run("no variant exists", func(t *testing.T) {
		enc, _ := pickPrecompressed(subFS, "/missing.js", "br, gzip")
		if enc != "" {
			t.Fatalf("got enc=%q, want empty", enc)
		}
	})
}
