package api

import (
	"os"
	"path/filepath"
	"testing"
)

// testDataCopyRoot holds per-call copies of testdata fixtures; removed after
// the package's tests finish.
var testDataCopyRoot string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "api-testdata-")
	if err != nil {
		panic(err)
	}
	testDataCopyRoot = dir
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// testDataCopy returns the path of a fresh copy of testdata/<name> (or of a
// not-yet-existing file when there is no fixture), so tests that save config
// never modify the committed fixtures.
func testDataCopy(name string) string {
	dir, err := os.MkdirTemp(testDataCopyRoot, "case-")
	if err != nil {
		panic(err)
	}
	dst := filepath.Join(dir, name)
	if data, err := os.ReadFile(filepath.Join("testdata", name)); err == nil {
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			panic(err)
		}
	}
	return dst
}
