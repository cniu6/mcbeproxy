package api

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 回归：//go:embed 默认跳过 _ 和 . 开头的文件，而 Vite 会生成
// assets/_plugin-vue_export-helper-*.js。这里逐一比对磁盘与嵌入内容，
// 任何漏嵌入都会在面板动态导入时变成 404。
func TestEmbeddedDistContainsEveryBuiltFile(t *testing.T) {
	root := "dist"
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		t.Skip("dist not built")
	}
	checked := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		embeddedPath := "dist/" + filepath.ToSlash(rel)
		if _, readErr := distFS.ReadFile(embeddedPath); readErr != nil {
			t.Errorf("built file missing from embed: %s (%v)", embeddedPath, readErr)
			return nil
		}
		checked++
		return nil
	})
	if err != nil {
		t.Fatalf("walk dist: %v", err)
	}
	if checked == 0 {
		t.Fatal("no files checked; dist appears empty")
	}
	if _, err := fs.Stat(distFS, "dist/index.html"); err != nil {
		t.Fatalf("index.html missing from embed: %v", err)
	}
	underscored := false
	_ = fs.WalkDir(distFS, "dist", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr == nil && !entry.IsDir() && strings.HasPrefix(entry.Name(), "_") {
			underscored = true
		}
		return nil
	})
	if !underscored {
		t.Log("no underscore-prefixed asset in this build; all: pattern still required for future ones")
	}
}
