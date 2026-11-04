package api

import (
	"strings"
	"testing"
)

// 公开状态页必须是构建时内联好的单文件：JS/CSS 已内嵌，不能再请求 assets/。
func TestStatusPageEmbeddedAndSelfContained(t *testing.T) {
	page, err := statusDistFS.ReadFile("status-dist/index.html")
	if err != nil {
		t.Fatalf("status page missing from embed: %v", err)
	}
	html := string(page)
	for _, want := range []string{`id="app"`, "<script", "naive-ui"} {
		if !strings.Contains(html, want) {
			t.Errorf("status page missing %q", want)
		}
	}
	for _, forbidden := range []string{`src="./assets/`, `href="./assets/`, `src="/assets/`} {
		if strings.Contains(html, forbidden) {
			t.Errorf("status page still references external asset %q", forbidden)
		}
	}
}
