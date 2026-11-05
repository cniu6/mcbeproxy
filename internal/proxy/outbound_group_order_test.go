package proxy

import (
	"fmt"
	"testing"

	"mcpeserverproxy/internal/config"
)

func TestListGroupsUngroupedFirstStable(t *testing.T) {
	manager := NewOutboundManager(nil)
	for i, group := range []string{"Z", "香港", "", "A", ""} {
		if err := manager.AddOutbound(&config.ProxyOutbound{
			Name: fmt.Sprintf("order-node-%d", i), Type: config.ProtocolSOCKS5,
			Server: "127.0.0.1", Port: 1080, Enabled: true, Group: group,
		}); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"", "A", "Z", "香港"}
	// 重复读取覆盖map迭代顺序变化，未分类不能随刷新漂移。
	for refresh := 0; refresh < 100; refresh++ {
		groups := manager.ListGroups()
		if len(groups) != len(want) {
			t.Fatalf("group count: got %d, want %d", len(groups), len(want))
		}
		for i, name := range want {
			if groups[i].Name != name {
				t.Fatalf("refresh %d group %d: got %q, want %q", refresh, i, groups[i].Name, name)
			}
		}
		if groups[0].TotalCount != 2 {
			t.Fatal("ordering changed ungrouped statistics")
		}
	}
}
