package api

import (
	"errors"
	"fmt"
	"strings"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/netroute"
)

// 名称同时是线路引用键；先准备所有变更，再保存，失败按逆序回滚，不能留下半套引用。
type outboundRenameChange struct {
	apply func() error
	undo  func() error
}

func renameOutboundSelection(value, oldName, newName string) string {
	if strings.HasPrefix(strings.TrimSpace(value), "@") {
		return value
	}
	parts := strings.Split(value, ",")
	changed := false
	for i, part := range parts {
		if strings.TrimSpace(part) == oldName {
			parts[i] = newName
			changed = true
		}
	}
	if !changed {
		return value
	}
	return strings.Join(parts, ",")
}

func validateRenamedOutboundName(name string) error {
	if name == "" || strings.EqualFold(name, "direct") || strings.HasPrefix(name, "@") || strings.ContainsAny(name, ",\r\n\x00") {
		return errors.New("节点名称不能为空、不能为direct，不能以@开头或包含逗号/换行")
	}
	return nil
}

func (h *ProxyOutboundHandler) renameProxyOutboundConfig(oldName string, cfg *config.ProxyOutbound) error {
	if err := validateRenamedOutboundName(cfg.Name); err != nil {
		return err
	}
	previous, ok := h.configMgr.GetOutbound(oldName)
	if !ok {
		return fmt.Errorf("原节点 %q 不存在", oldName)
	}
	if _, exists := h.configMgr.GetOutbound(cfg.Name); exists {
		return fmt.Errorf("节点名称 %q 已存在", cfg.Name)
	}
	h.applySensitiveFieldDefaults(oldName, cfg)
	// 订阅源ID不随显示名称改变，后续刷新继续保留用户自定义名称。
	cfg.SubscriptionID, cfg.SubscriptionName, cfg.SubscriptionNodeID = previous.SubscriptionID, previous.SubscriptionName, previous.SubscriptionNodeID
	for i, hop := range cfg.Chain {
		if hop == oldName {
			cfg.Chain[i] = cfg.Name
		}
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	changes := []outboundRenameChange{{
		apply: func() error { return h.configMgr.UpdateOutbound(oldName, cfg) },
		undo:  func() error { return h.configMgr.UpdateOutbound(cfg.Name, previous) },
	}}
	runtimeChanges := []outboundRenameChange{}
	if h.outboundMgr != nil {
		runtimeChanges = append(runtimeChanges, outboundRenameChange{
			apply: func() error { return h.outboundMgr.UpdateOutbound(oldName, cfg) },
			undo:  func() error { return h.outboundMgr.UpdateOutbound(cfg.Name, previous) },
		})
	}
	for _, item := range h.configMgr.GetAllOutbounds() {
		if item.Name == oldName {
			continue
		}
		before, after := item.Clone(), item.Clone()
		changed := false
		for i, hop := range after.Chain {
			if hop == oldName {
				after.Chain[i] = cfg.Name
				changed = true
			}
		}
		if !changed {
			continue
		}
		if err := after.Validate(); err != nil {
			return err
		}
		changes = append(changes, outboundRenameChange{
			apply: func() error { return h.configMgr.UpdateOutbound(before.Name, after) },
			undo:  func() error { return h.configMgr.UpdateOutbound(before.Name, before) },
		})
		if h.outboundMgr != nil {
			runtimeChanges = append(runtimeChanges, outboundRenameChange{
				apply: func() error { return h.outboundMgr.UpdateOutbound(before.Name, after) },
				undo:  func() error { return h.outboundMgr.UpdateOutbound(before.Name, before) },
			})
		}
	}
	if h.serverConfigMgr != nil {
		for _, item := range h.serverConfigMgr.GetAllServers() {
			before, after := *item, *item
			after.ProxyOutbound = renameOutboundSelection(before.ProxyOutbound, oldName, cfg.Name)
			_, blocked := before.AutoSelectBlockedNodes[oldName]
			if after.ProxyOutbound == before.ProxyOutbound && !blocked {
				continue
			}
			if blocked {
				after.AutoSelectBlockedNodes = make(map[string]*config.NodeAutoSelectBlock, len(before.AutoSelectBlockedNodes))
				for name, block := range before.AutoSelectBlockedNodes {
					after.AutoSelectBlockedNodes[name] = block
				}
				after.AutoSelectBlockedNodes[cfg.Name] = after.AutoSelectBlockedNodes[oldName]
				delete(after.AutoSelectBlockedNodes, oldName)
			}
			changes = append(changes, outboundRenameChange{
				apply: func() error { return h.serverConfigMgr.UpdateServer(after.ID, &after) },
				undo:  func() error { return h.serverConfigMgr.UpdateServer(before.ID, &before) },
			})
		}
	}
	if h.portConfigMgr != nil {
		for _, item := range h.portConfigMgr.GetAllPorts() {
			before, after := item.Clone(), item.Clone()
			after.ProxyOutbound = renameOutboundSelection(before.ProxyOutbound, oldName, cfg.Name)
			changed := after.ProxyOutbound != before.ProxyOutbound
			for i := range after.Users {
				after.Users[i].ProxyOutbound = renameOutboundSelection(before.Users[i].ProxyOutbound, oldName, cfg.Name)
				changed = changed || after.Users[i].ProxyOutbound != before.Users[i].ProxyOutbound
			}
			if !changed {
				continue
			}
			// 安全入口活动时不为一次改名踢人；明确等待空闲或管理员停用。
			if after.IsSecure() && h.activityProvider != nil && h.activityProvider.GetActiveConnectionsForProxyPort(after.ID) > 0 {
				return errors.New("引用该节点的安全入口有活动连接，请空闲或停用后改名")
			}
			changes = append(changes, outboundRenameChange{
				apply: func() error { return h.portConfigMgr.UpdatePort(after.ID, after) },
				undo:  func() error { return h.portConfigMgr.UpdatePort(before.ID, before) },
			})
		}
	}
	if h.subConfigMgr != nil {
		for _, item := range h.subConfigMgr.GetAllSubscriptions() {
			before, after := item.Clone(), item.Clone()
			if before.ProxyName != oldName {
				continue
			}
			after.ProxyName = cfg.Name
			changes = append(changes, outboundRenameChange{
				apply: func() error { return h.subConfigMgr.UpdateSubscription(after.ID, after) },
				undo:  func() error { return h.subConfigMgr.UpdateSubscription(before.ID, before) },
			})
		}
	}
	if h.prepareRename != nil {
		extra, err := h.prepareRename(oldName, cfg.Name)
		if err != nil {
			return err
		}
		changes = append(changes, extra...)
	}
	changes = append(changes, runtimeChanges...)
	for i, change := range changes {
		if err := change.apply(); err != nil {
			result := fmt.Errorf("节点改名失败: %w", err)
			// 当前写入也可能已改变内存，故一并恢复。
			for j := i; j >= 0; j-- {
				if undoErr := changes[j].undo(); undoErr != nil {
					result = errors.Join(result, fmt.Errorf("回滚失败: %w", undoErr))
				}
			}
			return result
		}
	}
	h.triggerOutboundReloadHook(cfg.Name)
	return nil
}

func (a *APIServer) prepareOutboundRename(oldName, newName string) ([]outboundRenameChange, error) {
	before, after := netroute.Current(), netroute.Current()
	changed := false
	for i := range after.Rules {
		after.Rules[i].Outbound = renameOutboundSelection(before.Rules[i].Outbound, oldName, newName)
		changed = changed || after.Rules[i].Outbound != before.Rules[i].Outbound
	}
	if !changed {
		return nil, nil
	}
	if a.networkStore == nil {
		return nil, errors.New("路由规则存储不可用，无法安全更新节点引用")
	}
	if err := netroute.Validate(after); err != nil {
		return nil, err
	}
	return []outboundRenameChange{{
		apply: func() error { _, err := a.networkStore.Save(after); return err },
		undo:  func() error { _, err := a.networkStore.Save(before); return err },
	}}, nil
}
