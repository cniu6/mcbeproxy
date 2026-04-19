package config

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

type ProxySubscriptionConfigManager struct {
	subscriptions map[string]*ProxySubscription
	mu            sync.RWMutex
	configPath    string
}

func NewProxySubscriptionConfigManager(configPath string) *ProxySubscriptionConfigManager {
	return &ProxySubscriptionConfigManager{
		subscriptions: make(map[string]*ProxySubscription),
		configPath:    configPath,
	}
}

func (m *ProxySubscriptionConfigManager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			m.subscriptions = make(map[string]*ProxySubscription)
			return nil
		}
		return fmt.Errorf("failed to read proxy subscription config file: %w", err)
	}

	var configs []*ProxySubscription
	if err := json.Unmarshal(data, &configs); err != nil {
		return fmt.Errorf("failed to parse proxy subscription config file: %w", err)
	}

	loaded := make(map[string]*ProxySubscription, len(configs))
	seenNames := make(map[string]string, len(configs))
	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid proxy subscription config for %s: %w", cfg.ID, err)
		}
		if _, exists := loaded[cfg.ID]; exists {
			return fmt.Errorf("duplicate proxy subscription id %s", cfg.ID)
		}
		nameKey := normalizeProxySubscriptionName(cfg.Name)
		if existingID, exists := seenNames[nameKey]; exists {
			return fmt.Errorf("duplicate proxy subscription name %s for %s and %s", cfg.Name, existingID, cfg.ID)
		}
		seenNames[nameKey] = cfg.ID
		loaded[cfg.ID] = cfg.Clone()
	}

	m.subscriptions = loaded
	return nil
}

func (m *ProxySubscriptionConfigManager) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.saveToFile()
}

func (m *ProxySubscriptionConfigManager) saveToFile() error {
	items := make([]*ProxySubscription, 0, len(m.subscriptions))
	for _, cfg := range m.subscriptions {
		items = append(items, cfg.Clone())
	}
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	data, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal proxy subscription config: %w", err)
	}
	if err := atomicWriteFile(m.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write proxy subscription config file: %w", err)
	}
	return nil
}

func (m *ProxySubscriptionConfigManager) GetSubscription(id string) (*ProxySubscription, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.subscriptions[id]
	if !ok {
		return nil, false
	}
	return cfg.Clone(), true
}

func (m *ProxySubscriptionConfigManager) GetAllSubscriptions() []*ProxySubscription {
	m.mu.RLock()
	defer m.mu.RUnlock()
	items := make([]*ProxySubscription, 0, len(m.subscriptions))
	for _, cfg := range m.subscriptions {
		items = append(items, cfg.Clone())
	}
	sort.Slice(items, func(i, j int) bool {
		return strings.ToLower(items[i].Name) < strings.ToLower(items[j].Name)
	})
	return items
}

func normalizeProxySubscriptionName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func (m *ProxySubscriptionConfigManager) ensureUniqueLocked(cfg *ProxySubscription, existingID string) error {
	if cfg == nil {
		return fmt.Errorf("proxy subscription is nil")
	}
	if cfg.ID == "" {
		return fmt.Errorf("proxy subscription id is required")
	}
	if current, exists := m.subscriptions[cfg.ID]; exists && (existingID == "" || cfg.ID != existingID) && current != nil {
		return fmt.Errorf("proxy subscription with id %s already exists", cfg.ID)
	}
	nameKey := normalizeProxySubscriptionName(cfg.Name)
	for id, existing := range m.subscriptions {
		if id == existingID || existing == nil {
			continue
		}
		if normalizeProxySubscriptionName(existing.Name) == nameKey {
			return fmt.Errorf("proxy subscription name %s already exists", cfg.Name)
		}
	}
	return nil
}

func (m *ProxySubscriptionConfigManager) AddSubscription(cfg *ProxySubscription) error {
	if cfg == nil {
		return fmt.Errorf("proxy subscription is nil")
	}
	clone := cfg.Clone()
	if err := clone.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.ensureUniqueLocked(clone, ""); err != nil {
		return err
	}
	m.subscriptions[clone.ID] = clone
	return m.saveToFile()
}

func (m *ProxySubscriptionConfigManager) UpdateSubscription(id string, cfg *ProxySubscription) error {
	if cfg == nil {
		return fmt.Errorf("proxy subscription is nil")
	}
	clone := cfg.Clone()
	if err := clone.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.subscriptions[id]; !exists {
		return fmt.Errorf("proxy subscription with id %s not found", id)
	}
	if err := m.ensureUniqueLocked(clone, id); err != nil {
		return err
	}
	if id != clone.ID {
		delete(m.subscriptions, id)
	}
	m.subscriptions[clone.ID] = clone
	return m.saveToFile()
}

func (m *ProxySubscriptionConfigManager) DeleteSubscription(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.subscriptions[id]; !exists {
		return fmt.Errorf("proxy subscription with id %s not found", id)
	}
	delete(m.subscriptions, id)
	return m.saveToFile()
}
