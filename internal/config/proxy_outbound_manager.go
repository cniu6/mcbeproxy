// Package config provides configuration management functionality.
package config

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ProxyOutboundConfigManager manages proxy outbound configurations with hot reload support.
type ProxyOutboundConfigManager struct {
	outbounds  map[string]*ProxyOutbound
	mu         sync.RWMutex
	configPath string
	watcher    *fsnotify.Watcher
	watcherMu  sync.Mutex
	onChange   func() // callback when config changes
}

// NewProxyOutboundConfigManager creates a new ProxyOutboundConfigManager instance.
func NewProxyOutboundConfigManager(configPath string) *ProxyOutboundConfigManager {
	return &ProxyOutboundConfigManager{
		outbounds:  make(map[string]*ProxyOutbound),
		configPath: configPath,
	}
}

// Load loads proxy outbound configurations from the JSON file.
// If the file doesn't exist, it initializes with an empty configuration.
func (m *ProxyOutboundConfigManager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, start with empty config
			m.outbounds = make(map[string]*ProxyOutbound)
			return nil
		}
		return fmt.Errorf("failed to read proxy outbound config file: %w", err)
	}

	var configs []*ProxyOutbound
	if err := json.Unmarshal(data, &configs); err != nil {
		return fmt.Errorf("failed to parse proxy outbound config file: %w", err)
	}

	// Validate all configs before applying
	for _, config := range configs {
		if err := config.Validate(); err != nil {
			return fmt.Errorf("invalid proxy outbound config for %s: %w", config.Name, err)
		}
	}

	// Clear existing and add new configs
	newOutbounds := make(map[string]*ProxyOutbound)
	for _, config := range configs {
		newOutbounds[config.Name] = config
	}

	m.outbounds = newOutbounds
	return nil
}

// Save persists the current proxy outbound configurations to the JSON file.
func (m *ProxyOutboundConfigManager) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.saveToFile()
}

// saveToFile persists the current configuration to the JSON file (must be called with lock held).
func (m *ProxyOutboundConfigManager) saveToFile() error {
	outbounds := make([]*ProxyOutbound, 0, len(m.outbounds))
	for _, outbound := range m.outbounds {
		outbounds = append(outbounds, outbound.Clone())
	}

	data, err := json.MarshalIndent(outbounds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal proxy outbound config: %w", err)
	}

	if err := os.WriteFile(m.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write proxy outbound config file: %w", err)
	}

	return nil
}

// Reload reloads configurations from the file.
func (m *ProxyOutboundConfigManager) Reload() error {
	if err := m.Load(); err != nil {
		return err
	}
	if m.onChange != nil {
		m.onChange()
	}
	return nil
}

// GetOutbound returns a proxy outbound configuration by name.
func (m *ProxyOutboundConfigManager) GetOutbound(name string) (*ProxyOutbound, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	outbound, ok := m.outbounds[name]
	if !ok {
		return nil, false
	}
	return outbound.Clone(), true
}

// GetAllOutbounds returns all proxy outbound configurations.
func (m *ProxyOutboundConfigManager) GetAllOutbounds() []*ProxyOutbound {
	m.mu.RLock()
	defer m.mu.RUnlock()
	outbounds := make([]*ProxyOutbound, 0, len(m.outbounds))
	for _, outbound := range m.outbounds {
		outbounds = append(outbounds, outbound.Clone())
	}
	return outbounds
}

// GetAll returns all proxy outbound configurations.
// It is an alias for GetAllOutbounds (kept for scheduler compatibility).
func (m *ProxyOutboundConfigManager) GetAll() []*ProxyOutbound {
	return m.GetAllOutbounds()
}

// GetByName returns a proxy outbound configuration by name.
// It is an alias for GetOutbound (kept for scheduler compatibility).
func (m *ProxyOutboundConfigManager) GetByName(name string) (*ProxyOutbound, bool) {
	return m.GetOutbound(name)
}

// GetByGroup returns all proxy outbound configurations in the given group.
func (m *ProxyOutboundConfigManager) GetByGroup(group string) []*ProxyOutbound {
	m.mu.RLock()
	defer m.mu.RUnlock()

	outbounds := make([]*ProxyOutbound, 0)
	for _, outbound := range m.outbounds {
		if outbound.Group == group {
			outbounds = append(outbounds, outbound.Clone())
		}
	}
	return outbounds
}

// AddOutbound adds a new proxy outbound configuration.
func (m *ProxyOutboundConfigManager) AddOutbound(config *ProxyOutbound) error {
	if err := config.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.outbounds[config.Name]; exists {
		return fmt.Errorf("proxy outbound with name %s already exists", config.Name)
	}

	m.outbounds[config.Name] = config.Clone()
	return m.saveToFile()
}

// UpdateOutbound updates an existing proxy outbound configuration.
func (m *ProxyOutboundConfigManager) UpdateOutbound(name string, config *ProxyOutbound) error {
	if err := config.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.outbounds[name]; !exists {
		return fmt.Errorf("proxy outbound with name %s not found", name)
	}

	// If name changed, remove old entry
	if name != config.Name {
		delete(m.outbounds, name)
	}
	m.outbounds[config.Name] = config.Clone()
	return m.saveToFile()
}

// DeleteOutbound removes a proxy outbound configuration.
func (m *ProxyOutboundConfigManager) DeleteOutbound(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.outbounds[name]; !exists {
		return fmt.Errorf("proxy outbound with name %s not found", name)
	}

	delete(m.outbounds, name)
	return m.saveToFile()
}

// SetOnChange sets a callback function to be called when configuration changes.
func (m *ProxyOutboundConfigManager) SetOnChange(callback func()) {
	m.onChange = callback
}

// OutboundCount returns the number of configured proxy outbounds.
func (m *ProxyOutboundConfigManager) OutboundCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.outbounds)
}

// GetConfigPath returns the configuration file path.
func (m *ProxyOutboundConfigManager) GetConfigPath() string {
	return m.configPath
}

// Watch starts watching the configuration file for changes.
// When changes are detected, it automatically reloads the configuration.
func (m *ProxyOutboundConfigManager) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	m.watcherMu.Lock()
	m.watcher = watcher
	m.watcherMu.Unlock()

	// Ensure the config file exists before watching
	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		// Create an empty config file
		if err := os.WriteFile(m.configPath, []byte("[]"), 0644); err != nil {
			watcher.Close()
			return fmt.Errorf("failed to create config file: %w", err)
		}
	}

	// Add the config file to the watcher
	if err := watcher.Add(m.configPath); err != nil {
		m.closeWatcher()
		return fmt.Errorf("failed to watch proxy outbound config file: %w", err)
	}

	go func() {
		defer m.closeWatcher()

		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Reload on write or create events
				if event.Op&fsnotify.Write == fsnotify.Write ||
					event.Op&fsnotify.Create == fsnotify.Create {
					// Small delay to ensure file write is complete
					time.Sleep(100 * time.Millisecond)
					if err := m.Reload(); err != nil {
						// Log error but continue watching
						fmt.Printf("proxy outbound config reload error: %v\n", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				// Log error but continue watching
				fmt.Printf("proxy outbound config watcher error: %v\n", err)
			}
		}
	}()

	return nil
}

// StopWatch stops watching the configuration file.
func (m *ProxyOutboundConfigManager) StopWatch() {
	m.closeWatcher()
}

// IsWatching returns true if the config manager is watching for file changes.
func (m *ProxyOutboundConfigManager) IsWatching() bool {
	m.watcherMu.Lock()
	defer m.watcherMu.Unlock()
	return m.watcher != nil
}

func (m *ProxyOutboundConfigManager) closeWatcher() {
	m.watcherMu.Lock()
	defer m.watcherMu.Unlock()
	if m.watcher != nil {
		m.watcher.Close()
		m.watcher = nil
	}
}
