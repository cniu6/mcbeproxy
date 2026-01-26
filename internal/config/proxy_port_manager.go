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

// ProxyPortConfigManager manages proxy port configurations with hot reload support.
type ProxyPortConfigManager struct {
	ports      map[string]*ProxyPortConfig
	mu         sync.RWMutex
	configPath string
	watcher    *fsnotify.Watcher
	watcherMu  sync.Mutex
	onChange   func()
}

// NewProxyPortConfigManager creates a new ProxyPortConfigManager instance.
func NewProxyPortConfigManager(configPath string) *ProxyPortConfigManager {
	return &ProxyPortConfigManager{
		ports:      make(map[string]*ProxyPortConfig),
		configPath: configPath,
	}
}

// Load loads proxy port configurations from the JSON file.
// If the file doesn't exist, it initializes with an empty configuration.
func (m *ProxyPortConfigManager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			m.ports = make(map[string]*ProxyPortConfig)
			return nil
		}
		return fmt.Errorf("failed to read proxy port config file: %w", err)
	}

	var configs []*ProxyPortConfig
	if err := json.Unmarshal(data, &configs); err != nil {
		return fmt.Errorf("failed to parse proxy port config file: %w", err)
	}

	newPorts := make(map[string]*ProxyPortConfig)
	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		if err := cfg.Validate(); err != nil {
			return fmt.Errorf("invalid proxy port config for %s: %w", cfg.ID, err)
		}
		newPorts[cfg.ID] = cfg.Clone()
	}

	m.ports = newPorts
	return nil
}

// Save persists the current proxy port configurations to the JSON file.
func (m *ProxyPortConfigManager) Save() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.saveToFile()
}

func (m *ProxyPortConfigManager) saveToFile() error {
	ports := make([]*ProxyPortConfig, 0, len(m.ports))
	for _, cfg := range m.ports {
		ports = append(ports, cfg.Clone())
	}
	data, err := json.MarshalIndent(ports, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal proxy port config: %w", err)
	}
	if err := os.WriteFile(m.configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write proxy port config file: %w", err)
	}
	return nil
}

// Reload reloads configurations from the file.
func (m *ProxyPortConfigManager) Reload() error {
	if err := m.Load(); err != nil {
		return err
	}
	if m.onChange != nil {
		m.onChange()
	}
	return nil
}

// GetPort returns a proxy port configuration by id.
func (m *ProxyPortConfigManager) GetPort(id string) (*ProxyPortConfig, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cfg, ok := m.ports[id]
	if !ok {
		return nil, false
	}
	return cfg.Clone(), true
}

// GetAllPorts returns all proxy port configurations.
func (m *ProxyPortConfigManager) GetAllPorts() []*ProxyPortConfig {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]*ProxyPortConfig, 0, len(m.ports))
	for _, cfg := range m.ports {
		result = append(result, cfg.Clone())
	}
	return result
}

// AddPort adds a new proxy port configuration.
func (m *ProxyPortConfigManager) AddPort(cfg *ProxyPortConfig) error {
	if cfg == nil {
		return fmt.Errorf("proxy port config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.ports[cfg.ID]; exists {
		return fmt.Errorf("proxy port with id %s already exists", cfg.ID)
	}
	m.ports[cfg.ID] = cfg.Clone()
	return m.saveToFile()
}

// UpdatePort updates an existing proxy port configuration.
func (m *ProxyPortConfigManager) UpdatePort(id string, cfg *ProxyPortConfig) error {
	if cfg == nil {
		return fmt.Errorf("proxy port config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.ports[id]; !exists {
		return fmt.Errorf("proxy port with id %s not found", id)
	}
	if id != cfg.ID {
		delete(m.ports, id)
	}
	m.ports[cfg.ID] = cfg.Clone()
	return m.saveToFile()
}

// DeletePort removes a proxy port configuration.
func (m *ProxyPortConfigManager) DeletePort(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.ports[id]; !exists {
		return fmt.Errorf("proxy port with id %s not found", id)
	}
	delete(m.ports, id)
	return m.saveToFile()
}

// SetOnChange sets a callback for config changes.
func (m *ProxyPortConfigManager) SetOnChange(callback func()) {
	m.onChange = callback
}

// Watch starts watching the configuration file for changes.
func (m *ProxyPortConfigManager) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %w", err)
	}

	m.watcherMu.Lock()
	m.watcher = watcher
	m.watcherMu.Unlock()

	if _, err := os.Stat(m.configPath); os.IsNotExist(err) {
		if err := os.WriteFile(m.configPath, []byte("[]"), 0644); err != nil {
			watcher.Close()
			return fmt.Errorf("failed to create config file: %w", err)
		}
	}

	if err := watcher.Add(m.configPath); err != nil {
		m.closeWatcher()
		return fmt.Errorf("failed to watch proxy port config file: %w", err)
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
				if event.Op&fsnotify.Write == fsnotify.Write ||
					event.Op&fsnotify.Create == fsnotify.Create {
					time.Sleep(100 * time.Millisecond)
					if err := m.Reload(); err != nil {
						fmt.Printf("proxy port config reload error: %v\n", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Printf("proxy port config watcher error: %v\n", err)
			}
		}
	}()

	return nil
}

// StopWatch stops watching the configuration file.
func (m *ProxyPortConfigManager) StopWatch() {
	m.closeWatcher()
}

func (m *ProxyPortConfigManager) closeWatcher() {
	m.watcherMu.Lock()
	defer m.watcherMu.Unlock()
	if m.watcher != nil {
		m.watcher.Close()
		m.watcher = nil
	}
}
