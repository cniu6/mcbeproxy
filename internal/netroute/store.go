package netroute

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store persists the network settings to a JSON file.
type Store struct {
	path string
	mu   sync.Mutex
}

// NewStore returns a store for path (e.g. "network.json").
func NewStore(path string) *Store { return &Store{path: path} }

// Path returns the file path.
func (s *Store) Path() string { return s.path }

// Load reads the file and applies it. A missing file means defaults (system
// routing, no rules).
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return Apply(Config{})
		}
		return fmt.Errorf("read %s: %w", s.path, err)
	}
	var cfg Config
	if len(strings.TrimSpace(string(data))) > 0 {
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("parse %s: %w", s.path, err)
		}
	}
	return Apply(normalize(cfg))
}

// Save validates, applies and persists cfg.
func (s *Store) Save(cfg Config) (Config, error) {
	cfg = normalize(cfg)
	if err := Validate(cfg); err != nil {
		return cfg, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return cfg, err
	}
	if err := writeAtomic(s.path, data); err != nil {
		return cfg, err
	}
	return cfg, Apply(cfg)
}

func normalize(cfg Config) Config {
	cfg = cfg.Clone()
	cfg.Interface = strings.TrimSpace(cfg.Interface)
	if cfg.Rules == nil {
		cfg.Rules = []Rule{}
	}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if strings.TrimSpace(r.ID) == "" {
			r.ID = newRuleID()
		}
		if a := normalizeAction(r.Action); a != "" {
			r.Action = a
		}
	}
	return cfg
}

func newRuleID() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return "rule-" + hex.EncodeToString(b[:])
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	return os.Rename(name, path)
}
