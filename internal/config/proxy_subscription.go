package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type ProxySubscription struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	URL           string    `json:"url"`
	Enabled       bool      `json:"enabled"`
	Group         string    `json:"group,omitempty"`
	ProxyName     string    `json:"proxy_name,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	LastUpdatedAt time.Time `json:"last_updated_at,omitempty"`
	LastNodeCount int       `json:"last_node_count,omitempty"`
	LastAdded     int       `json:"last_added,omitempty"`
	LastUpdated   int       `json:"last_updated,omitempty"`
	LastRemoved   int       `json:"last_removed,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
}

func (s *ProxySubscription) Clone() *ProxySubscription {
	if s == nil {
		return nil
	}
	clone := *s
	return &clone
}

func (s *ProxySubscription) ApplyDefaults() {
	s.ID = strings.TrimSpace(s.ID)
	s.Name = strings.TrimSpace(s.Name)
	s.URL = strings.TrimSpace(s.URL)
	s.Group = strings.TrimSpace(s.Group)
	s.ProxyName = strings.TrimSpace(s.ProxyName)
	s.UserAgent = strings.TrimSpace(s.UserAgent)
	if s.UserAgent == "" {
		s.UserAgent = "Mozilla/5.0"
	}
}

func (s *ProxySubscription) Validate() error {
	if s == nil {
		return errors.New("proxy subscription is nil")
	}
	s.ApplyDefaults()
	if s.ID == "" {
		return errors.New("id is required")
	}
	if s.Name == "" {
		return errors.New("name is required")
	}
	if s.URL == "" {
		return errors.New("url is required")
	}
	parsed, err := url.Parse(s.URL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("url must start with http:// or https://")
	}
	if parsed.Host == "" {
		return errors.New("url host is required")
	}
	return nil
}
