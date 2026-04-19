package config

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	ProxySubscriptionAutoUpdateModeDaily    = "daily"
	ProxySubscriptionAutoUpdateModeInterval = "interval"

	defaultProxySubscriptionAutoUpdateTime         = "04:00"
	defaultProxySubscriptionAutoUpdateIntervalDays = 1
)

type ProxySubscription struct {
	ID                      string    `json:"id"`
	Name                    string    `json:"name"`
	URL                     string    `json:"url"`
	Enabled                 bool      `json:"enabled"`
	Group                   string    `json:"group,omitempty"`
	ProxyName               string    `json:"proxy_name,omitempty"`
	UserAgent               string    `json:"user_agent,omitempty"`
	AutoUpdateEnabled       *bool     `json:"auto_update_enabled,omitempty"`
	AutoUpdateMode          string    `json:"auto_update_mode,omitempty"`
	AutoUpdateTime          string    `json:"auto_update_time,omitempty"`
	AutoUpdateIntervalDays  int       `json:"auto_update_interval_days,omitempty"`
	AutoUpdateLastAttemptAt time.Time `json:"auto_update_last_attempt_at,omitempty"`
	LastUpdatedAt           time.Time `json:"last_updated_at,omitempty"`
	LastNodeCount           int       `json:"last_node_count,omitempty"`
	LastAdded               int       `json:"last_added,omitempty"`
	LastUpdated             int       `json:"last_updated,omitempty"`
	LastRemoved             int       `json:"last_removed,omitempty"`
	LastSubscriptionUploadBytes   int64     `json:"last_subscription_upload_bytes,omitempty"`
	LastSubscriptionDownloadBytes int64     `json:"last_subscription_download_bytes,omitempty"`
	LastSubscriptionTotalBytes    int64     `json:"last_subscription_total_bytes,omitempty"`
	LastSubscriptionExpireAt      time.Time `json:"last_subscription_expire_at,omitempty"`
	LastError               string    `json:"last_error,omitempty"`
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
	s.AutoUpdateMode = normalizeProxySubscriptionAutoUpdateMode(s.AutoUpdateMode)
	s.AutoUpdateTime = normalizeProxySubscriptionAutoUpdateTime(s.AutoUpdateTime)
	if s.AutoUpdateIntervalDays <= 0 {
		s.AutoUpdateIntervalDays = defaultProxySubscriptionAutoUpdateIntervalDays
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
	switch s.GetAutoUpdateMode() {
	case ProxySubscriptionAutoUpdateModeDaily:
		if _, _, err := parseProxySubscriptionAutoUpdateTime(s.GetAutoUpdateTime()); err != nil {
			return err
		}
	case ProxySubscriptionAutoUpdateModeInterval:
		if s.GetAutoUpdateIntervalDays() < 1 {
			return errors.New("auto_update_interval_days must be >= 1")
		}
	default:
		return fmt.Errorf("invalid auto_update_mode: %s", s.AutoUpdateMode)
	}
	return nil
}

func (s *ProxySubscription) IsAutoUpdateEnabled() bool {
	return s == nil || s.AutoUpdateEnabled == nil || *s.AutoUpdateEnabled
}

func (s *ProxySubscription) GetAutoUpdateMode() string {
	if s == nil {
		return ProxySubscriptionAutoUpdateModeDaily
	}
	return normalizeProxySubscriptionAutoUpdateMode(s.AutoUpdateMode)
}

func (s *ProxySubscription) GetAutoUpdateTime() string {
	if s == nil {
		return defaultProxySubscriptionAutoUpdateTime
	}
	return normalizeProxySubscriptionAutoUpdateTime(s.AutoUpdateTime)
}

func (s *ProxySubscription) GetAutoUpdateIntervalDays() int {
	if s == nil || s.AutoUpdateIntervalDays <= 0 {
		return defaultProxySubscriptionAutoUpdateIntervalDays
	}
	return s.AutoUpdateIntervalDays
}

func normalizeProxySubscriptionAutoUpdateMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", ProxySubscriptionAutoUpdateModeDaily:
		return ProxySubscriptionAutoUpdateModeDaily
	case ProxySubscriptionAutoUpdateModeInterval:
		return ProxySubscriptionAutoUpdateModeInterval
	default:
		return strings.ToLower(strings.TrimSpace(mode))
	}
}

func normalizeProxySubscriptionAutoUpdateTime(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return defaultProxySubscriptionAutoUpdateTime
	}
	if _, _, err := parseProxySubscriptionAutoUpdateTime(trimmed); err != nil {
		return trimmed
	}
	return trimmed
}

func parseProxySubscriptionAutoUpdateTime(value string) (int, int, error) {
	parsed, err := time.Parse("15:04", strings.TrimSpace(value))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid auto_update_time %q: expected HH:MM", value)
	}
	return parsed.Hour(), parsed.Minute(), nil
}
