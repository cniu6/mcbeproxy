// Package config provides configuration management functionality.
package config

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ProxyPortType constants.
const (
	ProxyPortTypeHTTP   = "http"
	ProxyPortTypeSocks5 = "socks5"
	ProxyPortTypeSocks4 = "socks4"
	ProxyPortTypeMixed  = "mixed"
	ProxyPortTypeSock   = "sock" // alias of socks4
)

// ProxyPortConfig represents a local proxy port configuration.
type ProxyPortConfig struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	ListenAddr      string   `json:"listen_addr"`
	Type            string   `json:"type"` // http, socks5, socks4, mixed
	Enabled         bool     `json:"enabled"`
	Username        string   `json:"username,omitempty"`
	Password        string   `json:"password,omitempty"`
	ProxyOutbound   string   `json:"proxy_outbound"`    // Proxy outbound name or "@group" or "node1,node2"
	LoadBalance     string   `json:"load_balance"`      // least-latency, round-robin, random, least-connections
	LoadBalanceSort string   `json:"load_balance_sort"` // tcp, http, udp
	AllowList       []string `json:"allow_list"`        // CIDR list
}

// Clone returns a deep copy of the config.
func (pc *ProxyPortConfig) Clone() *ProxyPortConfig {
	if pc == nil {
		return nil
	}
	clone := *pc
	if pc.AllowList != nil {
		clone.AllowList = append([]string{}, pc.AllowList...)
	}
	return &clone
}

// ApplyDefaults normalizes fields and fills defaults.
func (pc *ProxyPortConfig) ApplyDefaults() {
	pc.Type = strings.ToLower(strings.TrimSpace(pc.Type))
	if pc.Type == ProxyPortTypeSock {
		pc.Type = ProxyPortTypeSocks4
	}
	if pc.AllowList == nil || len(pc.AllowList) == 0 {
		pc.AllowList = []string{"0.0.0.0/0"}
	}
	if pc.ID == "" && pc.Name != "" {
		pc.ID = pc.Name
	}
}

// Validate checks if required fields are present and valid.
func (pc *ProxyPortConfig) Validate() error {
	if pc == nil {
		return errors.New("proxy port config is nil")
	}
	pc.ApplyDefaults()
	if pc.ID == "" {
		return errors.New("id is required")
	}
	if pc.Name == "" {
		return errors.New("name is required")
	}
	if pc.ListenAddr == "" {
		return errors.New("listen_addr is required")
	}
	_, portStr, err := net.SplitHostPort(pc.ListenAddr)
	if err != nil {
		return fmt.Errorf("invalid listen_addr: %w", err)
	}
	if portStr == "" {
		return errors.New("listen_addr port is required")
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("listen_addr port must be between 1 and 65535, got %s", portStr)
	}
	switch pc.Type {
	case ProxyPortTypeHTTP, ProxyPortTypeSocks5, ProxyPortTypeSocks4, ProxyPortTypeMixed:
	default:
		return fmt.Errorf("invalid type: %s", pc.Type)
	}
	if err := validateCIDRList(pc.AllowList); err != nil {
		return err
	}
	return nil
}

// IsDirectConnection returns true if no proxy outbound is configured.
func (pc *ProxyPortConfig) IsDirectConnection() bool {
	return pc.ProxyOutbound == "" || pc.ProxyOutbound == "direct"
}

// IsGroupSelection returns true if proxy_outbound is a group.
func (pc *ProxyPortConfig) IsGroupSelection() bool {
	return strings.HasPrefix(pc.ProxyOutbound, "@")
}

// IsMultiNodeSelection returns true if proxy_outbound contains multiple nodes.
func (pc *ProxyPortConfig) IsMultiNodeSelection() bool {
	if pc.ProxyOutbound == "" || pc.ProxyOutbound == "direct" {
		return false
	}
	if strings.HasPrefix(pc.ProxyOutbound, "@") {
		return false
	}
	return strings.Contains(pc.ProxyOutbound, ",")
}

// GetNodeList returns the node list for multi-node selection.
func (pc *ProxyPortConfig) GetNodeList() []string {
	if !pc.IsMultiNodeSelection() {
		return nil
	}
	nodes := strings.Split(pc.ProxyOutbound, ",")
	result := make([]string, 0, len(nodes))
	for _, node := range nodes {
		trimmed := strings.TrimSpace(node)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// GetGroupName returns group name without @.
func (pc *ProxyPortConfig) GetGroupName() string {
	if pc.IsGroupSelection() {
		return strings.TrimPrefix(pc.ProxyOutbound, "@")
	}
	return ""
}

// GetLoadBalance returns load balance strategy defaulting to least-latency.
func (pc *ProxyPortConfig) GetLoadBalance() string {
	if pc.LoadBalance == "" {
		return LoadBalanceLeastLatency
	}
	return pc.LoadBalance
}

// GetLoadBalanceSort returns sort type defaulting to tcp.
func (pc *ProxyPortConfig) GetLoadBalanceSort() string {
	if pc.LoadBalanceSort == "" {
		return LoadBalanceSortTCP
	}
	return pc.LoadBalanceSort
}

func validateCIDRList(list []string) error {
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if strings.Contains(entry, "/") {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return fmt.Errorf("invalid allow_list CIDR: %s", entry)
			}
			continue
		}
		if ip := net.ParseIP(entry); ip == nil {
			return fmt.Errorf("invalid allow_list IP: %s", entry)
		}
	}
	return nil
}
