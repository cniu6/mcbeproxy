package db

import "strings"

// NormalizeACLServerID maps global ACL scope to a stable empty string.
// SQLite UNIQUE(display_name_lower, server_id) does not treat NULL as equal,
// so global entries must never use NULL server_id.
func NormalizeACLServerID(serverID string) string {
	return strings.TrimSpace(serverID)
}

func normalizeACLServerID(serverID string) string {
	return NormalizeACLServerID(serverID)
}