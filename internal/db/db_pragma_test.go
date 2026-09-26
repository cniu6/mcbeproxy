package db

import (
	"path/filepath"
	"testing"
)

// TestNewDatabaseAppliesPragmas guards against DSN parameters the driver
// silently ignores (the old mattn-style `_journal_mode=WAL` did nothing).
func TestNewDatabaseAppliesPragmas(t *testing.T) {
	d, err := NewDatabase(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.db.Close()
	want := map[string]string{"journal_mode": "wal", "synchronous": "1", "busy_timeout": "5000", "cache_size": "-8000"}
	for p, w := range want {
		var v string
		if err := d.db.QueryRow("PRAGMA " + p).Scan(&v); err != nil {
			t.Fatal(err)
		}
		if v != w {
			t.Errorf("PRAGMA %s = %s, want %s", p, v, w)
		}
	}
}
