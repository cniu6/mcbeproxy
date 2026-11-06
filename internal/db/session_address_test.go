package db

import (
	"path/filepath"
	"testing"
	"time"

	"mcpeserverproxy/internal/session"
)

func TestHistoricalSessionMappedAddressRead(t *testing.T) {
	database, err := NewDatabase(filepath.Join(t.TempDir(), "history.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err = database.Initialize(); err != nil {
		t.Fatal(err)
	}
	repo := NewSessionRepository(database, 100)
	record := &session.SessionRecord{ID: "legacy", ClientAddr: "14.19.48.240:12123", ServerID: "fixture", StartTime: time.Now(), EndTime: time.Now(), Status: "idle"}
	if err = repo.Create(record); err != nil {
		t.Fatal(err)
	}
	// 绕过新写入边界，模拟磁盘上已有的旧版映射表示；只在临时测试库执行。
	if _, err = database.DB().Exec("UPDATE sessions SET client_addr = ? WHERE id = ?", "[::ffff:14.19.48.240]:12123", record.ID); err != nil {
		t.Fatal(err)
	}
	single, err := repo.GetByID(record.ID)
	if err != nil {
		t.Fatal(err)
	}
	list, err := repo.List(10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if single.ClientAddr != "14.19.48.240:12123" || len(list) != 1 || list[0].ClientAddr != single.ClientAddr {
		t.Fatalf("旧历史地址未统一: single=%+v list=%+v", single, list)
	}
	var stored string
	if err = database.DB().QueryRow("SELECT client_addr FROM sessions WHERE id = ?", record.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != "[::ffff:14.19.48.240]:12123" {
		t.Fatal("读取旧历史不应重写数据库")
	}
}
