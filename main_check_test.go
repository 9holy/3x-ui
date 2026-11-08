package main

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestSnapshotIncludesCommittedWALWithoutChangingSource(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source.db")
	db, err := sql.Open("sqlite3", source)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE sample (value TEXT); INSERT INTO sample VALUES ('committed in WAL')"); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	walBefore, err := os.ReadFile(source + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(dir, "snapshot.db")
	if err := snapshotDatabase(source, snapshot); err != nil {
		t.Fatal(err)
	}
	copyDB, err := sql.Open("sqlite3", snapshot)
	if err != nil {
		t.Fatal(err)
	}
	defer copyDB.Close()
	var value string
	if err := copyDB.QueryRow("SELECT value FROM sample").Scan(&value); err != nil || value != "committed in WAL" {
		t.Fatalf("snapshot lost committed WAL: value=%q err=%v", value, err)
	}
	after, _ := os.ReadFile(source)
	walAfter, _ := os.ReadFile(source + "-wal")
	if !bytes.Equal(before, after) || !bytes.Equal(walBefore, walAfter) {
		t.Fatal("preflight changed the production database or WAL")
	}
	if st, err := os.Stat(snapshot); err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("snapshot permissions: stat=%v err=%v", st, err)
	}
}

func TestSnapshotFreshInstallDoesNotCreateProductionDirectory(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "not-created", "x-ui.db")
	if err := snapshotDatabase(source, filepath.Join(dir, "check.db")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Dir(source)); !os.IsNotExist(err) {
		t.Fatalf("preflight created production directory: %v", err)
	}
}
