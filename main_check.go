package main

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"x-ui/database"
	"x-ui/web/service"
	"x-ui/xray"
)

// snapshotDatabase uses SQLite's own snapshot so committed WAL transactions
// are included. A plain copy of x-ui.db can silently omit those transactions.
// The source is read-only; all migrations and quota updates happen on the copy.
func snapshotDatabase(source, destination string) error {
	if _, err := os.Stat(source); os.IsNotExist(err) {
		return nil // Fresh installations validate a temporary, empty database.
	} else if err != nil {
		return err
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	u := url.URL{Scheme: "file", Path: abs}
	db, err := sql.Open("sqlite3", u.String()+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		return err
	}
	defer db.Close()
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	_, err = db.Exec("VACUUM INTO ?", destination)
	return err
}

func checkInstallation(source string) error {
	dir, err := os.MkdirTemp("", "xui-upgrade-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	snapshot := filepath.Join(dir, "x-ui.db")
	if err := snapshotDatabase(source, snapshot); err != nil {
		return fmt.Errorf("snapshot existing database: %w", err)
	}
	f, err := os.OpenFile(snapshot, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := database.InitDB(snapshot); err != nil {
		return fmt.Errorf("check database migration: %w", err)
	}
	defer database.CloseDB()
	// Exercise the same legacy-data migration as the real upgrade, on the copy.
	(&service.InboundService{}).MigrateDB()
	if err := (&service.InboundService{}).ValidateStoredProtocols(); err != nil {
		return err
	}
	conf, err := (&service.XrayService{}).GetXrayConfig()
	if err != nil {
		return err
	}
	return xray.ValidateConfig(conf)
}
