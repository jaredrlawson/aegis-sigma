package db

import (
	"database/sql"
	"sync"
	_ "modernc.org/sqlite"
)

var (
	writeMu sync.Mutex
)

// WriteLock acquires the global write mutex. All DB writes must call this.
func WriteLock() {
	writeMu.Lock()
}

// WriteUnlock releases the global write mutex.
func WriteUnlock() {
	writeMu.Unlock()
}

func Open(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000&_synchronous=NORMAL")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}
