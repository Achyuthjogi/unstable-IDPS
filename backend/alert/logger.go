package alert

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"idps-backend/state"
)

// Logger writes alerts to an SQLite database.
type Logger struct {
	db *sql.DB
	mu sync.Mutex
}

// NewLogger creates a new SQLite alert logger.
func NewLogger(dbPath string) (*Logger, error) {
	if dbPath == "" {
		dbPath = "alerts.db"
	}
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}

	// Create alerts table
	schema := `
	CREATE TABLE IF NOT EXISTS alerts (
		id TEXT PRIMARY KEY,
		timestamp DATETIME,
		rule_id TEXT,
		msg TEXT,
		classtype TEXT,
		severity TEXT,
		src_ip TEXT,
		dst_ip TEXT,
		action TEXT,
		confidence REAL
	);
	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp);
	CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &Logger{db: db}, nil
}

// Log writes an alert to the SQLite DB.
func (l *Logger) Log(a state.Alert) error {
	if l.db == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	ts := time.Unix(0, int64(a.Timestamp*1e9)).Format(time.RFC3339)

	_, err := l.db.Exec(`
		INSERT INTO alerts (id, timestamp, rule_id, msg, classtype, severity, src_ip, dst_ip, action, confidence)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, a.ID, ts, a.RuleID, a.Reason, a.AlertType, a.Severity, a.SourceIP, a.DestIP, a.Action, a.Confidence)
	
	return err
}

// Close closes the database connection.
func (l *Logger) Close() {
	if l.db != nil {
		l.db.Close()
	}
}

// GetDB returns the database handle for querying endpoints.
func (l *Logger) GetDB() *sql.DB {
	return l.db
}

// DeleteAlert removes an alert from the SQLite DB by its ID.
func (l *Logger) DeleteAlert(id string) error {
	if l.db == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	_, err := l.db.Exec("DELETE FROM alerts WHERE id = ?", id)
	return err
}
