package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// Event represents an audited security action or policy change.
type Event struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`   // e.g. "admin", "system:engine", "system:auto_unblock"
	Action    string    `json:"action"`  // e.g. "FIREWALL_BLOCK", "FIREWALL_UNBLOCK", "CONFIG_CHANGE"
	Target    string    `json:"target"`  // e.g. "192.168.1.105", "SID-1000001"
	Status    string    `json:"status"`  // "CONFIRMED", "FAILED", "REQUESTED"
	Platform  string    `json:"platform"`
	Details   string    `json:"details"`
}

// Logger handles thread-safe persistent and in-memory audit logs.
type Logger struct {
	mu         sync.RWMutex
	filePath   string
	recentLogs []Event
	maxRecent  int
}

var (
	defaultLogger *Logger
	once          sync.Once
)

// Init initializes the global audit logger.
func Init(filePath string) *Logger {
	once.Do(func() {
		if filePath == "" {
			filePath = "audit.log"
		}
		defaultLogger = &Logger{
			filePath:   filePath,
			recentLogs: make([]Event, 0, 500),
			maxRecent:  500,
		}
	})
	return defaultLogger
}

// Get returns the default audit logger.
func Get() *Logger {
	if defaultLogger == nil {
		return Init("audit.log")
	}
	return defaultLogger
}

// Log records a new audit event.
func (l *Logger) Log(actor, action, target, status, platform, details string) Event {
	evt := Event{
		ID:        fmt.Sprintf("AUDIT-%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Actor:     actor,
		Action:    action,
		Target:    target,
		Status:    status,
		Platform:  platform,
		Details:   details,
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Append to recent memory buffer
	if len(l.recentLogs) >= l.maxRecent {
		l.recentLogs = l.recentLogs[1:]
	}
	l.recentLogs = append(l.recentLogs, evt)

	// Append to audit file
	f, err := os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		defer f.Close()
		bytes, _ := json.Marshal(evt)
		f.Write(bytes)
		f.WriteString("\n")
	}

	return evt
}

// Recent returns a copy of recent audit events.
func (l *Logger) Recent(limit int) []Event {
	l.mu.RLock()
	defer l.mu.RUnlock()

	total := len(l.recentLogs)
	if limit <= 0 || limit > total {
		limit = total
	}

	result := make([]Event, limit)
	start := total - limit
	copy(result, l.recentLogs[start:])
	return result
}
