package alert

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"idps-backend/state"
)

// Logger writes alerts to a JSON file (Snort alert_json style).
type Logger struct {
	file *os.File
	mu   sync.Mutex
}

// NewLogger creates a new JSON alert logger.
func NewLogger(path string) (*Logger, error) {
	if path == "" {
		return &Logger{}, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &Logger{file: f}, nil
}

// Log writes an alert to the JSON log.
func (l *Logger) Log(a state.Alert) error {
	if l.file == nil {
		return nil // Disabled
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	record := map[string]interface{}{
		"timestamp": time.Unix(0, int64(a.Timestamp*1e9)).Format(time.RFC3339),
		"rule_id":   a.RuleID,
		"msg":       a.Reason,
		"classtype": a.AlertType,
		"severity":  a.Severity,
		"src_ip":    a.SourceIP,
		"dst_ip":    a.DestIP,
		"action":    a.Action,
	}

	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = l.file.Write(data)
	return err
}

// Close closes the log file.
func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}
