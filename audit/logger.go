package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/alperen/opsfix/config"
)

type Logger struct {
	mu      sync.Mutex
	file    *os.File
	enabled bool
}

func New(cfg config.AuditConfig) (*Logger, error) {
	if !cfg.Enabled {
		return &Logger{enabled: false}, nil
	}

	f, err := os.OpenFile(cfg.FilePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("audit: open log file %q: %w", cfg.FilePath, err)
	}

	return &Logger{file: f, enabled: true}, nil
}

func (l *Logger) Log(e Event) {
	if !l.enabled {
		return
	}

	line, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: marshal error: %v\n", err)
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	l.file.Write(line)
	l.file.Write([]byte("\n"))
}

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

// NewEvent creates an audit event with a generated ID and current timestamp.
func NewEvent(tool, server string, params map[string]any) Event {
	return Event{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Tool:      tool,
		Server:    server,
		Params:    params,
	}
}
