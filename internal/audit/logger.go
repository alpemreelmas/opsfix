package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Logger struct {
	mu       sync.Mutex
	file     *os.File
	enabled  bool
	hmacKey  []byte
	prevHash string
}

type Event struct {
	ID         string         `json:"id"`
	Timestamp  time.Time      `json:"timestamp"`
	Tool       string         `json:"tool"`
	Server     string         `json:"server"`
	Adapter    string         `json:"adapter,omitempty"`
	Params     map[string]any `json:"params"`
	Decision   string         `json:"decision"`
	Risk       string         `json:"risk,omitempty"`
	Output     string         `json:"output,omitempty"`
	Error      string         `json:"error,omitempty"`
	DurationMs int64          `json:"duration_ms"`
	PrevHash   string         `json:"prev_hash,omitempty"`
	Hash       string         `json:"hash,omitempty"`
}

const (
	DecisionAllowed  = "allowed"
	DecisionBlocked  = "blocked"
	DecisionDenied   = "denied"
	DecisionApproved = "approved"
)

func New(filePath string, enabled bool) (*Logger, error) {
	if !enabled {
		return &Logger{enabled: false}, nil
	}

	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("audit: open log file %q: %w", filePath, err)
	}

	key := []byte(os.Getenv("OPSFIX_AUDIT_HMAC_KEY"))
	if len(key) == 0 {
		fmt.Fprintf(os.Stderr, "[opsfix] WARN: OPSFIX_AUDIT_HMAC_KEY not set; audit log will not be HMAC-protected\n")
	}

	return &Logger{file: f, enabled: true, hmacKey: key}, nil
}

func (l *Logger) Log(e Event) {
	if !l.enabled {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	e.PrevHash = l.prevHash

	// Compute hash of this entry (without Hash field set)
	if len(l.hmacKey) > 0 {
		entryJSON, _ := json.Marshal(e)
		mac := hmac.New(sha256.New, l.hmacKey)
		mac.Write(entryJSON)
		e.Hash = hex.EncodeToString(mac.Sum(nil))
		l.prevHash = e.Hash
	}

	line, err := json.Marshal(e)
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: marshal error: %v\n", err)
		return
	}

	if _, err := l.file.Write(line); err != nil {
		fmt.Fprintf(os.Stderr, "audit: write error: %v\n", err)
		return
	}
	l.file.Write([]byte("\n"))
}

func (l *Logger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

func NewEvent(tool, server string, params map[string]any) Event {
	return Event{
		ID:        fmt.Sprintf("%d", time.Now().UnixNano()),
		Timestamp: time.Now().UTC(),
		Tool:      tool,
		Server:    server,
		Params:    params,
	}
}
