package audit

import "time"

type Decision string

const (
	DecisionAllowed  Decision = "allowed"
	DecisionBlocked  Decision = "blocked"
	DecisionApproved Decision = "approved"
	DecisionDenied   Decision = "denied"
)

type Event struct {
	ID         string         `json:"id"`
	Timestamp  time.Time      `json:"timestamp"`
	Tool       string         `json:"tool"`
	Server     string         `json:"server"`
	Params     map[string]any `json:"params"`
	Decision   Decision       `json:"decision"`
	Risk       string         `json:"risk"`
	Output     string         `json:"output,omitempty"`
	Error      string         `json:"error,omitempty"`
	DurationMs int64          `json:"duration_ms"`
}
