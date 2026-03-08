package executor

import "github.com/alperen/opsfix/policy"

type ExecutionRequest struct {
	Tool       string
	ServerName string
	Params     map[string]any
	RequestID  string
	Confirmed  bool // true when user explicitly approved a risky action
}

type ExecutionResult struct {
	Output   string
	ExitCode int
	Approved bool
	Blocked  bool
	Risk     policy.RiskLevel
	AuditID  string
	// PendingApproval is set when the action requires user confirmation.
	// The message describes what will happen and how to confirm.
	PendingApproval string
}
