package ssh

import (
	"github.com/alperen/opsfix/adapter"
)

// AdapterExecutor wraps Executor to satisfy adapter.SSHExecutor interface.
type AdapterExecutor struct {
	exec *Executor
}

// NewAdapterExecutor creates an AdapterExecutor that satisfies adapter.SSHExecutor.
func NewAdapterExecutor(client Client, allowlist []string) *AdapterExecutor {
	return &AdapterExecutor{exec: NewExecutor(client, allowlist)}
}

func (a *AdapterExecutor) Run(cmd string, args ...string) (adapter.ExecResult, error) {
	res, err := a.exec.Run(cmd, args...)
	if err != nil {
		return adapter.ExecResult{}, err
	}
	return adapter.ExecResult{
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
		ExitCode: res.ExitCode,
	}, nil
}

func (a *AdapterExecutor) ReadFile(path string) ([]byte, error) {
	return a.exec.ReadFile(path)
}
