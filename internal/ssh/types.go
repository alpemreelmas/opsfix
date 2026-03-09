package ssh

import "time"

type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	Duration time.Duration
}

type Client interface {
	Exec(cmd string) (ExecResult, error)
	Close() error
}
