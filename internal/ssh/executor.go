package ssh

import (
	"fmt"
	"strings"
)

// allowedReadPrefixes are the path prefixes permitted for ReadFile.
var allowedReadPrefixes = []string{
	"/var/log/",
	"/srv/",
	"/etc/nginx/",
	"/etc/supervisor/",
	"/tmp/",
}

// Executor wraps a Client and enforces command allowlist + path allowlist.
type Executor struct {
	client    Client
	allowlist map[string]bool // permitted command binaries
}

// NewExecutor creates an Executor for the given client with a command allowlist.
// allowlist contains permitted command binaries e.g. ["systemctl", "journalctl"].
func NewExecutor(client Client, allowlist []string) *Executor {
	al := make(map[string]bool, len(allowlist))
	for _, cmd := range allowlist {
		al[cmd] = true
	}
	return &Executor{client: client, allowlist: al}
}

// Run executes cmd with args on the remote server.
// cmd must be in the allowlist. Args are passed separately — no shell string construction.
func (e *Executor) Run(cmd string, args ...string) (AdapterExecResult, error) {
	// Strip path prefix for allowlist check (e.g. /usr/bin/systemctl -> systemctl)
	binary := cmd
	if idx := strings.LastIndex(cmd, "/"); idx >= 0 {
		binary = cmd[idx+1:]
	}
	if !e.allowlist[binary] && !e.allowlist[cmd] {
		return AdapterExecResult{}, fmt.Errorf("security: command %q not in adapter allowlist", cmd)
	}

	// Build the exec string safely — args are shell-quoted individually
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellescape(cmd))
	for _, a := range args {
		parts = append(parts, shellescape(a))
	}
	execStr := strings.Join(parts, " ")

	res, err := e.client.Exec(execStr)
	if err != nil {
		return AdapterExecResult{}, err
	}
	return AdapterExecResult{
		Stdout:   res.Stdout,
		Stderr:   res.Stderr,
		ExitCode: res.ExitCode,
	}, nil
}

// ReadFile fetches a remote file. Path must start with an allowlisted prefix.
func (e *Executor) ReadFile(path string) ([]byte, error) {
	// Path traversal guard
	if strings.Contains(path, "..") {
		return nil, fmt.Errorf("security: path %q contains traversal sequence", path)
	}
	allowed := false
	for _, prefix := range allowedReadPrefixes {
		if strings.HasPrefix(path, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("security: path %q not in allowed read prefixes", path)
	}

	res, err := e.client.Exec("cat " + shellescape(path))
	if err != nil {
		return nil, err
	}
	return []byte(res.Stdout), nil
}

// shellescape returns a safely quoted version of s for use in SSH exec strings.
func shellescape(s string) string {
	if s == "" {
		return "''"
	}
	// Single-quote the string, escaping any single quotes within
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

// AdapterExecResult mirrors adapter.ExecResult to avoid circular imports.
type AdapterExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}
