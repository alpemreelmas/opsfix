package scanner

import (
	"fmt"
	"strings"

	sshpkg "github.com/alperen/opsfix/ssh"
)

func GetLogs(client sshpkg.Client, unit string, lines int) (string, error) {
	if strings.ContainsAny(unit, ";|&`$(){}") {
		return "", fmt.Errorf("get_logs: invalid unit name %q", unit)
	}
	if lines <= 0 || lines > 5000 {
		lines = 100
	}

	cmd := fmt.Sprintf("journalctl -u %s -n %d --no-pager --output=short-iso 2>/dev/null", unit, lines)
	res, err := client.Exec(cmd)
	if err != nil {
		return "", fmt.Errorf("get_logs %q: %w", unit, err)
	}

	if res.Stdout == "" && res.Stderr != "" {
		return "", fmt.Errorf("get_logs %q: %s", unit, strings.TrimSpace(res.Stderr))
	}

	return res.Stdout, nil
}

func GetFileLogs(client sshpkg.Client, path string, lines int) (string, error) {
	// Only allow paths under /var/log or /srv
	if !strings.HasPrefix(path, "/var/log/") && !strings.HasPrefix(path, "/srv/") {
		return "", fmt.Errorf("get_logs: path %q not in allowed directories", path)
	}
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("get_logs: path traversal not allowed")
	}
	if lines <= 0 || lines > 5000 {
		lines = 100
	}

	cmd := fmt.Sprintf("tail -n %d %s 2>/dev/null", lines, path)
	res, err := client.Exec(cmd)
	if err != nil {
		return "", fmt.Errorf("get_file_logs %q: %w", path, err)
	}

	return res.Stdout, nil
}
