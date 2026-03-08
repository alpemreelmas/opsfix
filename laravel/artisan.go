package laravel

import (
	"fmt"
	"strings"

	sshpkg "github.com/alperen/opsfix/ssh"
)

// RunArtisan runs an artisan command after validating it against the allowlist.
func RunArtisan(client sshpkg.Client, appPath, command string, allowlist []string) (ArtisanResult, error) {
	if strings.Contains(appPath, "..") || !strings.HasPrefix(appPath, "/") {
		return ArtisanResult{}, fmt.Errorf("artisan: invalid app path %q", appPath)
	}

	// Normalize command (trim spaces)
	command = strings.TrimSpace(command)

	if !isAllowed(command, allowlist) {
		return ArtisanResult{}, fmt.Errorf("artisan: command %q not in allowlist", command)
	}

	// Additional injection protection: command must not contain shell metacharacters
	if strings.ContainsAny(command, ";|&`$(){}\\\"'") {
		return ArtisanResult{}, fmt.Errorf("artisan: invalid characters in command %q", command)
	}

	cmd := fmt.Sprintf("cd %s && php artisan %s 2>&1", appPath, command)
	res, err := client.Exec(cmd)
	if err != nil {
		return ArtisanResult{}, fmt.Errorf("artisan: exec: %w", err)
	}

	return ArtisanResult{
		Command:  command,
		Output:   res.Stdout,
		ExitCode: res.ExitCode,
	}, nil
}

func isAllowed(command string, allowlist []string) bool {
	// Check exact match first
	for _, a := range allowlist {
		if a == command {
			return true
		}
	}
	// Check prefix match (e.g., "migrate:rollback --step=1")
	for _, a := range allowlist {
		if strings.HasPrefix(command, a+" ") {
			return true
		}
	}
	return false
}
