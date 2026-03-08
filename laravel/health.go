package laravel

import (
	"fmt"
	"strings"

	sshpkg "github.com/alperen/opsfix/ssh"
)

// CheckHealth performs read-only health checks for a Laravel application.
// appPath is the absolute path to the Laravel root (e.g., /var/www/myapp).
func CheckHealth(client sshpkg.Client, appPath string) (HealthStatus, error) {
	if strings.Contains(appPath, "..") || !strings.HasPrefix(appPath, "/") {
		return HealthStatus{}, fmt.Errorf("laravel health: invalid app path %q", appPath)
	}

	status := HealthStatus{}

	// Check storage writability
	res, err := client.Exec(fmt.Sprintf("test -w %s/storage && echo ok || echo fail", appPath))
	if err == nil {
		status.StorageOK = strings.TrimSpace(res.Stdout) == "ok"
	}

	// Get env info via artisan
	res, err = client.Exec(fmt.Sprintf("cd %s && php artisan about --json 2>/dev/null", appPath))
	if err == nil && res.ExitCode == 0 {
		output := res.Stdout
		// Parse key fields from plain text since --json may not be available in all versions
		for _, line := range strings.Split(output, "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "environment") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					status.AppEnv = parts[len(parts)-1]
				}
			}
			if strings.Contains(lower, "debug") {
				status.AppDebug = strings.Contains(lower, "true") || strings.Contains(lower, "enabled")
			}
			if strings.Contains(lower, "laravel version") || strings.Contains(lower, "version") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					status.LaravelVersion = parts[len(parts)-1]
				}
			}
		}
	}

	// Check cache
	res, err = client.Exec(fmt.Sprintf("cd %s && php artisan cache:clear --quiet 2>&1 && echo ok || echo fail", appPath))
	if err == nil {
		status.CacheOK = strings.TrimSpace(res.Stdout) == "ok"
	}

	// Check queue via supervisorctl
	res, err = client.Exec("supervisorctl status 2>/dev/null | grep -c RUNNING || true")
	if err == nil {
		status.QueueOK = strings.TrimSpace(res.Stdout) != "0"
	}

	return status, nil
}
