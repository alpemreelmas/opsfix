package executor

import (
	"fmt"
	"strings"
)

// buildRestartService returns the systemctl restart command for a service.
func buildRestartService(service string) (string, error) {
	if err := validateIdentifier(service); err != nil {
		return "", fmt.Errorf("restart_service: %w", err)
	}
	return fmt.Sprintf("systemctl restart %s", service), nil
}

// buildQueueRestart returns the supervisorctl restart command.
func buildQueueRestart(worker string) (string, error) {
	if err := validateIdentifier(worker); err != nil {
		return "", fmt.Errorf("queue_restart: %w", err)
	}
	return fmt.Sprintf("supervisorctl restart %s", worker), nil
}

// buildDeploy returns the deploy sequence for a Laravel app.
func buildDeploy(appPath, branch string) ([]string, error) {
	if strings.Contains(appPath, "..") || !strings.HasPrefix(appPath, "/") {
		return nil, fmt.Errorf("deploy: invalid app path %q", appPath)
	}
	if err := validateIdentifier(branch); err != nil {
		return nil, fmt.Errorf("deploy: invalid branch: %w", err)
	}

	return []string{
		fmt.Sprintf("cd %s && git fetch origin", appPath),
		fmt.Sprintf("cd %s && git checkout %s", appPath, branch),
		fmt.Sprintf("cd %s && git pull origin %s", appPath, branch),
		fmt.Sprintf("cd %s && composer install --no-dev --no-interaction --optimize-autoloader 2>&1", appPath),
		fmt.Sprintf("cd %s && php artisan config:cache 2>&1", appPath),
		fmt.Sprintf("cd %s && php artisan route:cache 2>&1", appPath),
		fmt.Sprintf("cd %s && php artisan view:cache 2>&1", appPath),
		fmt.Sprintf("cd %s && php artisan migrate --force 2>&1", appPath),
	}, nil
}

// validateIdentifier rejects strings containing shell metacharacters.
func validateIdentifier(s string) error {
	if s == "" {
		return fmt.Errorf("empty identifier")
	}
	if strings.ContainsAny(s, ";|&`$(){}\\\"' \t\n\r") {
		return fmt.Errorf("invalid characters in %q", s)
	}
	return nil
}
