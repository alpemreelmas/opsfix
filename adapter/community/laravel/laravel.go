package laravel

import (
	"fmt"
	"strings"

	"github.com/alperen/opsfix/adapter"
)

func init() {
	adapter.Register(&LaravelAdapter{})
}

// allowedArtisanCommands is the explicit allowlist for artisan commands.
var allowedArtisanCommands = map[string]bool{
	"cache:clear":    true,
	"config:cache":   true,
	"config:clear":   true,
	"route:cache":    true,
	"route:clear":    true,
	"view:cache":     true,
	"view:clear":     true,
	"optimize":       true,
	"optimize:clear": true,
	"queue:restart":  true,
	"storage:link":   true,
	"migrate":        true,
	"migrate:status": true,
	"about":          true,
}

type LaravelAdapter struct{}

func (a *LaravelAdapter) ID() string            { return "laravel" }
func (a *LaravelAdapter) InterfaceVersion() int { return adapter.InterfaceVersion }

func (a *LaravelAdapter) Tools() []adapter.ToolDefinition {
	return []adapter.ToolDefinition{
		{
			Name:        "laravel_health",
			Description: "Check Laravel application health (storage, env, cache)",
			ReadOnly:    true,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server":   map[string]any{"type": "string"},
					"app_path": map[string]any{"type": "string", "description": "Absolute path to Laravel root"},
				},
				"required": []string{"server", "app_path"},
			},
		},
		{
			Name:        "laravel_artisan",
			Description: "Run an allowed artisan command",
			ReadOnly:    false,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server":   map[string]any{"type": "string"},
					"app_path": map[string]any{"type": "string"},
					"command":  map[string]any{"type": "string", "description": "Artisan command (e.g. cache:clear)"},
				},
				"required": []string{"server", "app_path", "command"},
			},
		},
		{
			Name:        "laravel_deploy",
			Description: "Deploy Laravel app: git pull, composer install, artisan optimize",
			ReadOnly:    false,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server":   map[string]any{"type": "string"},
					"app_path": map[string]any{"type": "string"},
					"branch":   map[string]any{"type": "string", "default": "main"},
				},
				"required": []string{"server", "app_path"},
			},
		},
		{
			Name:        "laravel_queue_restart",
			Description: "Restart Laravel queue workers via supervisorctl",
			ReadOnly:    false,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server": map[string]any{"type": "string"},
					"worker": map[string]any{"type": "string", "description": "Worker name or 'all'", "default": "all"},
				},
				"required": []string{"server"},
			},
		},
	}
}

func (a *LaravelAdapter) DefaultPolicyRules() []adapter.PolicyRule {
	return []adapter.PolicyRule{
		{Name: "laravel-health-low", Tool: "laravel_health", Risk: "low"},
		{Name: "laravel-artisan-medium", Tool: "laravel_artisan", Risk: "medium"},
		{Name: "laravel-deploy-high", Tool: "laravel_deploy", Risk: "high"},
		{Name: "laravel-queue-restart-medium", Tool: "laravel_queue_restart", Risk: "medium"},
		// Block dangerous artisan commands
		{
			Name:  "laravel-block-db-wipe",
			Tool:  "laravel_artisan",
			Block: true,
			Conditions: []adapter.PolicyCondition{
				{Field: "command", Matches: `^(migrate:fresh|db:wipe|migrate:reset)`},
			},
		},
	}
}

func (a *LaravelAdapter) Execute(tool string, params adapter.Params, exec adapter.SSHExecutor) (adapter.Result, error) {
	switch tool {
	case "laravel_health":
		return a.health(params, exec)
	case "laravel_artisan":
		return a.artisan(params, exec)
	case "laravel_deploy":
		return a.deploy(params, exec)
	case "laravel_queue_restart":
		return a.queueRestart(params, exec)
	default:
		return adapter.Result{}, fmt.Errorf("laravel adapter: unknown tool %q", tool)
	}
}

func (a *LaravelAdapter) PreFlight(tool string, params adapter.Params, exec adapter.SSHExecutor) (adapter.PreFlightReport, error) {
	report := adapter.PreFlightReport{
		CurrentState: map[string]any{},
		RollbackInfo: map[string]any{},
	}

	switch tool {
	case "laravel_deploy":
		appPath := strParam(params, "app_path")
		branch := strParam(params, "branch")
		if branch == "" {
			branch = "main"
		}

		// Get current git SHA for rollback
		res, err := exec.Run("git", "-C", appPath, "rev-parse", "--short", "HEAD")
		if err == nil && res.ExitCode == 0 {
			sha := strings.TrimSpace(res.Stdout)
			report.CurrentState["git_sha"] = sha
			report.RollbackInfo["git_sha"] = sha
			report.RollbackInfo["app_path"] = appPath
		}

		// Check disk free (df -BG on app path, parse available column)
		res, err = exec.Run("df", "-BG", appPath)
		if err == nil {
			lines := strings.Split(res.Stdout, "\n")
			if len(lines) > 1 {
				fields := strings.Fields(lines[1])
				if len(fields) >= 4 {
					avail := strings.TrimSuffix(fields[3], "G")
					report.CurrentState["disk_free_gb"] = avail
					if n := parseGB(avail); n > 0 && n < 3 {
						report.Warnings = append(report.Warnings, fmt.Sprintf("low disk space: %sGB free", avail))
					}
				}
			}
		}

		report.Plan = []string{
			fmt.Sprintf("git -C %s pull origin %s", appPath, branch),
			fmt.Sprintf("composer install --no-interaction --no-dev --optimize-autoloader -d %s", appPath),
			fmt.Sprintf("php %s/artisan optimize", appPath),
			fmt.Sprintf("php %s/artisan migrate --force", appPath),
		}

	case "laravel_artisan":
		command := strParam(params, "command")
		appPath := strParam(params, "app_path")
		report.Plan = []string{fmt.Sprintf("php %s/artisan %s", appPath, command)}

	case "laravel_queue_restart":
		worker := strParam(params, "worker")
		if worker == "" {
			worker = "all"
		}
		report.Plan = []string{fmt.Sprintf("supervisorctl restart %s", worker)}
	}

	return report, nil
}

func (a *LaravelAdapter) Verify(tool string, params adapter.Params, result adapter.Result, exec adapter.SSHExecutor) (adapter.VerifyReport, error) {
	switch tool {
	case "laravel_deploy":
		appPath := strParam(params, "app_path")

		// Check artisan can run
		res, err := exec.Run("php", appPath+"/artisan", "--version")
		if err != nil || res.ExitCode != 0 {
			return adapter.VerifyReport{
				Success: false,
				Error:   fmt.Sprintf("post-deploy health check failed: artisan not responding: %v", err),
			}, nil
		}

		// Get new git SHA
		newSHA := ""
		if res2, err2 := exec.Run("git", "-C", appPath, "rev-parse", "--short", "HEAD"); err2 == nil {
			newSHA = strings.TrimSpace(res2.Stdout)
		}

		return adapter.VerifyReport{
			Success:  true,
			NewState: map[string]any{"git_sha": newSHA, "artisan": strings.TrimSpace(res.Stdout)},
		}, nil

	case "laravel_artisan":
		if result.ExitCode != 0 {
			return adapter.VerifyReport{
				Success: false,
				Error:   fmt.Sprintf("artisan exited with code %d", result.ExitCode),
			}, nil
		}
		return adapter.VerifyReport{Success: true}, nil
	}

	return adapter.VerifyReport{Success: true}, nil
}

func (a *LaravelAdapter) Probe(exec adapter.SSHExecutor) adapter.CapabilitySet {
	caps := adapter.CapabilitySet{
		AdapterID: a.ID(),
		Available: map[string]string{},
		Fallbacks: map[string]string{},
	}
	candidates := map[string][]string{
		"php":           {"php8.3", "php8.2", "php8.1", "php"},
		"composer":      {"composer", "composer2"},
		"supervisorctl": {"supervisorctl"},
		"git":           {"git"},
	}
	for logical, variants := range candidates {
		for _, bin := range variants {
			res, err := exec.Run("which", bin)
			if err == nil && res.ExitCode == 0 {
				caps.Available[logical] = strings.TrimSpace(res.Stdout)
				if bin != logical {
					caps.Fallbacks[logical] = bin
				}
				break
			}
		}
		if _, found := caps.Available[logical]; !found {
			caps.Unavailable = append(caps.Unavailable, logical)
		}
	}
	return caps
}

func (a *LaravelAdapter) health(params adapter.Params, exec adapter.SSHExecutor) (adapter.Result, error) {
	appPath := strParam(params, "app_path")
	if err := validatePath(appPath); err != nil {
		return adapter.Result{}, err
	}

	var sb strings.Builder

	// Check storage writability
	res, err := exec.Run("test", "-w", appPath+"/storage")
	if err == nil {
		if res.ExitCode == 0 {
			sb.WriteString("storage: writable\n")
		} else {
			sb.WriteString("storage: NOT writable\n")
		}
	}

	// Check artisan can run
	res, err = exec.Run("php", appPath+"/artisan", "--version")
	if err == nil {
		sb.WriteString(fmt.Sprintf("artisan: %s\n", strings.TrimSpace(res.Stdout)))
	}

	return adapter.Result{Output: sb.String(), ExitCode: 0}, nil
}

func (a *LaravelAdapter) artisan(params adapter.Params, exec adapter.SSHExecutor) (adapter.Result, error) {
	appPath := strParam(params, "app_path")
	command := strParam(params, "command")

	if err := validatePath(appPath); err != nil {
		return adapter.Result{}, err
	}

	if command == "" {
		return adapter.Result{}, fmt.Errorf("laravel_artisan: 'command' required")
	}

	// Allowlist check on base command
	fields := strings.Fields(command)
	baseCmd := fields[0]
	if !allowedArtisanCommands[baseCmd] {
		return adapter.Result{}, fmt.Errorf("laravel_artisan: command %q not in allowlist", baseCmd)
	}

	// Build args: php <appPath>/artisan <command-parts...>
	artisanArgs := append([]string{appPath + "/artisan"}, fields...)
	res, err := exec.Run("php", artisanArgs...)
	if err != nil {
		return adapter.Result{}, err
	}

	return adapter.Result{Output: res.Stdout + res.Stderr, ExitCode: res.ExitCode}, nil
}

func (a *LaravelAdapter) deploy(params adapter.Params, exec adapter.SSHExecutor) (adapter.Result, error) {
	appPath := strParam(params, "app_path")
	branch := strParam(params, "branch")
	if branch == "" {
		branch = "main"
	}
	if err := validatePath(appPath); err != nil {
		return adapter.Result{}, err
	}

	var sb strings.Builder
	steps := []struct {
		name string
		cmd  string
		args []string
	}{
		{"git pull", "git", []string{"-C", appPath, "pull", "origin", branch}},
		{"composer install", "composer", []string{"install", "--no-interaction", "--no-dev", "--optimize-autoloader", "-d", appPath}},
		{"artisan optimize", "php", []string{appPath + "/artisan", "optimize"}},
		{"artisan migrate", "php", []string{appPath + "/artisan", "migrate", "--force"}},
	}

	for _, step := range steps {
		res, err := exec.Run(step.cmd, step.args...)
		if err != nil {
			return adapter.Result{Output: sb.String(), ExitCode: 1}, fmt.Errorf("deploy failed at %q: %w", step.name, err)
		}
		sb.WriteString(fmt.Sprintf("=== %s ===\n%s\n", step.name, res.Stdout+res.Stderr))
		if res.ExitCode != 0 {
			return adapter.Result{Output: sb.String(), ExitCode: res.ExitCode},
				fmt.Errorf("deploy step %q failed (exit %d): %s", step.name, res.ExitCode, res.Stderr)
		}
	}

	return adapter.Result{Output: sb.String(), ExitCode: 0}, nil
}

func (a *LaravelAdapter) queueRestart(params adapter.Params, exec adapter.SSHExecutor) (adapter.Result, error) {
	worker := strParam(params, "worker")
	if worker == "" {
		worker = "all"
	}
	res, err := exec.Run("supervisorctl", "restart", worker)
	if err != nil {
		return adapter.Result{}, err
	}
	return adapter.Result{Output: res.Stdout + res.Stderr, ExitCode: res.ExitCode}, nil
}

func validatePath(path string) error {
	if path == "" {
		return fmt.Errorf("app_path is required")
	}
	if strings.Contains(path, "..") || !strings.HasPrefix(path, "/") {
		return fmt.Errorf("invalid app_path %q: must be absolute, no traversal", path)
	}
	return nil
}

func strParam(params adapter.Params, key string) string {
	if v, ok := params[key]; ok {
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
	return ""
}

// parseGB parses an integer from a string like "5" or "5G".
func parseGB(s string) int {
	s = strings.TrimSuffix(strings.TrimSpace(s), "G")
	n := 0
	fmt.Sscanf(s, "%d", &n)
	return n
}
