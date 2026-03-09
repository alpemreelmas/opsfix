package systemd

import (
	"fmt"
	"strings"

	"github.com/alperen/opsfix/adapter"
)

func init() {
	adapter.Register(&SystemdAdapter{})
}

type SystemdAdapter struct{}

func (a *SystemdAdapter) ID() string            { return "systemd" }
func (a *SystemdAdapter) InterfaceVersion() int { return adapter.InterfaceVersion }

func (a *SystemdAdapter) Tools() []adapter.ToolDefinition {
	return []adapter.ToolDefinition{
		{
			Name:        "service_status",
			Description: "Get status of a systemd service",
			ReadOnly:    true,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server":  map[string]any{"type": "string", "description": "Target server name"},
					"service": map[string]any{"type": "string", "description": "Service name"},
				},
				"required": []string{"server", "service"},
			},
		},
		{
			Name:        "service_list",
			Description: "List all active systemd services",
			ReadOnly:    true,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server": map[string]any{"type": "string"},
				},
				"required": []string{"server"},
			},
		},
		{
			Name:        "service_restart",
			Description: "Restart a systemd service",
			ReadOnly:    false,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server":  map[string]any{"type": "string"},
					"service": map[string]any{"type": "string"},
				},
				"required": []string{"server", "service"},
			},
		},
		{
			Name:        "service_logs",
			Description: "Get recent logs for a systemd service via journalctl",
			ReadOnly:    true,
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"server":  map[string]any{"type": "string"},
					"service": map[string]any{"type": "string"},
					"lines":   map[string]any{"type": "integer", "default": 100},
				},
				"required": []string{"server", "service"},
			},
		},
	}
}

func (a *SystemdAdapter) DefaultPolicyRules() []adapter.PolicyRule {
	return []adapter.PolicyRule{
		{Name: "systemd-status-low", Tool: "service_status", Risk: "low"},
		{Name: "systemd-list-low", Tool: "service_list", Risk: "low"},
		{Name: "systemd-logs-low", Tool: "service_logs", Risk: "low"},
		{Name: "systemd-restart-medium", Tool: "service_restart", Risk: "medium"},
	}
}

func (a *SystemdAdapter) Execute(tool string, params adapter.Params, exec adapter.SSHExecutor) (adapter.Result, error) {
	switch tool {
	case "service_status":
		svc := strParam(params, "service")
		if svc == "" {
			return adapter.Result{}, fmt.Errorf("service_status: 'service' required")
		}
		res, err := exec.Run("systemctl", "status", svc, "--no-pager")
		if err != nil {
			return adapter.Result{}, err
		}
		return adapter.Result{Output: res.Stdout + res.Stderr, ExitCode: res.ExitCode}, nil

	case "service_list":
		res, err := exec.Run("systemctl", "list-units", "--type=service", "--state=active", "--no-pager", "--plain")
		if err != nil {
			return adapter.Result{}, err
		}
		return adapter.Result{Output: res.Stdout, ExitCode: res.ExitCode}, nil

	case "service_restart":
		svc := strParam(params, "service")
		if svc == "" {
			return adapter.Result{}, fmt.Errorf("service_restart: 'service' required")
		}
		res, err := exec.Run("sudo", "systemctl", "restart", svc)
		if err != nil {
			return adapter.Result{}, err
		}
		return adapter.Result{Output: res.Stdout + res.Stderr, ExitCode: res.ExitCode}, nil

	case "service_logs":
		svc := strParam(params, "service")
		if svc == "" {
			return adapter.Result{}, fmt.Errorf("service_logs: 'service' required")
		}
		lines := "100"
		if n, ok := params["lines"]; ok {
			lines = fmt.Sprintf("%v", n)
		}
		res, err := exec.Run("journalctl", "-u", svc, "-n", lines, "--no-pager")
		if err != nil {
			return adapter.Result{}, err
		}
		return adapter.Result{Output: res.Stdout + res.Stderr, ExitCode: res.ExitCode}, nil

	default:
		return adapter.Result{}, fmt.Errorf("systemd adapter: unknown tool %q", tool)
	}
}

func (a *SystemdAdapter) PreFlight(tool string, params adapter.Params, exec adapter.SSHExecutor) (adapter.PreFlightReport, error) {
	report := adapter.PreFlightReport{CurrentState: map[string]any{}}

	switch tool {
	case "service_restart":
		svc := strParam(params, "service")
		if svc == "" {
			report.Blocker = "service_restart: 'service' required"
			return report, nil
		}
		res, err := exec.Run("systemctl", "is-active", svc)
		if err == nil {
			report.CurrentState["service_status"] = strings.TrimSpace(res.Stdout)
		}
		report.Plan = []string{fmt.Sprintf("systemctl restart %s", svc)}
	}

	return report, nil
}

func (a *SystemdAdapter) Verify(tool string, params adapter.Params, result adapter.Result, exec adapter.SSHExecutor) (adapter.VerifyReport, error) {
	switch tool {
	case "service_restart":
		svc := strParam(params, "service")
		res, err := exec.Run("systemctl", "is-active", svc)
		if err != nil || strings.TrimSpace(res.Stdout) != "active" {
			status := ""
			if res.Stdout != "" {
				status = strings.TrimSpace(res.Stdout)
			}
			return adapter.VerifyReport{
				Success: false,
				Error:   fmt.Sprintf("service %q is not active after restart: %s", svc, status),
			}, nil
		}
		return adapter.VerifyReport{
			Success:  true,
			NewState: map[string]any{"service_status": "active"},
		}, nil
	}
	return adapter.VerifyReport{Success: true}, nil
}

func (a *SystemdAdapter) Probe(exec adapter.SSHExecutor) adapter.CapabilitySet {
	caps := adapter.CapabilitySet{
		AdapterID:   a.ID(),
		Available:   map[string]string{},
		Fallbacks:   map[string]string{},
	}
	for _, bin := range []string{"systemctl", "journalctl"} {
		res, err := exec.Run("which", bin)
		if err == nil && res.ExitCode == 0 {
			caps.Available[bin] = strings.TrimSpace(res.Stdout)
		} else {
			caps.Unavailable = append(caps.Unavailable, bin)
		}
	}
	return caps
}

func strParam(params adapter.Params, key string) string {
	if v, ok := params[key]; ok {
		return strings.TrimSpace(fmt.Sprintf("%v", v))
	}
	return ""
}
