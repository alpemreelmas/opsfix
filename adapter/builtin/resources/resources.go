package resources

import (
	"fmt"
	"strings"

	"github.com/alperen/opsfix/adapter"
)

func init() {
	adapter.Register(&ResourcesAdapter{})
}

type ResourcesAdapter struct{}

func (a *ResourcesAdapter) ID() string            { return "resources" }
func (a *ResourcesAdapter) InterfaceVersion() int { return adapter.InterfaceVersion }

func (a *ResourcesAdapter) Tools() []adapter.ToolDefinition {
	return []adapter.ToolDefinition{
		{Name: "disk_usage", Description: "Get disk usage", ReadOnly: true, InputSchema: serverSchema()},
		{Name: "memory_usage", Description: "Get memory usage", ReadOnly: true, InputSchema: serverSchema()},
		{Name: "cpu_usage", Description: "Get CPU load", ReadOnly: true, InputSchema: serverSchema()},
	}
}

func serverSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"server": map[string]any{"type": "string"},
		},
		"required": []string{"server"},
	}
}

func (a *ResourcesAdapter) DefaultPolicyRules() []adapter.PolicyRule {
	return []adapter.PolicyRule{
		{Name: "resources-read-low", Tool: "disk_usage", Risk: "low"},
		{Name: "resources-mem-low", Tool: "memory_usage", Risk: "low"},
		{Name: "resources-cpu-low", Tool: "cpu_usage", Risk: "low"},
	}
}

func (a *ResourcesAdapter) Execute(tool string, params adapter.Params, exec adapter.SSHExecutor) (adapter.Result, error) {
	switch tool {
	case "disk_usage":
		res, err := exec.Run("df", "-h")
		if err != nil {
			return adapter.Result{}, err
		}
		return adapter.Result{Output: res.Stdout, ExitCode: res.ExitCode}, nil

	case "memory_usage":
		res, err := exec.Run("free", "-h")
		if err != nil {
			return adapter.Result{}, err
		}
		return adapter.Result{Output: res.Stdout, ExitCode: res.ExitCode}, nil

	case "cpu_usage":
		res, err := exec.Run("uptime")
		if err != nil {
			return adapter.Result{}, err
		}
		return adapter.Result{Output: strings.TrimSpace(res.Stdout), ExitCode: res.ExitCode}, nil

	default:
		return adapter.Result{}, fmt.Errorf("resources adapter: unknown tool %q", tool)
	}
}

// PreFlight is a no-op for read-only tools.
func (a *ResourcesAdapter) PreFlight(tool string, params adapter.Params, exec adapter.SSHExecutor) (adapter.PreFlightReport, error) {
	return adapter.PreFlightReport{}, nil
}

// Verify is a no-op for read-only tools.
func (a *ResourcesAdapter) Verify(tool string, params adapter.Params, result adapter.Result, exec adapter.SSHExecutor) (adapter.VerifyReport, error) {
	return adapter.VerifyReport{Success: true}, nil
}

func (a *ResourcesAdapter) Probe(exec adapter.SSHExecutor) adapter.CapabilitySet {
	caps := adapter.CapabilitySet{
		AdapterID: a.ID(),
		Available: map[string]string{},
		Fallbacks: map[string]string{},
	}
	for _, bin := range []string{"df", "free", "uptime"} {
		res, err := exec.Run("which", bin)
		if err == nil && res.ExitCode == 0 {
			caps.Available[bin] = strings.TrimSpace(res.Stdout)
		} else {
			caps.Unavailable = append(caps.Unavailable, bin)
		}
	}
	return caps
}
