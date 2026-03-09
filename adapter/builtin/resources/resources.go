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
