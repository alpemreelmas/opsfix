package mcpserver

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/alperen/opsfix/executor"
	"github.com/alperen/opsfix/laravel"
	"github.com/alperen/opsfix/scanner"
	sshpkg "github.com/alperen/opsfix/ssh"
)

type Dispatcher struct {
	scanner  *scanner.Scanner
	executor *executor.Executor
	pool     *sshpkg.Pool
}

func NewDispatcher(sc *scanner.Scanner, ex *executor.Executor, pool *sshpkg.Pool) *Dispatcher {
	return &Dispatcher{scanner: sc, executor: ex, pool: pool}
}

func (d *Dispatcher) Dispatch(params ToolCallParams) ToolResult {
	result, err := d.dispatch(params)
	if err != nil {
		return errorResult(err.Error())
	}
	return textResult(result)
}

func (d *Dispatcher) dispatch(params ToolCallParams) (string, error) {
	args := params.Arguments
	server := strArg(args, "server")

	switch params.Name {
	// ---- Read-only tools ----

	case "scan_server":
		if server == "" {
			return "", fmt.Errorf("scan_server: 'server' is required")
		}
		return d.scanner.ScanServer(server)

	case "list_services":
		if server == "" {
			return "", fmt.Errorf("list_services: 'server' is required")
		}
		client, err := d.pool.Get(server)
		if err != nil {
			return "", err
		}
		svcs, err := scanner.ListServices(client)
		if err != nil {
			return "", err
		}
		return marshalJSON(svcs)

	case "service_status":
		if server == "" {
			return "", fmt.Errorf("service_status: 'server' is required")
		}
		svc := strArg(args, "service")
		if svc == "" {
			return "", fmt.Errorf("service_status: 'service' is required")
		}
		client, err := d.pool.Get(server)
		if err != nil {
			return "", err
		}
		info, err := scanner.ServiceStatus(client, svc)
		if err != nil {
			return "", err
		}
		return marshalJSON(info)

	case "get_logs":
		if server == "" {
			return "", fmt.Errorf("get_logs: 'server' is required")
		}
		unit := strArg(args, "unit")
		if unit == "" {
			return "", fmt.Errorf("get_logs: 'unit' is required")
		}
		lines := intArg(args, "lines", 100)
		client, err := d.pool.Get(server)
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(unit, "/") {
			return scanner.GetFileLogs(client, unit, lines)
		}
		return scanner.GetLogs(client, unit, lines)

	case "disk_usage":
		if server == "" {
			return "", fmt.Errorf("disk_usage: 'server' is required")
		}
		client, err := d.pool.Get(server)
		if err != nil {
			return "", err
		}
		entries, err := scanner.DiskUsage(client)
		if err != nil {
			return "", err
		}
		return marshalJSON(entries)

	case "memory_usage":
		if server == "" {
			return "", fmt.Errorf("memory_usage: 'server' is required")
		}
		client, err := d.pool.Get(server)
		if err != nil {
			return "", err
		}
		info, err := scanner.MemoryUsage(client)
		if err != nil {
			return "", err
		}
		return marshalJSON(info)

	case "cpu_usage":
		if server == "" {
			return "", fmt.Errorf("cpu_usage: 'server' is required")
		}
		client, err := d.pool.Get(server)
		if err != nil {
			return "", err
		}
		info, err := scanner.CPUUsage(client)
		if err != nil {
			return "", err
		}
		return marshalJSON(info)

	case "queue_status":
		if server == "" {
			return "", fmt.Errorf("queue_status: 'server' is required")
		}
		client, err := d.pool.Get(server)
		if err != nil {
			return "", err
		}
		workers, err := scanner.QueueStatus(client)
		if err != nil {
			return "", err
		}
		return marshalJSON(workers)

	case "check_laravel_health":
		if server == "" {
			return "", fmt.Errorf("check_laravel_health: 'server' is required")
		}
		appPath := strArg(args, "app_path")
		if appPath == "" {
			return "", fmt.Errorf("check_laravel_health: 'app_path' is required")
		}
		client, err := d.pool.Get(server)
		if err != nil {
			return "", err
		}
		status, err := laravel.CheckHealth(client, appPath)
		if err != nil {
			return "", err
		}
		return marshalJSON(status)

	// ---- Execution tools ----

	case "restart_service", "queue_restart", "deploy_service", "run_artisan":
		if server == "" {
			return "", fmt.Errorf("%s: 'server' is required", params.Name)
		}
		req := executor.ExecutionRequest{
			Tool:       params.Name,
			ServerName: server,
			Params:     args,
			Confirmed:  boolArg(args, "confirmed"),
		}
		result, err := d.executor.Execute(req)
		if err != nil {
			return "", err
		}
		if result.PendingApproval != "" {
			return result.PendingApproval, nil
		}
		if result.Blocked {
			return "", fmt.Errorf("action blocked by policy (risk: %s)", result.Risk)
		}
		return fmt.Sprintf("Success (risk: %s, audit: %s)\n\n%s", result.Risk, result.AuditID, result.Output), nil

	default:
		return "", fmt.Errorf("unknown tool %q", params.Name)
	}
}

// helpers

func strArg(args map[string]any, key string) string {
	if v, ok := args[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func intArg(args map[string]any, key string, def int) int {
	if v, ok := args[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return def
}

func boolArg(args map[string]any, key string) bool {
	if v, ok := args[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return false
}

func marshalJSON(v any) (string, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal: %w", err)
	}
	return string(b), nil
}

func textResult(text string) ToolResult {
	return ToolResult{Content: []ContentBlock{{Type: "text", Text: text}}}
}

func errorResult(msg string) ToolResult {
	return ToolResult{
		Content: []ContentBlock{{Type: "text", Text: msg}},
		IsError: true,
	}
}
