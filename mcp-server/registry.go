package mcpserver

func allTools() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        "scan_server",
			Description: "Collect full server state: services, disk, memory, CPU, and queue workers. Read-only.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server": {Type: "string", Description: "Server name as defined in config"},
				},
				Required: []string{"server"},
			},
		},
		{
			Name:        "list_services",
			Description: "List all systemd services and their states. Read-only.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server": {Type: "string", Description: "Server name"},
				},
				Required: []string{"server"},
			},
		},
		{
			Name:        "service_status",
			Description: "Get detailed status of a specific systemd service. Read-only.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server":  {Type: "string", Description: "Server name"},
					"service": {Type: "string", Description: "Service name (e.g., nginx, php-fpm)"},
				},
				Required: []string{"server", "service"},
			},
		},
		{
			Name:        "get_logs",
			Description: "Fetch recent logs for a systemd unit or log file. Read-only.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server": {Type: "string", Description: "Server name"},
					"unit":   {Type: "string", Description: "Systemd unit name (e.g., nginx.service) or absolute log file path under /var/log or /srv"},
					"lines":  {Type: "number", Description: "Number of lines to fetch (default 100, max 5000)", Default: 100},
				},
				Required: []string{"server", "unit"},
			},
		},
		{
			Name:        "disk_usage",
			Description: "Get disk usage for all filesystems. Read-only.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server": {Type: "string", Description: "Server name"},
				},
				Required: []string{"server"},
			},
		},
		{
			Name:        "memory_usage",
			Description: "Get memory usage from /proc/meminfo. Read-only.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server": {Type: "string", Description: "Server name"},
				},
				Required: []string{"server"},
			},
		},
		{
			Name:        "cpu_usage",
			Description: "Get CPU load averages and core count. Read-only.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server": {Type: "string", Description: "Server name"},
				},
				Required: []string{"server"},
			},
		},
		{
			Name:        "queue_status",
			Description: "Get Supervisor queue worker statuses. Read-only.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server": {Type: "string", Description: "Server name"},
				},
				Required: []string{"server"},
			},
		},
		{
			Name:        "check_laravel_health",
			Description: "Check Laravel application health: storage writability, cache, queue, env info. Read-only.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server":   {Type: "string", Description: "Server name"},
					"app_path": {Type: "string", Description: "Absolute path to Laravel app root"},
				},
				Required: []string{"server", "app_path"},
			},
		},
		{
			Name:        "restart_service",
			Description: "Restart a systemd service. Requires user confirmation for medium+ risk.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server":    {Type: "string", Description: "Server name"},
					"service":   {Type: "string", Description: "Service name to restart"},
					"confirmed": {Type: "boolean", Description: "Set to true to confirm execution of a risky action", Default: false},
				},
				Required: []string{"server", "service"},
			},
		},
		{
			Name:        "queue_restart",
			Description: "Restart Supervisor queue worker(s). Requires user confirmation.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server":    {Type: "string", Description: "Server name"},
					"worker":    {Type: "string", Description: "Worker name or 'all' (default: all)"},
					"confirmed": {Type: "boolean", Description: "Set to true to confirm", Default: false},
				},
				Required: []string{"server"},
			},
		},
		{
			Name:        "deploy_service",
			Description: "Deploy a Laravel application: git pull, composer install, artisan cache, migrate. High risk - requires confirmation.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server":    {Type: "string", Description: "Server name"},
					"app_path":  {Type: "string", Description: "Absolute path to app root"},
					"branch":    {Type: "string", Description: "Git branch to deploy"},
					"confirmed": {Type: "boolean", Description: "Set to true to confirm", Default: false},
				},
				Required: []string{"server", "app_path", "branch"},
			},
		},
		{
			Name:        "run_artisan",
			Description: "Run an allowed artisan command. Allowlisted commands only. Requires confirmation for migrate commands.",
			InputSchema: JSONSchema{
				Type: "object",
				Properties: map[string]Property{
					"server":    {Type: "string", Description: "Server name"},
					"app_path":  {Type: "string", Description: "Absolute path to Laravel app root"},
					"command":   {Type: "string", Description: "Artisan command (e.g., cache:clear, migrate:status)"},
					"confirmed": {Type: "boolean", Description: "Set to true to confirm risky commands", Default: false},
				},
				Required: []string{"server", "app_path", "command"},
			},
		},
	}
}
