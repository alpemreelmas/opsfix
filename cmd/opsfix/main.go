package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/alperen/opsfix/internal/audit"
	"github.com/alperen/opsfix/internal/config"
	"github.com/alperen/opsfix/internal/dispatch"
	"github.com/alperen/opsfix/internal/policy"
	"github.com/alperen/opsfix/internal/ratelimit"
	"github.com/alperen/opsfix/internal/secret"
	sshpkg "github.com/alperen/opsfix/internal/ssh"
	mcpserver "github.com/alperen/opsfix/mcp-server"

	// Register built-in adapters
	_ "github.com/alperen/opsfix/adapter/builtin/resources"
	_ "github.com/alperen/opsfix/adapter/builtin/systemd"
	// Register community adapters
	_ "github.com/alperen/opsfix/adapter/community/laravel"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "[opsfix] fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfgPath := os.Getenv("OPSFIX_CONFIG")
	if cfgPath == "" {
		cfgPath = "config.yaml"
	}

	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[opsfix] loaded config: %d servers\n", len(cfg.Servers))

	// Validate SSH key permissions for all servers
	for _, srv := range cfg.Servers {
		if err := sshpkg.ValidateKeyFile(srv.KeyPath); err != nil {
			return fmt.Errorf("ssh key validation: %w", err)
		}
		if srv.Bastion != nil {
			if err := sshpkg.ValidateKeyFile(srv.Bastion.KeyPath); err != nil {
				return fmt.Errorf("bastion key validation: %w", err)
			}
		}
	}

	// Load policy
	policyFile, err := policy.Load(cfg.PolicyFile)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	policyEngine := policy.NewEngine(policyFile)
	fmt.Fprintf(os.Stderr, "[opsfix] policy: %d rules\n", len(policyFile.Rules))

	// Secret redactor
	var literals []string
	if envKey := cfg.Audit.RedactLiteralsEnv; envKey != "" {
		if val := os.Getenv(envKey); val != "" {
			literals = strings.Split(val, ",")
		}
	}
	redactor := secret.New(literals)

	// Audit logger
	auditLogger, err := audit.New(cfg.Audit.FilePath, cfg.Audit.Enabled)
	if err != nil {
		return fmt.Errorf("init audit logger: %w", err)
	}
	defer auditLogger.Close()

	// Rate limiter
	rps := cfg.RateLimit.RequestsPerSecond
	if rps == 0 {
		rps = 2.0
	}
	burst := cfg.RateLimit.Burst
	if burst == 0 {
		burst = 10
	}
	limiter := ratelimit.New(rps, burst)

	// SSH pool
	pool := sshpkg.NewPool(cfg.Servers, cfg.SSH)
	defer pool.Close()

	// Dispatcher (adapter-based)
	dispatcher := dispatch.New(pool, policyEngine, auditLogger, limiter, redactor)

	// MCP server
	srv := mcpserver.New(dispatcher)
	return srv.Run()
}
