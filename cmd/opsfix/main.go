package main

import (
	"fmt"
	"os"

	"github.com/alperen/opsfix/audit"
	"github.com/alperen/opsfix/config"
	"github.com/alperen/opsfix/executor"
	mcpserver "github.com/alperen/opsfix/mcp-server"
	"github.com/alperen/opsfix/policy"
	"github.com/alperen/opsfix/scanner"
	sshpkg "github.com/alperen/opsfix/ssh"
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

	// Load config
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	fmt.Fprintf(os.Stderr, "[opsfix] loaded config: %d servers\n", len(cfg.Servers))

	// Load policy
	policyFile, err := policy.Load(cfg.PolicyFile)
	if err != nil {
		return fmt.Errorf("load policy: %w", err)
	}
	policyEngine := policy.NewEngine(policyFile)
	fmt.Fprintf(os.Stderr, "[opsfix] policy loaded: %d rules\n", len(policyFile.Rules))

	// Audit logger
	auditLogger, err := audit.New(cfg.Audit)
	if err != nil {
		return fmt.Errorf("init audit logger: %w", err)
	}
	defer auditLogger.Close()

	// SSH pool
	pool := sshpkg.NewPool(cfg.Servers, cfg.SSH)
	defer pool.Close()

	// Scanner
	sc := scanner.New(pool)

	// Executor
	ex := executor.New(pool, policyEngine, auditLogger, policyFile.ArtisanAllowlist)

	// Dispatcher
	dispatcher := mcpserver.NewDispatcher(sc, ex, pool)

	// MCP server
	srv := mcpserver.New(dispatcher)
	return srv.Run()
}
