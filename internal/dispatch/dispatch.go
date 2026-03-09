package dispatch

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/alperen/opsfix/adapter"
	"github.com/alperen/opsfix/internal/audit"
	"github.com/alperen/opsfix/internal/policy"
	"github.com/alperen/opsfix/internal/ratelimit"
	"github.com/alperen/opsfix/internal/secret"
	sshpkg "github.com/alperen/opsfix/internal/ssh"
)

// Allowlist of commands all built-in adapters may use.
var builtinAllowlist = []string{
	"systemctl", "journalctl", "supervisorctl",
	"df", "free", "uptime",
	"php", "composer", "git",
	"test", "cat", "tail", "sudo",
}

type Dispatcher struct {
	pool         *sshpkg.Pool
	policyEngine *policy.Engine
	auditLogger  *audit.Logger
	limiter      *ratelimit.Limiter
	redactor     *secret.Redactor
	toolIndex    map[string]adapter.Adapter

	deployMuMu  sync.Mutex
	deployLocks map[string]*sync.Mutex
}

func New(
	pool *sshpkg.Pool,
	engine *policy.Engine,
	auditLogger *audit.Logger,
	limiter *ratelimit.Limiter,
	redactor *secret.Redactor,
) *Dispatcher {
	return &Dispatcher{
		pool:         pool,
		policyEngine: engine,
		auditLogger:  auditLogger,
		limiter:      limiter,
		redactor:     redactor,
		toolIndex:    adapter.ToolIndex(),
		deployLocks:  make(map[string]*sync.Mutex),
	}
}

func (d *Dispatcher) serverLock(server string) *sync.Mutex {
	d.deployMuMu.Lock()
	defer d.deployMuMu.Unlock()
	if mu, ok := d.deployLocks[server]; ok {
		return mu
	}
	mu := &sync.Mutex{}
	d.deployLocks[server] = mu
	return mu
}

type Request struct {
	Tool      string
	Server    string
	Params    map[string]any
	Confirmed bool
}

type Response struct {
	Output          string `json:"output,omitempty"`
	ExitCode        int    `json:"exit_code,omitempty"`
	Blocked         bool   `json:"blocked,omitempty"`
	PendingApproval string `json:"pending_approval,omitempty"`
	Risk            string `json:"risk,omitempty"`
	AuditID         string `json:"audit_id,omitempty"`
	Error           string `json:"error,omitempty"`
}

func (d *Dispatcher) Dispatch(req Request) Response {
	// 1. Rate limit
	if err := d.limiter.Allow(req.Server); err != nil {
		return Response{Error: err.Error()}
	}

	// 2. Find adapter
	a, ok := d.toolIndex[req.Tool]
	if !ok {
		return Response{Error: fmt.Sprintf("unknown tool %q", req.Tool)}
	}

	// 3. Redact params for audit
	redactedParams := d.redactor.RedactMap(req.Params)

	// 4. Policy check
	decision := d.policyEngine.Evaluate(req.Tool, req.Params)

	evt := audit.NewEvent(req.Tool, req.Server, redactedParams)
	evt.Adapter = a.ID()
	evt.Risk = string(decision.Risk)

	if decision.Blocked {
		evt.Decision = audit.DecisionBlocked
		evt.Error = decision.Reason
		d.auditLogger.Log(evt)
		return Response{
			Blocked: true,
			Risk:    string(decision.Risk),
			Error:   fmt.Sprintf("blocked: %s", decision.Reason),
			AuditID: evt.ID,
		}
	}

	// 5. Approval gate
	if decision.RequiresApproval && !req.Confirmed {
		evt.Decision = audit.DecisionDenied
		d.auditLogger.Log(evt)
		return Response{
			Risk:            string(decision.Risk),
			PendingApproval: fmt.Sprintf("Risk: %s\nTool: %s on server %q\nRe-call with confirmed=true to execute.", decision.Risk, req.Tool, req.Server),
			AuditID:         evt.ID,
		}
	}

	// 6. Concurrency lock for mutating ops
	for _, toolDef := range a.Tools() {
		if toolDef.Name == req.Tool && !toolDef.ReadOnly {
			mu := d.serverLock(req.Server)
			if !mu.TryLock() {
				return Response{Error: fmt.Sprintf("deploy_in_progress: another mutating operation is running on %q", req.Server)}
			}
			defer mu.Unlock()
			break
		}
	}

	// 7. Get SSH client and executor
	client, err := d.pool.Get(req.Server)
	if err != nil {
		return Response{Error: fmt.Sprintf("ssh: %v", err)}
	}

	sshExec := sshpkg.NewAdapterExecutor(client, builtinAllowlist)

	// 8. Execute via adapter
	result, err := a.Execute(req.Tool, req.Params, sshExec)
	if err != nil {
		evt.Decision = audit.DecisionAllowed
		evt.Error = d.redactor.Redact(err.Error())
		d.auditLogger.Log(evt)
		return Response{Error: err.Error()}
	}

	evt.Decision = audit.DecisionApproved
	evt.Output = d.redactor.Redact(truncate(result.Output, 4096))
	d.auditLogger.Log(evt)

	return Response{
		Output:   result.Output,
		ExitCode: result.ExitCode,
		AuditID:  evt.ID,
	}
}

// AllTools returns tool definitions for MCP tools/list response.
func (d *Dispatcher) AllTools() []adapter.ToolDefinition {
	return adapter.AllTools()
}

func (d *Dispatcher) MarshalResponse(r Response) string {
	b, _ := json.MarshalIndent(r, "", "  ")
	return string(b)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "\n[TRUNCATED]"
}
