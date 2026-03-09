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
	"which",
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

	probeCacheMu sync.RWMutex
	probeCache   map[string]adapter.CapabilitySet // key: "server:adapterID"
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
		probeCache:   make(map[string]adapter.CapabilitySet),
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

// GetCapabilities lazily probes and caches capabilities for a server+adapter pair.
func (d *Dispatcher) GetCapabilities(server, adapterID string) (adapter.CapabilitySet, error) {
	key := server + ":" + adapterID

	d.probeCacheMu.RLock()
	if caps, ok := d.probeCache[key]; ok {
		d.probeCacheMu.RUnlock()
		return caps, nil
	}
	d.probeCacheMu.RUnlock()

	a, ok := d.adapterByID(adapterID)
	if !ok {
		return adapter.CapabilitySet{}, fmt.Errorf("unknown adapter %q", adapterID)
	}

	client, err := d.pool.Get(server)
	if err != nil {
		return adapter.CapabilitySet{}, fmt.Errorf("ssh: %v", err)
	}
	sshExec := sshpkg.NewAdapterExecutor(client, builtinAllowlist)
	caps := a.Probe(sshExec)

	d.probeCacheMu.Lock()
	d.probeCache[key] = caps
	d.probeCacheMu.Unlock()

	return caps, nil
}

func (d *Dispatcher) adapterByID(id string) (adapter.Adapter, bool) {
	seen := map[string]bool{}
	for _, a := range d.toolIndex {
		if seen[a.ID()] {
			continue
		}
		seen[a.ID()] = true
		if a.ID() == id {
			return a, true
		}
	}
	return nil, false
}

type Request struct {
	Tool      string
	Server    string
	Params    map[string]any
	Confirmed bool
}

type Response struct {
	Output          string         `json:"output,omitempty"`
	ExitCode        int            `json:"exit_code,omitempty"`
	Blocked         bool           `json:"blocked,omitempty"`
	PendingApproval bool           `json:"pending_approval,omitempty"`
	PreFlight       *PreFlightView `json:"pre_flight,omitempty"`
	Verify          *VerifyView    `json:"verify,omitempty"`
	Risk            string         `json:"risk,omitempty"`
	AuditID         string         `json:"audit_id,omitempty"`
	Error           string         `json:"error,omitempty"`
}

type PreFlightView struct {
	CurrentState map[string]any `json:"current_state,omitempty"`
	Plan         []string       `json:"plan,omitempty"`
	Warnings     []string       `json:"warnings,omitempty"`
	Blocker      string         `json:"blocker,omitempty"`
}

type VerifyView struct {
	Success    bool           `json:"success"`
	NewState   map[string]any `json:"new_state,omitempty"`
	RolledBack bool           `json:"rolled_back,omitempty"`
	Error      string         `json:"error,omitempty"`
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

	// 3. Determine if readonly
	isReadOnly := false
	for _, t := range a.Tools() {
		if t.Name == req.Tool {
			isReadOnly = t.ReadOnly
			break
		}
	}

	// 4. Redact params for audit + policy check
	redactedParams := d.redactor.RedactMap(req.Params)
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

	// 5. Get SSH client + executor (needed for PreFlight before approval gate for mutating tools)
	client, err := d.pool.Get(req.Server)
	if err != nil {
		return Response{Error: "ssh: " + err.Error()}
	}
	sshExec := sshpkg.NewAdapterExecutor(client, builtinAllowlist)

	// 6. PreFlight (mutating only)
	var pfReport adapter.PreFlightReport
	if !isReadOnly {
		pfReport, err = d.runPreFlight(a, req.Tool, req.Params, sshExec)
		if err != nil {
			return Response{Error: "pre-flight: " + err.Error()}
		}
		if pfReport.Blocker != "" {
			return Response{
				Blocked: true,
				PreFlight: &PreFlightView{
					CurrentState: pfReport.CurrentState,
					Blocker:      pfReport.Blocker,
					Warnings:     pfReport.Warnings,
				},
				Error:   "pre-flight blocked: " + pfReport.Blocker,
				AuditID: evt.ID,
			}
		}
		if decision.RequiresApproval && !req.Confirmed {
			evt.Decision = audit.DecisionDenied
			d.auditLogger.Log(evt)
			return Response{
				PendingApproval: true,
				Risk:            string(decision.Risk),
				PreFlight: &PreFlightView{
					CurrentState: pfReport.CurrentState,
					Plan:         pfReport.Plan,
					Warnings:     pfReport.Warnings,
				},
				AuditID: evt.ID,
			}
		}
	} else if decision.RequiresApproval && !req.Confirmed {
		evt.Decision = audit.DecisionDenied
		d.auditLogger.Log(evt)
		return Response{
			PendingApproval: true,
			Risk:            string(decision.Risk),
			AuditID:         evt.ID,
		}
	}

	// 7. Concurrency lock for mutating ops
	if !isReadOnly {
		mu := d.serverLock(req.Server)
		if !mu.TryLock() {
			return Response{Error: fmt.Sprintf("deploy_in_progress: server %q busy", req.Server)}
		}
		defer mu.Unlock()
	}

	// 8. Execute via adapter
	result, err := a.Execute(req.Tool, req.Params, sshExec)
	if err != nil {
		evt.Decision = audit.DecisionAllowed
		evt.Error = d.redactor.Redact(err.Error())
		d.auditLogger.Log(evt)
		return Response{Error: err.Error(), AuditID: evt.ID}
	}

	// 9. Verify (mutating only)
	var verifyView *VerifyView
	if !isReadOnly {
		vr, verifyErr := a.Verify(req.Tool, req.Params, result, sshExec)
		if verifyErr == nil {
			view := &VerifyView{
				Success:    vr.Success,
				NewState:   vr.NewState,
				RolledBack: vr.RolledBack,
				Error:      vr.Error,
			}
			if !vr.Success && len(pfReport.RollbackInfo) > 0 {
				rolled := d.attemptRollback(a, req.Tool, pfReport.RollbackInfo, sshExec)
				view.RolledBack = rolled
				if rolled {
					view.Error += " (rolled back to previous state)"
				}
			}
			verifyView = view
		}
	}

	evt.Decision = audit.DecisionApproved
	evt.Output = d.redactor.Redact(truncate(result.Output, 4096))
	d.auditLogger.Log(evt)

	return Response{
		Output:   result.Output,
		ExitCode: result.ExitCode,
		Verify:   verifyView,
		AuditID:  evt.ID,
	}
}

func (d *Dispatcher) runPreFlight(a adapter.Adapter, tool string, params adapter.Params, exec adapter.SSHExecutor) (report adapter.PreFlightReport, err error) {
	defer func() {
		if r := recover(); r != nil {
			// pre-flight panic → return empty report so execution isn't blocked
			report = adapter.PreFlightReport{}
			err = nil
		}
	}()
	return a.PreFlight(tool, params, exec)
}

func (d *Dispatcher) attemptRollback(a adapter.Adapter, tool string, rollbackInfo map[string]any, exec adapter.SSHExecutor) bool {
	// Only laravel_deploy rollback supported for now
	if tool != "laravel_deploy" {
		return false
	}
	sha, _ := rollbackInfo["git_sha"].(string)
	appPath, _ := rollbackInfo["app_path"].(string)
	if sha == "" || appPath == "" {
		return false
	}
	res, err := exec.Run("git", "-C", appPath, "checkout", sha)
	if err != nil || res.ExitCode != 0 {
		return false
	}
	exec.Run("php", appPath+"/artisan", "optimize") //nolint:errcheck
	return true
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
