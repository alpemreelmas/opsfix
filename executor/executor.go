package executor

import (
	"fmt"
	"strings"
	"time"

	"github.com/alperen/opsfix/audit"
	"github.com/alperen/opsfix/laravel"
	"github.com/alperen/opsfix/policy"
	sshpkg "github.com/alperen/opsfix/ssh"
)

type Executor struct {
	pool         *sshpkg.Pool
	policyEngine *policy.Engine
	auditLogger  *audit.Logger
	artisanAllowlist []string
}

func New(pool *sshpkg.Pool, engine *policy.Engine, logger *audit.Logger, allowlist []string) *Executor {
	return &Executor{
		pool:             pool,
		policyEngine:     engine,
		auditLogger:      logger,
		artisanAllowlist: allowlist,
	}
}

func (e *Executor) Execute(req ExecutionRequest) (ExecutionResult, error) {
	start := time.Now()

	// 1. Policy gate
	decision := e.policyEngine.Evaluate(req.Tool, req.Params)

	auditEvent := audit.NewEvent(req.Tool, req.ServerName, req.Params)

	if decision.Blocked {
		auditEvent.Decision = audit.DecisionBlocked
		auditEvent.Risk = string(decision.Risk)
		auditEvent.Error = decision.Reason
		auditEvent.DurationMs = time.Since(start).Milliseconds()
		e.auditLogger.Log(auditEvent)

		return ExecutionResult{
			Blocked: true,
			Risk:    decision.Risk,
			AuditID: auditEvent.ID,
		}, fmt.Errorf("action blocked by policy: %s", decision.Reason)
	}

	// 2. Approval gate
	if decision.RequiresApproval && !req.Confirmed {
		preview, err := e.buildPreview(req)
		if err != nil {
			return ExecutionResult{}, err
		}

		auditEvent.Decision = audit.DecisionDenied
		auditEvent.Risk = string(decision.Risk)
		auditEvent.DurationMs = time.Since(start).Milliseconds()
		e.auditLogger.Log(auditEvent)

		return ExecutionResult{
			Risk:            decision.Risk,
			AuditID:         auditEvent.ID,
			PendingApproval: fmt.Sprintf("Risk: %s\n\n%s\n\nTo confirm, call %q again with confirmed=true.", decision.Risk, preview, req.Tool),
		}, nil
	}

	// 3. Get SSH client
	client, err := e.pool.Get(req.ServerName)
	if err != nil {
		return ExecutionResult{}, fmt.Errorf("executor: %w", err)
	}

	// 4. Execute
	output, exitCode, err := e.run(client, req)
	if err != nil {
		auditEvent.Decision = audit.DecisionAllowed
		auditEvent.Risk = string(decision.Risk)
		auditEvent.Error = err.Error()
		auditEvent.DurationMs = time.Since(start).Milliseconds()
		e.auditLogger.Log(auditEvent)
		return ExecutionResult{}, err
	}

	auditEvent.Decision = audit.DecisionApproved
	auditEvent.Risk = string(decision.Risk)
	auditEvent.Output = truncate(output, 500)
	auditEvent.DurationMs = time.Since(start).Milliseconds()
	e.auditLogger.Log(auditEvent)

	return ExecutionResult{
		Output:   output,
		ExitCode: exitCode,
		Approved: req.Confirmed || !decision.RequiresApproval,
		Risk:     decision.Risk,
		AuditID:  auditEvent.ID,
	}, nil
}

func (e *Executor) run(client sshpkg.Client, req ExecutionRequest) (string, int, error) {
	strParam := func(key string) string {
		if v, ok := req.Params[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}

	switch req.Tool {
	case "restart_service":
		cmd, err := buildRestartService(strParam("service"))
		if err != nil {
			return "", 1, err
		}
		res, err := client.Exec(cmd)
		if err != nil {
			return "", 1, err
		}
		return res.Stdout + res.Stderr, res.ExitCode, nil

	case "queue_restart":
		worker := strParam("worker")
		if worker == "" {
			worker = "all"
		}
		cmd, err := buildQueueRestart(worker)
		if err != nil {
			return "", 1, err
		}
		res, err := client.Exec(cmd)
		if err != nil {
			return "", 1, err
		}
		return res.Stdout + res.Stderr, res.ExitCode, nil

	case "deploy_service":
		appPath := strParam("app_path")
		branch := strParam("branch")
		cmds, err := buildDeploy(appPath, branch)
		if err != nil {
			return "", 1, err
		}
		var sb strings.Builder
		for _, cmd := range cmds {
			res, err := client.Exec(cmd)
			if err != nil {
				return sb.String(), 1, fmt.Errorf("deploy failed at %q: %w", cmd, err)
			}
			sb.WriteString(fmt.Sprintf("$ %s\n%s\n", cmd, res.Stdout))
			if res.ExitCode != 0 {
				return sb.String(), res.ExitCode, fmt.Errorf("deploy step failed (exit %d): %s", res.ExitCode, res.Stderr)
			}
		}
		return sb.String(), 0, nil

	case "run_artisan":
		appPath := strParam("app_path")
		command := strParam("command")
		result, err := laravel.RunArtisan(client, appPath, command, e.artisanAllowlist)
		if err != nil {
			return "", 1, err
		}
		return result.Output, result.ExitCode, nil

	default:
		return "", 1, fmt.Errorf("executor: unknown tool %q", req.Tool)
	}
}

func (e *Executor) buildPreview(req ExecutionRequest) (string, error) {
	strParam := func(key string) string {
		if v, ok := req.Params[key]; ok {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}

	switch req.Tool {
	case "restart_service":
		return fmt.Sprintf("Will run: systemctl restart %s on server %q", strParam("service"), req.ServerName), nil
	case "queue_restart":
		worker := strParam("worker")
		if worker == "" {
			worker = "all"
		}
		return fmt.Sprintf("Will run: supervisorctl restart %s on server %q", worker, req.ServerName), nil
	case "deploy_service":
		return fmt.Sprintf("Will deploy branch %q of %q on server %q (git pull + composer + artisan cache + migrate)", strParam("branch"), strParam("app_path"), req.ServerName), nil
	case "run_artisan":
		return fmt.Sprintf("Will run: php artisan %s in %q on server %q", strParam("command"), strParam("app_path"), req.ServerName), nil
	}
	return fmt.Sprintf("Will execute tool %q with params %v on server %q", req.Tool, req.Params, req.ServerName), nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}
