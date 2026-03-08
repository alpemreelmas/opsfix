# Opsfix — Full Software Design (FSD)

**Version:** 2.0-draft
**Date:** 2026-03-08
**Module:** `github.com/alperen/opsfix`
**Go Version:** 1.22+
**Status:** Design document — pre-implementation

---

## Table of Contents

1. [Overview & Goals](#1-overview--goals)
2. [Current State & Problems](#2-current-state--problems)
3. [Architecture Design](#3-architecture-design)
4. [Plugin / Adapter System](#4-plugin--adapter-system)
5. [Security Design](#5-security-design) ← PRIMARY FOCUS
6. [Configuration Schema](#6-configuration-schema)
7. [Observability](#7-observability)
8. [Edge Cases](#8-edge-cases)
9. [Testing Strategy](#9-testing-strategy)
10. [Deployment](#10-deployment)
11. [Migration Plan](#11-migration-plan)

---

## 1. Overview & Goals

Opsfix is a Go MCP (Model Context Protocol) server that exposes a curated set of tools to an AI agent (Claude Code) for safe, audited, policy-gated infrastructure operations on remote servers over SSH.

### 1.1 Goals of This Redesign

- Remove all framework-specific (Laravel) hardcoding from core packages
- Introduce a first-class **adapter/plugin system** so any tech stack can be supported without modifying core
- Make **security a hard invariant** — not best-effort — at every layer
- Keep the binary statically compiled, zero runtime dependencies
- Enable community contribution of new platform adapters via reviewed source PRs

### 1.2 Non-Goals

- Opsfix is **not** a general-purpose shell proxy — all operations are tool-scoped
- Opsfix does **not** store secrets — reads key files at startup, uses them only for SSH auth
- Opsfix does **not** replace CI/CD pipelines — it complements them for incident response and ad-hoc ops
- Opsfix does **not** use dynamic plugin loading (`go plugin`) — this is a deliberate security decision

---

## 2. Current State & Problems

### 2.1 Package Inventory

| Package | Role | Problem |
|---|---|---|
| `config` | YAML config load/validate | Needs adapter fields, plugin config sections |
| `policy` | Rule engine | Hardcodes tool names like `run_artisan` |
| `audit` | JSONL audit log | No tamper protection, no secret redaction |
| `ssh` | SSH client pool | Missing bastion/jump host, no key permission validation |
| `scanner` | Server scan/health | Unconditionally calls `journalctl`, `supervisorctl` |
| `executor` | Tool execution | Hardcodes Laravel deploy in a switch statement |
| `laravel` | Artisan runner, health | Tightly coupled to executor and dispatcher |
| `mcp-server` | JSON-RPC dispatch | Imports `laravel` directly; not extensible |
| `cmd/opsfix` | Entrypoint | Manually wires everything; no adapter concept |

### 2.2 Key Coupling Problems

- `mcp-server/dispatcher.go` imports `github.com/alperen/opsfix/laravel` directly
- `executor/executor.go` has `case "run_artisan"` with Laravel-specific steps hardcoded
- `policy.yaml` rules reference tool names that only exist for Laravel
- `scanner` calls `journalctl` and `supervisorctl` unconditionally (breaks on Docker-only hosts, BSD, Alpine)

---

## 3. Architecture Design

### 3.1 High-Level Architecture

```
User (natural language)
        │
        ▼
Claude Code (AI Reasoning Layer)
        │  JSON-RPC 2.0 / stdio
        ▼
┌─────────────────────────────────────────┐
│            Opsfix MCP Server            │
│                                         │
│  ┌──────────┐   ┌─────────────────────┐ │
│  │  Policy  │   │   Rate Limiter      │ │
│  │  Engine  │   │  (token bucket)     │ │
│  └──────────┘   └─────────────────────┘ │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │        Adapter Registry          │   │
│  │  systemd │ nginx │ docker │ k8s  │   │
│  │  laravel │ django│ rails  │ node │   │
│  │  [community adapters...]         │   │
│  └──────────────────────────────────┘   │
│                                         │
│  ┌──────────┐   ┌─────────────────────┐ │
│  │  Secret  │   │   Audit Logger      │ │
│  │ Redactor │   │  (HMAC chain JSONL) │ │
│  └──────────┘   └─────────────────────┘ │
└─────────────────────────────────────────┘
        │  SSH / key-based auth only
        ▼
┌─────────────────────────────────────────┐
│           Target Servers                │
│  (any OS, any stack, ai-agent user)     │
└─────────────────────────────────────────┘
```

### 3.2 Target Package Structure

```
github.com/alperen/opsfix/
├── cmd/opsfix/
│   └── main.go                      # entrypoint: load config → wire → serve
│
├── internal/                        # not importable by community adapters
│   ├── config/                      # load, validate, defaults
│   ├── policy/                      # rule engine (adapter-agnostic)
│   ├── audit/                       # tamper-evident HMAC-chained JSONL
│   ├── ssh/                         # pool, bastion, key manager
│   ├── ratelimit/                   # per-server token bucket
│   ├── dispatch/                    # MCP tool → adapter router
│   ├── secret/                      # redaction pipeline
│   └── health/                      # opsfix self-health (Unix socket)
│
├── adapter/                         # PUBLIC — importable by community adapters
│   ├── adapter.go                   # Adapter interface
│   ├── registry.go                  # global registry
│   ├── builtin/
│   │   ├── systemd/                 # systemd service management
│   │   ├── supervisor/              # Supervisor/supervisorctl
│   │   ├── docker/                  # Docker & Compose
│   │   ├── kubernetes/              # kubectl wrapper
│   │   ├── nginx/                   # Nginx status, reload, test
│   │   ├── generic/                 # fallback: any systemd service
│   │   └── resources/               # disk, memory, CPU, logs
│   └── community/                   # reviewed community PRs
│       ├── laravel/
│       ├── django/
│       ├── rails/
│       ├── nodejs/                  # PM2
│       ├── nextjs/
│       ├── spring/
│       ├── celery/
│       ├── sidekiq/
│       └── fastapi/
│
├── docs/
│   └── FSD.md                       # this document
├── config.example.yaml
├── policy.example.yaml
├── go.mod
└── go.sum
```

---

## 4. Plugin / Adapter System

### 4.1 Core Adapter Interface

```go
// adapter/adapter.go
package adapter

import "github.com/alperen/opsfix/internal/ssh"

// InterfaceVersion must be incremented when breaking changes are made.
const InterfaceVersion = 2

// Adapter is the contract every platform adapter must implement.
type Adapter interface {
    // ID returns the unique adapter identifier (e.g., "laravel", "django").
    ID() string

    // InterfaceVersion returns the interface version this adapter targets.
    InterfaceVersion() int

    // Tools returns the list of MCP tools this adapter provides.
    Tools() []ToolDefinition

    // Execute runs a tool. The SSH executor is the ONLY way to run
    // remote commands — adapters must not use os/exec or net.Dial.
    Execute(tool string, params Params, exec ssh.Executor) (Result, error)

    // DefaultPolicyRules returns adapter-specific policy rules to be
    // merged into the policy engine on startup (lower priority than
    // user-defined rules in policy.yaml).
    DefaultPolicyRules() []PolicyRule
}

// Params is a typed parameter bag — adapters must not accept raw map[string]any.
type Params map[string]any

// Result is the structured output of a tool execution.
type Result struct {
    Output   string
    ExitCode int
    Metadata map[string]any // adapter-specific structured data
}

// ToolDefinition describes a single MCP tool exposed by an adapter.
type ToolDefinition struct {
    Name        string
    Description string
    InputSchema JSONSchema
    // ReadOnly indicates no state is modified. Policy engine uses this.
    ReadOnly bool
}

// PolicyRule is a default rule contributed by an adapter.
type PolicyRule struct {
    Name       string
    Tool       string
    Risk       string // "low" | "medium" | "high" | "critical"
    Block      bool
    Conditions []PolicyCondition
}

type PolicyCondition struct {
    Field   string
    Matches string // regex
}
```

### 4.2 SSH Executor Interface (injected into adapters)

```go
// internal/ssh/executor.go
package ssh

// Executor is the ONLY way adapters may run remote commands.
// It enforces allowlisting and logs every invocation.
type Executor interface {
    // Run executes a pre-approved command on the remote server.
    // cmd must be one of the commands declared in the adapter's manifest.
    // Arguments are passed as separate strings — NEVER concatenated into a shell string.
    Run(cmd string, args ...string) (ExecResult, error)

    // ReadFile fetches a remote file path. Path must start with an
    // allowlisted prefix (e.g., /var/log/, /srv/, /etc/nginx/).
    ReadFile(path string) ([]byte, error)
}

type ExecResult struct {
    Stdout   string
    Stderr   string
    ExitCode int
    Duration time.Duration
}
```

**Injection prevention:** Adapters pass command and arguments separately. The SSH layer calls `session.Run()` which sends an `exec` request — not a `shell` request — so shell metacharacters in any argument are completely inert. Adapters never construct shell strings.

### 4.3 Adapter Registry

```go
// adapter/registry.go
package adapter

import "fmt"

var globalRegistry = &registry{adapters: map[string]Adapter{}}

func Register(a Adapter) {
    if a.InterfaceVersion() != InterfaceVersion {
        panic(fmt.Sprintf("adapter %q: interface version mismatch (got %d, want %d)",
            a.ID(), a.InterfaceVersion(), InterfaceVersion))
    }
    globalRegistry.register(a)
}

func All() []Adapter        { return globalRegistry.all() }
func ToolIndex() map[string]Adapter { return globalRegistry.toolIndex() }
```

Adapters self-register in `init()`:

```go
// adapter/community/laravel/laravel.go
func init() {
    adapter.Register(&LaravelAdapter{})
}
```

The binary includes only the adapters imported by `cmd/opsfix/main.go`. Community adapters are opt-in via blank imports controlled by build tags:

```go
//go:build laravel
import _ "github.com/alperen/opsfix/adapter/community/laravel"
```

### 4.4 Adapter Manifest (community PR requirement)

Every community adapter directory must include a `manifest.yaml`:

```yaml
# adapter/community/fastapi/manifest.yaml
id: fastapi
version: "1.0.0"
interface_version: 2
description: "FastAPI (Python) adapter — health check, process management, log tail"
author: "Jane Doe <jane@example.com>"

# ALL remote commands this adapter may execute — used for audit and review.
# Format: ["binary", "arg1", ...] where args starting with $ are variable.
remote_commands:
  - ["systemctl", "status", "$service"]
  - ["systemctl", "restart", "$service"]
  - ["journalctl", "-u", "$unit", "-n", "$lines", "--no-pager"]
  - ["tail", "-n", "$lines", "$log_path"]    # $log_path validated against allowlist

# Read-only file path prefixes this adapter may access.
remote_read_paths:
  - "/var/log/"
  - "/etc/supervisor/"

tools:
  - name: fastapi_health
    read_only: true
    risk: low
  - name: fastapi_restart
    read_only: false
    risk: medium
    requires_approval: true
```

### 4.5 Built-in Adapter Catalog

| Adapter ID | Platform | Tools |
|---|---|---|
| `systemd` | systemd services | `service_status`, `service_list`, `service_restart`, `service_logs` |
| `supervisor` | Supervisor workers | `supervisor_status`, `supervisor_restart`, `supervisor_logs` |
| `resources` | OS metrics | `disk_usage`, `memory_usage`, `cpu_usage` |
| `docker` | Docker/Compose | `docker_ps`, `docker_logs`, `docker_restart`, `compose_up`, `compose_down` |
| `kubernetes` | kubectl | `k8s_pods`, `k8s_rollout_restart`, `k8s_logs`, `k8s_describe` |
| `nginx` | Nginx | `nginx_status`, `nginx_reload`, `nginx_test_config`, `nginx_logs` |
| `generic` | Any service | `generic_service_status`, `generic_service_restart`, `generic_logs` |

| Community ID | Platform | Key Tools |
|---|---|---|
| `laravel` | Laravel (PHP) | `laravel_artisan`, `laravel_health`, `laravel_deploy`, `laravel_queue_restart` |
| `django` | Django (Python) | `django_manage`, `django_health`, `django_deploy`, `django_collectstatic` |
| `rails` | Rails (Ruby) | `rails_runner`, `rails_health`, `rails_deploy`, `rails_db_migrate` |
| `nodejs` | Node.js / PM2 | `pm2_status`, `pm2_restart`, `pm2_logs`, `pm2_reload` |
| `nextjs` | Next.js | `nextjs_health`, `nextjs_restart`, `nextjs_build_restart` |
| `spring` | Spring Boot | `spring_health`, `spring_restart`, `spring_logs` |
| `celery` | Celery workers | `celery_status`, `celery_restart`, `celery_purge` |
| `sidekiq` | Sidekiq | `sidekiq_status`, `sidekiq_restart`, `sidekiq_stats` |
| `php_fpm` | PHP-FPM | `phpfpm_status`, `phpfpm_reload`, `phpfpm_logs` |
| `fastapi` | FastAPI | `fastapi_health`, `fastapi_restart`, `fastapi_logs` |

---

## 5. Security Design

> **Security is the primary design constraint. Every other concern is secondary.**

### 5.1 Threat Model — STRIDE Analysis

| Threat | Component | Attack Vector | Severity | Mitigation |
|---|---|---|---|---|
| **Spoofing** | SSH auth | Stolen/guessed credentials | Critical | Key-only auth; no passwords; `PermitRootLogin no` |
| **Spoofing** | MCP stdio | Malicious MCP client | Medium | Opsfix only launched by Claude Code (stdio trust boundary) |
| **Tampering** | Audit log | Attacker modifies log after breach | High | HMAC chain; each entry includes hash of previous entry |
| **Tampering** | Policy file | Attacker weakens rules | High | Policy file hash pinned in config; re-read triggers re-verify |
| **Tampering** | SSH commands | Injection via AI-provided params | Critical | Args separated from command; exec (not shell) request |
| **Repudiation** | Any action | No proof of what ran | High | Append-only audit log; every tool call logged pre-execution |
| **Info Disclosure** | Audit log | Secrets in log output | High | Secret redaction pipeline before logging |
| **Info Disclosure** | SSH key | Key file readable by others | High | Key permission check at startup (fail-fast if `chmod 644`) |
| **DoS** | SSH pool | AI hammers infrastructure | Medium | Per-server token bucket rate limiter |
| **DoS** | Audit log | Disk full stops all operations | Medium | Pre-flight disk check; fallback to stderr on write failure |
| **Elevation of Privilege** | ai-agent user | Sudo abuse | Critical | Minimal sudoers allowlist; no NOPASSWD for dangerous commands |
| **Elevation of Privilege** | Plugin | Malicious community adapter | High | No dynamic loading; source review required; no `os/exec` in adapters |
| **Elevation of Privilege** | Path traversal | `../` in file paths | High | Prefix allowlist enforced in `ssh.Executor.ReadFile()` |

### 5.2 SSH Security

#### Key Management

```go
// internal/ssh/keymgr.go

// validateKeyFile checks that the private key file has secure permissions.
// Fails fast at startup if key is group- or world-readable.
func validateKeyFile(path string) error {
    info, err := os.Stat(path)
    if err != nil {
        return fmt.Errorf("ssh key %q: %w", path, err)
    }
    mode := info.Mode().Perm()
    if mode & 0o044 != 0 {
        return fmt.Errorf("ssh key %q: permissions %o are too open; require 0600 or 0400", path, mode)
    }
    return nil
}
```

#### Connection Policy

- `PasswordAuthentication` → always disabled (`ssh.AuthMethod` only uses `PublicKeys`)
- `HostKeyCallback` → `knownhosts.New()` is **mandatory in non-dev mode**; `InsecureIgnoreHostKey` blocked by a compile-time check on build tag `production`
- SSH certificate authorities supported: config accepts `ca_public_key` instead of per-host `known_hosts`

#### Bastion / Jump Host

```go
// internal/ssh/pool.go — bastion support
type ServerConfig struct {
    Name    string
    Host    string
    Port    int
    User    string
    KeyPath string
    Bastion *BastionConfig // optional
}

type BastionConfig struct {
    Host    string
    Port    int
    User    string
    KeyPath string // may differ from target key
}
```

When `Bastion` is set: dial bastion → open TCP channel to target → SSH handshake to target through that channel. The target never has a direct public IP.

#### SSH Certificate Authority

```yaml
# config.yaml
ssh:
  certificate_authority:
    trusted_ca_public_key: "/etc/opsfix/ca.pub"  # signs host certs
    # When set, known_hosts_file is ignored; host certs verified against CA
```

### 5.3 Command Injection Prevention

Three independent layers:

**Layer 1 — Adapter contract:** Adapters call `exec.Run("systemctl", "restart", serviceName)` with args as separate strings. This is enforced by the `ssh.Executor` interface. There is no string concatenation.

**Layer 2 — SSH exec request:** The Go SSH library sends an `exec` channel request with the command string. The server spawns the process with `execve()` — no shell involved. Metacharacters are literal.

**Layer 3 — Allowlist validation in ssh.Executor:** The Executor validates that the command binary is in a per-adapter declared allowlist (from `manifest.yaml`). Commands not in the allowlist panic at registration time in test mode, and return an error at runtime.

```go
// internal/ssh/executor.go
func (e *sshExecutor) Run(cmd string, args ...string) (ExecResult, error) {
    if !e.allowlist.Permitted(cmd) {
        return ExecResult{}, fmt.Errorf("security: command %q not in adapter allowlist", cmd)
    }
    // Build session — NO shell string construction
    sess, _ := e.client.NewSession()
    // ssh sends exec request; target OS calls execve, no /bin/sh
    err := sess.Run(buildExecString(cmd, args...))
    ...
}

// buildExecString quotes args for the SSH exec request.
// This is NOT shell quoting — it's only needed because the Go SSH library
// takes a single string for the exec request. The server still uses execve.
func buildExecString(cmd string, args ...string) string {
    parts := make([]string, 0, len(args)+1)
    parts = append(parts, shellescape(cmd))
    for _, a := range args {
        parts = append(parts, shellescape(a))
    }
    return strings.Join(parts, " ")
}
```

### 5.4 Privilege Separation — ai-agent User Design

The agent connects as a non-root user with minimal sudo grants.

**Server-side setup (`scripts/setup-agent-user.sh`):**

```bash
#!/bin/bash
set -euo pipefail

useradd -r -m -s /bin/bash ai-agent

# SSH authorized_keys
mkdir -p /home/ai-agent/.ssh
cp "$OPSFIX_PUBKEY" /home/ai-agent/.ssh/authorized_keys
chown -R ai-agent:ai-agent /home/ai-agent/.ssh
chmod 700 /home/ai-agent/.ssh
chmod 600 /home/ai-agent/.ssh/authorized_keys

# Sudoers — minimal, explicit
cat > /etc/sudoers.d/ai-agent << 'EOF'
# Opsfix ai-agent sudoers
# ALLOWED: service management (explicit service names set by operator)
ai-agent ALL=(root) NOPASSWD: /bin/systemctl status *
ai-agent ALL=(root) NOPASSWD: /bin/systemctl restart nginx
ai-agent ALL=(root) NOPASSWD: /bin/systemctl restart php8.3-fpm
ai-agent ALL=(root) NOPASSWD: /bin/systemctl restart supervisor

# ALLOWED: log reading
ai-agent ALL=(root) NOPASSWD: /usr/bin/journalctl -u * -n * --no-pager *

# DENIED: anything else requires root — implicit via no other NOPASSWD rules
EOF

chmod 440 /etc/sudoers.d/ai-agent
visudo -c  # validate before applying
```

**What ai-agent can never do:**
- Run `rm`, `mkfs`, `fdisk`, `dd`
- Modify `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- SSH from target server to other servers (no outbound SSH keys for ai-agent)
- Read files outside its home and designated log directories without explicit sudo grants

### 5.5 Policy Engine Design

#### Rule Evaluation

1. Rules evaluated **top-to-bottom**; **first match wins**
2. `block: true` is **unconditional** — bypasses approval flow entirely
3. Default is **deny-unless-explicitly-allowed** for execution tools; **allow** for read-only tools
4. Adapter default rules merged at lowest priority (user rules always win)

```
Policy evaluation order:
  1. User rules (policy.yaml)          ← highest priority
  2. Adapter default rules             ← contributed by adapter
  3. System defaults (block_at/require_approval_at thresholds)
```

#### Risk Level Semantics

| Level | Meaning | Default Behavior |
|---|---|---|
| `low` | No service disruption possible | Auto-approved |
| `medium` | Transient disruption possible (restart) | Requires confirmation |
| `high` | Data change or significant disruption | Requires confirmation + diff preview |
| `critical` | Irreversible data loss | Hard blocked |

#### Conflict Resolution

When multiple rules could match (won't happen due to first-match-wins, but documented for clarity): earlier rule in the file wins. Operators should place more specific rules before more general ones.

#### Default-Deny for Execution

Any tool with `ReadOnly: false` that has no matching policy rule defaults to `risk: medium` (requires approval). This means new adapters that forget to declare policy rules are safe by default.

### 5.6 Secret Redaction

Every audit log entry passes through the redaction pipeline before being written:

```go
// internal/secret/redactor.go

// Redactor replaces known secret patterns with [REDACTED] before logging.
type Redactor struct {
    literals []string   // exact strings to redact (loaded from config)
    patterns []*regexp.Regexp // regex patterns
}

// Built-in patterns always active:
var builtinPatterns = []*regexp.Regexp{
    regexp.MustCompile(`(?i)password["\s]*[:=]["\s]*\S+`),
    regexp.MustCompile(`(?i)secret["\s]*[:=]["\s]*\S+`),
    regexp.MustCompile(`(?i)token["\s]*[:=]["\s]*\S+`),
    regexp.MustCompile(`(?i)api[_-]?key["\s]*[:=]["\s]*\S+`),
    regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`), // base64 (potential keys)
}
```

Config allows adding literal strings to redact (e.g., known DB password):

```yaml
audit:
  redact_literals_env: "OPSFIX_REDACT_SECRETS"  # comma-separated secrets in env var
  # Never put secrets directly in config file
```

### 5.7 Tamper-Evident Audit Log

Each audit entry includes an HMAC of the previous entry's hash, forming a chain. Tampering with any entry breaks all subsequent entries' verification.

```go
// internal/audit/logger.go

type Event struct {
    ID         string         `json:"id"`
    Timestamp  time.Time      `json:"timestamp"`
    Tool       string         `json:"tool"`
    Server     string         `json:"server"`
    Adapter    string         `json:"adapter"`
    Params     map[string]any `json:"params"`    // after redaction
    Decision   string         `json:"decision"`  // allowed|blocked|approved|pending
    Risk       string         `json:"risk"`
    Output     string         `json:"output,omitempty"` // after redaction, truncated
    Error      string         `json:"error,omitempty"`
    DurationMs int64          `json:"duration_ms"`
    PrevHash   string         `json:"prev_hash"` // HMAC-SHA256 of previous entry
    Hash       string         `json:"hash"`      // HMAC-SHA256 of this entry
}
```

HMAC key loaded from environment variable `OPSFIX_AUDIT_HMAC_KEY`. If not set: log is written but without HMAC chain (warning emitted). Verification tool: `opsfix verify-audit --file audit.jsonl`.

### 5.8 Rate Limiting

Per-server token bucket prevents AI agent from hammering infrastructure:

```go
// internal/ratelimit/limiter.go

type Limiter struct {
    buckets map[string]*rate.Limiter // keyed by server name
    mu      sync.RWMutex
}

// Default: 10 requests/second burst, 2 requests/second steady state per server.
// Config overrides per server via rate_limit section.
```

Additionally: a **global concurrency gate** prevents concurrent mutating operations on the same server:

```go
// internal/dispatch/dispatch.go
type deployLock struct {
    mu    sync.Mutex
    locks map[string]*sync.Mutex // per server
}
// Second deploy to same server blocks until first completes or times out.
```

### 5.9 Network Security Recommendations

These are documented operator guidelines:

| Control | Recommendation |
|---|---|
| Opsfix host position | Run on a dedicated bastion/management host — never on a web server |
| Outbound firewall | Allow only port 22 outbound to specific target server IPs |
| No inbound ports | Opsfix listens on no TCP ports (stdio only) |
| Target server firewalls | Allow SSH inbound only from Opsfix host IP |
| Separate key per environment | Different ed25519 keys for prod vs. staging vs. dev |
| Private network | Place Opsfix host and targets on the same VPC/VLAN |
| Key rotation cadence | Rotate SSH keys every 90 days via `opsfix rotate-key` command |

### 5.10 Supply Chain Security — Plugin/Adapter Trust

- **No dynamic loading**: `go build -buildmode=plugin` is explicitly NOT used. All adapters compiled in at build time.
- **Source-only community adapters**: submitted as Go source PRs, reviewed before merge
- **Adapter review checklist** (required for merge):
  1. All `remote_commands` declared in manifest; none are `/bin/sh`, `/bin/bash`, or interpreters with user-controlled arguments
  2. No `net.Dial` or HTTP calls from within the adapter
  3. No `os/exec` usage (caught by custom `go vet` analyzer)
  4. No file I/O on the agent host (only `ssh.Executor` allowed)
  5. Panic recovery tested
  6. All params validated before passing to `ssh.Executor`
- **Reproducible builds**: `go.sum` pinned; CI verifies `go mod verify`
- **Binary signing**: Released binaries signed with `cosign`, published to Rekor transparency log

### 5.11 Blast Radius Limiting

- **Per-server SSH key** (recommended): compromise of one key affects only that server
- **Per-server rate limit**: misbehaving AI cannot use one connection to affect another server
- **Server tag scoping**: policy rules can restrict tools to servers with specific tags (e.g., `tags: [staging]`)
- **No lateral movement**: `ai-agent` user has no SSH keys; cannot SSH from target to other servers
- **Connection isolation**: each server has its own SSH session in the pool; sessions not shared

### 5.12 Credential Rotation Without Downtime

```bash
# opsfix rotate-key --server web-01 --new-key ~/.ssh/opsfix_new_ed25519
# 1. Adds new public key to authorized_keys on web-01 (both keys valid)
# 2. Updates config.yaml to point to new key
# 3. Invalidates old connection in SSH pool
# 4. Verifies new connection works
# 5. Removes old public key from authorized_keys
```

---

## 6. Configuration Schema

```yaml
# config.yaml — full schema with all options
version: "1"

# Path to policy rules file
policy_file: "/etc/opsfix/policy.yaml"

# Audit logging
audit:
  enabled: true
  file_path: "/var/log/opsfix/audit.jsonl"
  # HMAC key for tamper-evident chain — set via env var, NOT here
  hmac_key_env: "OPSFIX_AUDIT_HMAC_KEY"
  # Env var containing comma-separated literal strings to redact
  redact_literals_env: "OPSFIX_REDACT_SECRETS"
  # Max size of captured output per event (bytes)
  max_output_bytes: 4096

# SSH defaults (can be overridden per server)
ssh:
  idle_timeout: "5m"
  connect_timeout: "10s"
  command_timeout: "2m"
  # Required in production. Omit only for dev.
  known_hosts_file: "/home/deploy/.ssh/known_hosts"
  # Optional: use SSH CA instead of known_hosts
  # certificate_authority:
  #   trusted_ca_public_key: "/etc/opsfix/ca.pub"

# Rate limiting
rate_limit:
  # Per-server token bucket
  requests_per_second: 2.0
  burst: 10
  # Max time to wait in queue before returning rate_limited error
  queue_timeout: "30s"

# Adapters to load (built-in adapters always loaded)
# Community adapters must also be compiled in via build tags
adapters:
  - id: laravel
    config:
      # Adapter-specific configuration
      app_path: "/var/www/myapp"
      php_binary: "php8.3"
      artisan_timeout: "120s"

  - id: django
    config:
      app_path: "/var/www/mydjango"
      python_binary: "python3"
      manage_timeout: "60s"

# Target servers
servers:
  - name: web-01
    host: "10.0.1.10"
    port: 22
    user: "ai-agent"
    key_path: "/etc/opsfix/keys/web-01_ed25519"
    tags: ["web", "production"]
    # Per-server rate limit override
    rate_limit:
      requests_per_second: 1.0
      burst: 5

  - name: web-01-via-bastion
    host: "10.0.1.10"
    port: 22
    user: "ai-agent"
    key_path: "/etc/opsfix/keys/web-01_ed25519"
    tags: ["web", "production"]
    bastion:
      host: "bastion.example.com"
      port: 22
      user: "jumpuser"
      key_path: "/etc/opsfix/keys/bastion_ed25519"

  - name: worker-01
    host: "10.0.1.11"
    port: 22
    user: "ai-agent"
    key_path: "/etc/opsfix/keys/worker-01_ed25519"
    tags: ["worker", "production"]

  - name: k8s-master
    host: "10.0.2.10"
    port: 22
    user: "ai-agent"
    key_path: "/etc/opsfix/keys/k8s_ed25519"
    tags: ["kubernetes", "production"]
```

### Policy Schema

```yaml
# policy.yaml — full schema
version: "1"

defaults:
  require_approval_at: medium   # low | medium | high | critical
  block_at: critical

rules:
  # Format: tool glob patterns supported ("laravel_*")
  - name: block-db-destruction
    tool: "laravel_artisan"
    block: true
    conditions:
      - field: command
        matches: "^migrate:fresh|^db:wipe|^migrate:reset"

  - name: block-celery-purge-production
    tool: "celery_purge"
    block: true
    conditions:
      - field: server_tag
        matches: "production"

  - name: deploy-production-high
    tool: "*_deploy"          # matches any adapter's deploy tool
    risk: high
    conditions:
      - field: branch
        matches: "^main$|^master$|^production$"

  - name: restart-web-medium
    tool: "service_restart"
    risk: medium
    conditions:
      - field: service
        matches: "^nginx$|^php.*-fpm$"

  - name: k8s-rollout-high
    tool: "k8s_rollout_restart"
    risk: high

  # Read-only tools: always auto-allowed (risk: low implied)
  - name: allow-all-reads
    tool: "*_status"
    risk: low

  - name: allow-all-health
    tool: "*_health"
    risk: low
```

---

## 7. Observability

### 7.1 Structured Logging

All internal logs go to **stderr** (JSON format in production, human-readable in dev):

```go
// Log levels: DEBUG, INFO, WARN, ERROR, CRITICAL
// Format: {"level":"INFO","ts":"2026-03-08T10:00:00Z","msg":"tool call","tool":"service_restart","server":"web-01"}
```

### 7.2 Metrics (Prometheus)

Exposed on a Unix domain socket (`/run/opsfix/metrics.sock`) — not a TCP port:

```
opsfix_tool_calls_total{tool, server, adapter, decision}  counter
opsfix_tool_duration_seconds{tool, adapter}                histogram
opsfix_ssh_connections_active{server}                      gauge
opsfix_ssh_reconnects_total{server}                        counter
opsfix_policy_decisions_total{tool, decision, risk}        counter
opsfix_rate_limit_rejections_total{server}                 counter
opsfix_adapter_panics_total{adapter}                       counter
opsfix_audit_write_errors_total                            counter
```

### 7.3 Self-Health Endpoint

Unix socket at `/run/opsfix/health.sock`:

```json
GET /health → 200 OK
{
  "status": "healthy",  // "healthy" | "degraded" | "unhealthy"
  "policy": {"status": "healthy", "rules": 12},
  "audit": {"status": "healthy", "free_bytes": 10737418240},
  "adapters": [
    {"id": "laravel", "status": "healthy"},
    {"id": "systemd", "status": "healthy"}
  ],
  "ssh_pool": {"connections": 2, "healthy": 2}
}
```

`unhealthy` if policy or audit subsystem is broken (all mutating operations blocked). `degraded` if an adapter fails to initialize.

### 7.4 SIGHUP Config Reload

On receiving `SIGHUP`:
1. Re-read `config.yaml` and `policy.yaml`
2. Validate new config before applying
3. Apply policy changes atomically (swap engine pointer under RWMutex)
4. Log reload result; do NOT kill in-flight operations

---

## 8. Edge Cases

### 8.1 SSH & Connectivity

| Edge Case | Detection | Handling |
|---|---|---|
| SSH connect timeout | `net.DialTimeout` error | Return `{"error":"ssh_timeout","retry":true}` to AI |
| SSH key rejected (auth failure) | `gossh.HandshakeError` | Return `{"error":"ssh_auth_failed"}`; do NOT retry (lockout risk) |
| Host key mismatch | `knownhosts` callback error | Return `{"error":"ssh_host_key_mismatch"}`; log CRITICAL; never auto-accept |
| Server unreachable | `net.OpError EHOSTUNREACH` | Return `{"error":"ssh_unreachable"}`; rate-limit retries |
| SSH disconnects mid-command | `io.EOF` on session read | Return `{"error":"ssh_disconnected_mid_exec","partial_output":"...","output_complete":false}` |
| Key file missing at startup | `os.Stat` error | Fatal at startup with clear message; never silently skip |
| Key file too-open permissions | `mode & 0o044 != 0` | Fatal at startup; log exact permissions found |
| Bastion unreachable | Dial bastion fails | Return `{"error":"bastion_unreachable","bastion":"..."}`; pool entry marked unhealthy |

### 8.2 Command Execution

| Edge Case | Detection | Handling |
|---|---|---|
| Command not in adapter allowlist | Executor allowlist check | Return `{"error":"command_not_allowed"}`; log CRITICAL (potential injection attempt) |
| Command times out | `context.WithTimeout` | Kill SSH session; return `{"error":"command_timeout","timeout_seconds":120}` |
| Command exits non-zero | `ssh.ExitError` | Return output + exit code; adapter decides if this is an error |
| Command produces no output | Empty stdout | Return empty output; not an error |
| Command output too large | Byte counter | Truncate at `max_output_bytes`; append `[TRUNCATED]` marker |
| Target has wrong OS (busybox) | Command not found | Return stderr as error message; adapter should check binary existence |
| journalctl not available | `command not found` in stderr | Detect and suggest using file log path instead |
| supervisorctl not available | `command not found` | Return `{"error":"supervisorctl_not_found"}`; suggest Docker/systemd alternative |

### 8.3 Partial Operations (Deploy)

| Edge Case | Handling |
|---|---|
| Composer succeeds, `migrate` fails | Return `{"error":"deploy_partial","last_successful_step":"composer","failed_step":"migrate","output":"..."}` |
| Git pull fails (conflict) | Stop immediately; do not proceed to next step; report conflict details |
| Disk full during deploy | Detect pre-flight; if it happens mid-deploy, report with `disk_full: true` |
| Deploy: rollback strategy | Adapter stores pre-deploy git SHA; on failure, `git checkout $sha` + `php artisan config:cache` |
| Concurrent deploys to same server | Deploy lock per server; second caller gets `{"error":"deploy_in_progress"}` |

### 8.4 Policy & Config

| Edge Case | Handling |
|---|---|
| Policy file missing at startup | Fatal; clear error message |
| Policy file malformed YAML | Fatal; print parse error with line number |
| Policy file missing during SIGHUP reload | Keep existing policy; log ERROR |
| Config references unknown adapter | Fatal at startup with adapter name |
| Config references nonexistent server in rule | Log WARN; rule still loaded (server may appear later) |
| Adapter declares conflicting tool name | Registration panic with both adapter IDs; caught in integration tests |

### 8.5 Concurrent AI Requests

| Edge Case | Handling |
|---|---|
| Two concurrent reads to same server | Allowed; SSH pool serializes at session level |
| Two concurrent mutations to same server | Global deploy lock; second waits up to `queue_timeout` |
| AI sends 100 calls in 1 second | Token bucket exhausted; return `{"error":"rate_limited","retry_after_ms":500}` |
| Plugin adapter panics | `defer recover()` in dispatch; log stack trace; return `{"error":"adapter_panic","adapter":"laravel"}`; increment metric |

### 8.6 MCP Protocol

| Edge Case | Handling |
|---|---|
| AI sends malformed JSON-RPC | Return `{"error":{"code":-32700,"message":"Parse error"}}` |
| AI sends unknown method | Return `{"error":{"code":-32601,"message":"Method not found"}}` |
| AI sends wrong param types | JSON schema validation; return `{"error":{"code":-32602,"data":{"field":"service","expected":"string"}}}` |
| AI sends oversized params | Reject before parsing if content-length > 1MB |
| MCP client disconnects mid-operation | Context cancelled; SSH command killed; partial result written to audit log |
| AI sends `tools/list` with no adapters | Return empty tools array; log WARN |

### 8.7 Audit Log

| Edge Case | Handling |
|---|---|
| Audit disk full | Log to stderr; block ALL mutating operations (fail-safe); return `{"error":"audit_unavailable"}` |
| HMAC key missing | Log WARN; write entries without HMAC; mark entries with `"hmac":"disabled"` |
| Log file deleted externally | Re-open on next write; HMAC chain breaks at that point (detectable) |
| Clock skew | Use monotonic clock for duration; use `time.UTC()` for timestamps; accept skew in verification tool |

---

## 9. Testing Strategy

### 9.1 Unit Tests (Security-Critical Paths)

| Test | Location | What to test |
|---|---|---|
| Policy engine | `internal/policy/engine_test.go` | Block rules, risk thresholds, condition matching, conflict resolution, default-deny |
| Secret redactor | `internal/secret/redactor_test.go` | All built-in patterns, literal redaction, edge cases (empty string, no secrets) |
| SSH executor allowlist | `internal/ssh/executor_test.go` | Allowed commands pass, disallowed commands error, injection strings rejected |
| Key permission check | `internal/ssh/keymgr_test.go` | 0600 ok, 0644 fail, 0400 ok, 0640 fail |
| HMAC audit chain | `internal/audit/logger_test.go` | Chain verifies, single entry tampered breaks chain, missing key degrades gracefully |
| Rate limiter | `internal/ratelimit/limiter_test.go` | Burst allowed, steady rate enforced, per-server isolation |
| Path traversal guard | `internal/ssh/executor_test.go` | `../` rejected, allowed prefixes pass, absolute path outside prefix rejected |
| Adapter registry | `adapter/registry_test.go` | Duplicate ID panics, version mismatch panics, tool collision detected |

### 9.2 Integration Tests

```go
// test/integration/ — uses an in-process SSH server (golang.org/x/crypto/ssh test helpers)
// Never hits real infrastructure

TestScanServer_Success
TestScanServer_SSHTimeout
TestRestartService_RequiresApproval
TestRestartService_ConfirmedExecutes
TestRestartService_BlockedByPolicy
TestDeploy_PartialFailureReportsStep
TestRateLimit_ExcessiveRequests
TestAuditLog_AllEventsWritten
TestAuditLog_HMACChainValid
TestPlugin_PanicRecovered
```

### 9.3 Adapter Testing Convention

Each adapter must include:
```
adapter/community/laravel/
  laravel.go
  laravel_test.go       # unit tests with mock ssh.Executor
  manifest.yaml
  testdata/
    commands.yaml       # expected commands for each tool
```

Mock `ssh.Executor` records all calls and verifies:
- Only declared `remote_commands` are called
- Arguments contain no shell metacharacters
- No calls are made outside the allowlist

---

## 10. Deployment

### 10.1 Recommended Topology

```
┌─────────────────────────────────┐
│   Management Network (private)   │
│                                  │
│  ┌──────────────┐               │
│  │ Opsfix host  │ ←── Claude Code (stdio)
│  │ (bastion)    │               │
│  └──────┬───────┘               │
│         │ SSH (port 22)          │
│   ┌─────┴──────┬─────────┐      │
│   ▼            ▼         ▼      │
│ web-01      worker-01  db-01    │
└─────────────────────────────────┘
          ↑ No public IP on target servers
```

### 10.2 Systemd Unit (for Opsfix host)

```ini
# /etc/systemd/system/opsfix.service
[Unit]
Description=Opsfix MCP Server
After=network.target

[Service]
Type=simple
User=opsfix
Group=opsfix
ExecStart=/usr/local/bin/opsfix
Environment=OPSFIX_CONFIG=/etc/opsfix/config.yaml
Environment=OPSFIX_AUDIT_HMAC_KEY_FILE=/etc/opsfix/audit_hmac.key
# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/log/opsfix /run/opsfix
ProtectHome=true
CapabilityBoundingSet=
AmbientCapabilities=
# Resource limits
LimitNOFILE=1024
MemoryMax=256M

[Install]
WantedBy=multi-user.target
```

### 10.3 Docker Image

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o opsfix ./cmd/opsfix

FROM scratch
COPY --from=builder /build/opsfix /opsfix
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
ENTRYPOINT ["/opsfix"]
```

### 10.4 `.claude/mcp.json` Registration

```json
{
  "mcpServers": {
    "opsfix": {
      "command": "/usr/local/bin/opsfix",
      "env": {
        "OPSFIX_CONFIG": "/etc/opsfix/config.yaml"
      }
    }
  }
}
```

---

## 11. Migration Plan

### Phase 1 — Internal Refactor (no behavior change)

1. Move `config/`, `policy/`, `audit/`, `ssh/` → `internal/` (unexported from module)
2. Create `adapter/adapter.go` with `Adapter` interface
3. Extract `scanner` → `adapter/builtin/systemd` + `adapter/builtin/resources`
4. Extract `executor` → `adapter/builtin/supervisor` + command builders
5. Replace `mcp-server/dispatcher.go` with `internal/dispatch/dispatch.go` using registry
6. Verify: `go build ./...` passes; behavior identical

### Phase 2 — Security Hardening

1. Add key permission validation to `internal/ssh/keymgr.go`
2. Add `known_hosts` enforcement (fatal in non-dev mode)
3. Add secret redaction pipeline
4. Add HMAC chain to audit logger
5. Add rate limiter (`internal/ratelimit/`)
6. Add global deploy concurrency lock
7. Add parameter allowlist validation in `ssh.Executor`

### Phase 3 — Community Adapters

In order of demand:
1. `laravel` (migrate existing code to adapter interface)
2. `django`
3. `rails`
4. `nodejs` (PM2)
5. `docker`
6. `kubernetes`
7. `celery`, `sidekiq`, `nginx`, `fastapi`

### Phase 4 — Observability & Polish

1. Prometheus metrics on Unix socket
2. Self-health endpoint
3. SIGHUP config reload
4. Docker image + systemd unit
5. `opsfix verify-audit` CLI subcommand
6. `opsfix rotate-key` CLI subcommand
7. Documentation site

---

## Appendix A — Security Checklist (Pre-Production)

- [ ] SSH keys: 0600 permissions, dedicated per-server keys
- [ ] `known_hosts_file` configured (no `InsecureIgnoreHostKey`)
- [ ] `OPSFIX_AUDIT_HMAC_KEY` set
- [ ] Audit log on separate disk from OS
- [ ] `ai-agent` user created with minimal sudoers
- [ ] Target servers: `PasswordAuthentication no`, `PermitRootLogin no`
- [ ] Opsfix host firewall: only port 22 outbound to specific IPs
- [ ] Policy: all production deploy tools require confirmation
- [ ] Policy: all data-destructive commands blocked
- [ ] Rate limits configured per environment
- [ ] Binary signed and `go mod verify` passes in CI

---

*This document is the authoritative design reference for Opsfix v2. Implementation should follow the migration plan in Phase order.*
