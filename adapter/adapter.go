package adapter

// InterfaceVersion must be incremented when breaking changes are made.
const InterfaceVersion = 2

// Adapter is the contract every platform adapter must implement.
type Adapter interface {
	ID() string
	InterfaceVersion() int
	Tools() []ToolDefinition
	Execute(tool string, params Params, exec SSHExecutor) (Result, error)
	DefaultPolicyRules() []PolicyRule
	// PreFlight runs before execution for mutating tools. Returns a report
	// describing current state, the execution plan, and any blockers.
	PreFlight(tool string, params Params, exec SSHExecutor) (PreFlightReport, error)
	// Verify runs after execution for mutating tools. Returns success/failure
	// and the new observed state.
	Verify(tool string, params Params, result Result, exec SSHExecutor) (VerifyReport, error)
	// Probe checks which binaries/capabilities are available on the target server.
	Probe(exec SSHExecutor) CapabilitySet
}

type Params map[string]any

type Result struct {
	Output   string
	ExitCode int
	Metadata map[string]any
}

type ToolDefinition struct {
	Name        string
	Description string
	InputSchema map[string]any
	ReadOnly    bool
}

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

// SSHExecutor is the ONLY way adapters may run remote commands.
// Adapters must not use os/exec or net.Dial.
type SSHExecutor interface {
	Run(cmd string, args ...string) (ExecResult, error)
	ReadFile(path string) ([]byte, error)
}

type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// PreFlightReport is returned by Adapter.PreFlight before execution.
type PreFlightReport struct {
	CurrentState map[string]any // e.g. git_sha, disk_free_gb, service_status
	Plan         []string       // human-readable steps that will execute
	RollbackInfo map[string]any // info needed to rollback (e.g. {"git_sha": "abc123"})
	Warnings     []string       // non-blocking warnings ("disk only 2GB free")
	Blocker      string         // if non-empty, blocks execution with this reason
}

// VerifyReport is returned by Adapter.Verify after execution.
type VerifyReport struct {
	Success    bool
	NewState   map[string]any
	RolledBack bool
	Error      string
}

// CapabilitySet describes what binaries/tools are available on a target server.
type CapabilitySet struct {
	AdapterID   string
	Available   map[string]string // binary -> resolved path or version
	Unavailable []string
	Fallbacks   map[string]string // binary -> fallback command
}
