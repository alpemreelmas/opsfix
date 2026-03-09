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
