package policy

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type Decision struct {
	Allowed          bool
	Risk             RiskLevel
	RequiresApproval bool
	Blocked          bool
	Reason           string
}

type Condition struct {
	Field   string `yaml:"field"`
	Matches string `yaml:"matches"`
}

type Rule struct {
	Name       string      `yaml:"name"`
	Tool       string      `yaml:"tool"`
	Risk       RiskLevel   `yaml:"risk"`
	Block      bool        `yaml:"block"`
	Conditions []Condition `yaml:"conditions"`
}

type Defaults struct {
	RequireApprovalAt RiskLevel `yaml:"require_approval_at"`
	BlockAt           RiskLevel `yaml:"block_at"`
}

type PolicyFile struct {
	Version        string   `yaml:"version"`
	Defaults       Defaults `yaml:"defaults"`
	Rules          []Rule   `yaml:"rules"`
	ArtisanAllowlist []string `yaml:"artisan_allowlist"`
}
