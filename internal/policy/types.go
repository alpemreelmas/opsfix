package policy

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

type PolicyFile struct {
	Version          string   `yaml:"version"`
	ArtisanAllowlist []string `yaml:"artisan_allowlist"`
	Defaults         Defaults `yaml:"defaults"`
	Rules            []Rule   `yaml:"rules"`
}

type Defaults struct {
	RequireApprovalAt RiskLevel `yaml:"require_approval_at"`
	BlockAt           RiskLevel `yaml:"block_at"`
}

type Rule struct {
	Name       string      `yaml:"name"`
	Tool       string      `yaml:"tool"`
	Risk       RiskLevel   `yaml:"risk"`
	Block      bool        `yaml:"block"`
	Conditions []Condition `yaml:"conditions"`
}

type Condition struct {
	Field   string `yaml:"field"`
	Matches string `yaml:"matches"`
}

type Decision struct {
	Allowed          bool
	Blocked          bool
	Risk             RiskLevel
	RequiresApproval bool
	Reason           string
}
