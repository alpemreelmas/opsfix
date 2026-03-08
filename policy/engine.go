package policy

import (
	"fmt"
	"regexp"
)

var riskOrder = map[RiskLevel]int{
	RiskLow:      1,
	RiskMedium:   2,
	RiskHigh:     3,
	RiskCritical: 4,
}

type Engine struct {
	pf *PolicyFile
}

func NewEngine(pf *PolicyFile) *Engine {
	return &Engine{pf: pf}
}

func (e *Engine) Evaluate(tool string, params map[string]any) Decision {
	for _, rule := range e.pf.Rules {
		if rule.Tool != tool && rule.Tool != "*" {
			continue
		}

		if !matchConditions(rule.Conditions, params) {
			continue
		}

		// First matching rule wins
		if rule.Block {
			return Decision{
				Allowed: false,
				Blocked: true,
				Risk:    RiskCritical,
				Reason:  fmt.Sprintf("blocked by rule %q", rule.Name),
			}
		}

		risk := rule.Risk
		if risk == "" {
			risk = RiskLow
		}

		requiresApproval := riskOrder[risk] >= riskOrder[e.pf.Defaults.RequireApprovalAt]
		blocked := riskOrder[risk] >= riskOrder[e.pf.Defaults.BlockAt]

		if blocked {
			return Decision{
				Allowed: false,
				Blocked: true,
				Risk:    risk,
				Reason:  fmt.Sprintf("risk level %q meets block threshold", risk),
			}
		}

		return Decision{
			Allowed:          true,
			Risk:             risk,
			RequiresApproval: requiresApproval,
			Reason:           fmt.Sprintf("matched rule %q", rule.Name),
		}
	}

	// No matching rule - apply defaults
	return Decision{
		Allowed:          true,
		Risk:             RiskLow,
		RequiresApproval: false,
		Reason:           "no matching rule; default allow",
	}
}

func (e *Engine) IsArtisanAllowed(command string) bool {
	for _, allowed := range e.pf.ArtisanAllowlist {
		if allowed == command {
			return true
		}
	}
	return false
}

func matchConditions(conditions []Condition, params map[string]any) bool {
	for _, c := range conditions {
		val, ok := params[c.Field]
		if !ok {
			return false
		}

		str := fmt.Sprintf("%v", val)
		matched, err := regexp.MatchString(c.Matches, str)
		if err != nil || !matched {
			return false
		}
	}
	return true
}
