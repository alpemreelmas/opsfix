package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*PolicyFile, error) {
	if path == "" {
		return &PolicyFile{
			Defaults: Defaults{
				RequireApprovalAt: RiskMedium,
				BlockAt:           RiskCritical,
			},
		}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %q: %w", path, err)
	}

	var pf PolicyFile
	if err := yaml.Unmarshal(data, &pf); err != nil {
		return nil, fmt.Errorf("policy: parse %q: %w", path, err)
	}

	if pf.Defaults.RequireApprovalAt == "" {
		pf.Defaults.RequireApprovalAt = RiskMedium
	}
	if pf.Defaults.BlockAt == "" {
		pf.Defaults.BlockAt = RiskCritical
	}

	return &pf, nil
}
