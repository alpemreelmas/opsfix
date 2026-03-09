package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}

	// Set defaults
	if cfg.SSH.IdleTimeout == 0 {
		cfg.SSH.IdleTimeout = 300e9 // 5 minutes
	}
	if cfg.SSH.ConnectTimeout == 0 {
		cfg.SSH.ConnectTimeout = 10e9 // 10 seconds
	}
	if cfg.SSH.CommandTimeout == 0 {
		cfg.SSH.CommandTimeout = 30e9 // 30 seconds
	}

	for i := range cfg.Servers {
		if cfg.Servers[i].Port == 0 {
			cfg.Servers[i].Port = 22
		}
	}

	return &cfg, nil
}
