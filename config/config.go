package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	setDefaults(&cfg)
	return &cfg, validate(&cfg)
}

func setDefaults(cfg *Config) {
	if cfg.SSH.IdleTimeout == 0 {
		cfg.SSH.IdleTimeout = 5 * time.Minute
	}
	if cfg.SSH.ConnectTimeout == 0 {
		cfg.SSH.ConnectTimeout = 10 * time.Second
	}
	for i := range cfg.Servers {
		if cfg.Servers[i].Port == 0 {
			cfg.Servers[i].Port = 22
		}
	}
}

func validate(cfg *Config) error {
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("config: no servers defined")
	}
	names := make(map[string]bool)
	for _, s := range cfg.Servers {
		if s.Name == "" {
			return fmt.Errorf("config: server missing name")
		}
		if s.Host == "" {
			return fmt.Errorf("config: server %q missing host", s.Name)
		}
		if s.User == "" {
			return fmt.Errorf("config: server %q missing user", s.Name)
		}
		if s.KeyPath == "" {
			return fmt.Errorf("config: server %q missing key_path", s.Name)
		}
		if names[s.Name] {
			return fmt.Errorf("config: duplicate server name %q", s.Name)
		}
		names[s.Name] = true
	}
	return nil
}
