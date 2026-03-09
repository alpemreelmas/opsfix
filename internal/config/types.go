package config

import "time"

type Config struct {
	Version    string          `yaml:"version"`
	PolicyFile string          `yaml:"policy_file"`
	Audit      AuditConfig     `yaml:"audit"`
	SSH        SSHConfig       `yaml:"ssh"`
	RateLimit  RateLimitConfig `yaml:"rate_limit"`
	Servers    []ServerConfig  `yaml:"servers"`
	Adapters   []AdapterConfig `yaml:"adapters"`
}

type AuditConfig struct {
	Enabled           bool   `yaml:"enabled"`
	FilePath          string `yaml:"file_path"`
	HMACKeyEnv        string `yaml:"hmac_key_env"`
	RedactLiteralsEnv string `yaml:"redact_literals_env"`
	MaxOutputBytes    int    `yaml:"max_output_bytes"`
}

type SSHConfig struct {
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	CommandTimeout time.Duration `yaml:"command_timeout"`
	KnownHostsFile string        `yaml:"known_hosts_file"`
}

type RateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

type ServerConfig struct {
	Name    string         `yaml:"name"`
	Host    string         `yaml:"host"`
	Port    int            `yaml:"port"`
	User    string         `yaml:"user"`
	KeyPath string         `yaml:"key_path"`
	Tags    []string       `yaml:"tags"`
	Bastion *BastionConfig `yaml:"bastion"`
}

type BastionConfig struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	User    string `yaml:"user"`
	KeyPath string `yaml:"key_path"`
}

type AdapterConfig struct {
	ID     string         `yaml:"id"`
	Config map[string]any `yaml:"config"`
}
