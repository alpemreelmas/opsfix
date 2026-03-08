package config

import "time"

type Config struct {
	Version    string         `yaml:"version"`
	PolicyFile string         `yaml:"policy_file"`
	Audit      AuditConfig    `yaml:"audit"`
	SSH        SSHConfig      `yaml:"ssh"`
	Servers    []ServerConfig `yaml:"servers"`
}

type ServerConfig struct {
	Name    string   `yaml:"name"`
	Host    string   `yaml:"host"`
	Port    int      `yaml:"port"`
	User    string   `yaml:"user"`
	KeyPath string   `yaml:"key_path"`
	Tags    []string `yaml:"tags"`
}

type AuditConfig struct {
	Enabled  bool   `yaml:"enabled"`
	FilePath string `yaml:"file_path"`
}

type SSHConfig struct {
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
	KnownHostsFile string        `yaml:"known_hosts_file"`
}
