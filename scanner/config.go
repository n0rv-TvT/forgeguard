package scanner

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the ForgeGuard configuration file (.forgeguard.yml)
type Config struct {
	IgnorePaths       []string          `yaml:"ignore_paths"`
	DisableRules      []string          `yaml:"disable_rules"`
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
}

// LoadConfig reads and parses the configuration file
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
