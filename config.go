package main

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Listen struct {
	ACME string `yaml:"acme"` // :443
	Mgmt string `yaml:"mgmt"` // :8443
}

type Config struct {
	path string `yaml:"-"`

	Mode    string `yaml:"mode"`
	DataDir string `yaml:"data_dir"`
	Listen  Listen `yaml:"listen"`

	// Адрес мастера (для клиентов и для проверки старого УЦ при promote).
	MasterAddress string `yaml:"master_address"`

	// Публичный recovery-ключ (base64). Раздаётся всем клиентам.
	RecoveryPublicKey string `yaml:"recovery_public_key"`

	// Известные клиенты (жёстко заданные IP/DNS — без mDNS).
	Clients []string `yaml:"clients"`

	PullInterval time.Duration `yaml:"pull_interval"` // 1h
	PingInterval time.Duration `yaml:"ping_interval"` // 5m
}

func DefaultConfig() *Config {
	return &Config{
		Mode:         "master",
		DataDir:      "/var/lib/natssl",
		Listen:       Listen{ACME: ":443", Mgmt: ":8443"},
		PullInterval: time.Hour,
		PingInterval: 5 * time.Minute,
	}
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := DefaultConfig()
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, err
	}
	c.path = path
	if c.PullInterval == 0 {
		c.PullInterval = time.Hour
	}
	if c.PingInterval == 0 {
		c.PingInterval = 5 * time.Minute
	}
	return c, nil
}

func (c *Config) Save() error {
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, b, 0o644)
}

// Пути к артефактам.
func (c *Config) caCertPath() string  { return filepath.Join(c.DataDir, "root-ca.crt") }
func (c *Config) caKeyPath() string   { return filepath.Join(c.DataDir, "root-ca.key") }
func (c *Config) dbPath() string      { return filepath.Join(c.DataDir, "natssl.db") }
func (c *Config) cachePath() string   { return filepath.Join(c.DataDir, "network-cache.enc") }
func (c *Config) issuedDir() string   { return filepath.Join(c.DataDir, "issued") }
