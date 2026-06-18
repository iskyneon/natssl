package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Listen holds the two listening sockets used by the master.
type Listen struct {
	ACME string `yaml:"acme"` // ACME-style issuance API, e.g. ":443"
	Mgmt string `yaml:"mgmt"` // mTLS management/sync, e.g. ":8443"
}

// Config is the on-disk configuration shared by master and client modes.
type Config struct {
	Mode              string        `yaml:"mode"`                // master | client
	DataDir           string        `yaml:"data_dir"`            // /var/lib/natssl
	Listen            Listen        `yaml:"listen"`              // ports
	MasterAddress     string        `yaml:"master_address"`      // client -> master host/IP
	RecoveryPublicKey string        `yaml:"recovery_public_key"` // base64, auto-filled on bootstrap
	ClientNetworks    []string      `yaml:"client_networks"`     // master: CIDRs allowed to self-register
	Clients           []string      `yaml:"clients"`             // optional static push targets (fallback)
	PullInterval      time.Duration `yaml:"pull_interval"`       // cache pull/push cadence
	PingInterval      time.Duration `yaml:"ping_interval"`       // master health-check cadence

	path string `yaml:"-"` // source file path (not serialized)
}

// DefaultConfig returns a config with safe defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode:         "master",
		DataDir:      "/var/lib/natssl",
		Listen:       Listen{ACME: ":443", Mgmt: ":8443"},
		PullInterval: time.Hour,
		PingInterval: 5 * time.Minute,
	}
}

// LoadConfig reads and validates the YAML config at path.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := DefaultConfig()
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	c.path = path

	if c.DataDir == "" {
		c.DataDir = "/var/lib/natssl"
	}
	if c.Listen.ACME == "" {
		c.Listen.ACME = ":443"
	}
	if c.Listen.Mgmt == "" {
		c.Listen.Mgmt = ":8443"
	}
	if c.PullInterval <= 0 {
		c.PullInterval = time.Hour
	}
	if c.PingInterval <= 0 {
		c.PingInterval = 5 * time.Minute
	}

	// Validate CIDRs early so misconfiguration fails loudly on the master.
	for _, cidr := range c.ClientNetworks {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return nil, fmt.Errorf("invalid client_networks entry %q: %w", cidr, err)
		}
	}
	return c, nil
}

// Save writes the config back to its source path (creating parent dirs).
func (c *Config) Save() error {
	if c.path == "" {
		c.path = "/etc/natssl/config.yaml"
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	b, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, b, 0o644)
}

// ClientAllowed reports whether a peer IP is permitted to self-register.
// A peer is allowed if its IP falls inside any configured client_networks CIDR.
func (c *Config) ClientAllowed(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range c.ClientNetworks {
		if _, n, err := net.ParseCIDR(cidr); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// --- derived paths -------------------------------------------------------

func (c *Config) caCertPath() string { return filepath.Join(c.DataDir, "root-ca.crt") }
func (c *Config) caKeyPath() string  { return filepath.Join(c.DataDir, "root-ca.key") }
func (c *Config) dbPath() string     { return filepath.Join(c.DataDir, "natssl.db") }
func (c *Config) cachePath() string  { return filepath.Join(c.DataDir, "network-cache.enc") }
func (c *Config) issuedDir() string  { return filepath.Join(c.DataDir, "issued") }
