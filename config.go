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
	InstallTrust      bool          `yaml:"install_trust"`          // install OS/Firefox trust anchors (native default true)
	Mode              string        `yaml:"mode"`                   // master | client
	DataDir           string        `yaml:"data_dir"`               // /var/lib/natssl
	Listen            Listen        `yaml:"listen"`                 // ports
	ServerNames       []string      `yaml:"server_names,omitempty"` // extra DNS names in the server leaf
	LastMigration     time.Time     `yaml:"last_migration,omitempty"`
	MasterMgmtAddress string        `yaml:"master_mgmt_address,omitempty"` // optional control address, defaults to master host:8443
	MasterAddress     string        `yaml:"master_address"`                // client -> master host/IP
	MasterFingerprint string        `yaml:"master_fingerprint"`            // client: SHA-256 of master Root CA (pinning)
	RecoveryPublicKey string        `yaml:"recovery_public_key"`           // base64, auto-filled on bootstrap
	EnrollmentToken   string        `yaml:"enrollment_token"`              // shared secret for /acme/register
	ClientNetworks    []string      `yaml:"client_networks"`               // master: CIDRs allowed to self-register
	Clients           []string      `yaml:"clients"`                       // optional initial registered client IPs
	PullInterval      time.Duration `yaml:"pull_interval"`                 // cache pull cadence
	PingInterval      time.Duration `yaml:"ping_interval"`                 // master health-check cadence

	path string `yaml:"-"` // source file path (not serialized)
}

// DefaultConfig returns a config with safe defaults.
func DefaultConfig() *Config {
	return &Config{
		Mode:         "master",
		InstallTrust: true,
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
	return atomicWriteFile(c.path, b, 0o600)
}

// ClientAllowed reports whether a peer IP is permitted to self-register.
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
func (c *Config) crlPath() string    { return filepath.Join(c.DataDir, "root-ca.crl") }
func (c *Config) issuedDir() string  { return filepath.Join(c.DataDir, "issued") }

func (c *Config) identityCertPath() string { return filepath.Join(c.DataDir, "client-identity.crt") }
func (c *Config) identityKeyPath() string  { return filepath.Join(c.DataDir, "client-identity.key") }

// Preserve an explicit bootstrap port and correctly bracket IPv6 addresses.
func (c *Config) masterURL(control bool, path string) string {
	addr := c.MasterAddress
	port := "443"
	if control {
		addr = c.MasterMgmtAddress
		if addr == "" {
			addr = host(c.MasterAddress)
		}
		port = "8443"
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(host(addr), port)
	}
	return "https://" + addr + path
}
