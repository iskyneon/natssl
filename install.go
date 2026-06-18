package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	debianRootCAPath = "/usr/local/share/ca-certificates/natssl-root.crt"
	rhelRootCAPath   = "/etc/pki/ca-trust/source/anchors/natssl-root.crt"
)

// InstallRootCAIntoOS installs the Root CA (read from certPath) into the system
// trust store (Debian/Ubuntu and RHEL/Rocky/CentOS).
func InstallRootCAIntoOS(certPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required to install CA into the OS trust store")
	}
	pemBytes, err := os.ReadFile(certPath)
	if err != nil {
		return err
	}
	// Debian/Ubuntu first.
	if err := os.WriteFile(debianRootCAPath, pemBytes, 0o644); err == nil {
		if err := exec.Command("update-ca-certificates").Run(); err == nil {
			return nil
		}
	}
	// RHEL family fallback.
	if err := os.WriteFile(rhelRootCAPath, pemBytes, 0o644); err != nil {
		return fmt.Errorf("write RHEL anchor: %w", err)
	}
	if err := exec.Command("update-ca-trust", "extract").Run(); err != nil {
		return fmt.Errorf("update-ca-trust: %w", err)
	}
	return nil
}

// InstallRootCAIntoFirefox imports the Root CA into every discovered Firefox
// profile via certutil (libnss3-tools / nss-tools).
func InstallRootCAIntoFirefox(certPath string) error {
	if _, err := exec.LookPath("certutil"); err != nil {
		return fmt.Errorf("certutil (libnss3-tools/nss-tools) not installed")
	}
	var roots []string
	for _, h := range homeDirs() {
		roots = append(roots,
			filepath.Join(h, ".mozilla", "firefox"),
			filepath.Join(h, "snap", "firefox", "common", ".mozilla", "firefox"),
		)
	}
	installed := 0
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			profile := filepath.Join(root, e.Name())
			if _, err := os.Stat(filepath.Join(profile, "cert9.db")); err != nil {
				continue
			}
			cmd := exec.Command("certutil", "-A",
				"-n", "NATSSL Private Root CA",
				"-t", "CT,C,C",
				"-i", certPath,
				"-d", "sql:"+profile,
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				fmt.Printf("[natssl] firefox profile %s: %s\n", profile, string(out))
			} else {
				installed++
			}
		}
	}
	fmt.Printf("[natssl] firefox profiles updated: %d\n", installed)
	return nil
}

func homeDirs() []string {
	var dirs []string
	if entries, err := os.ReadDir("/home"); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				dirs = append(dirs, filepath.Join("/home", e.Name()))
			}
		}
	}
	return append(dirs, "/root")
}

func LoadInstalledRootCA() (*x509.Certificate, error) {
	b, err := os.ReadFile(debianRootCAPath)
	if err != nil {
		b, err = os.ReadFile(rhelRootCAPath)
		if err != nil {
			return nil, err
		}
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("installed Root CA is not valid PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}
