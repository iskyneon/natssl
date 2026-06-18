package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const systemRootCAPath = "/usr/local/share/ca-certificates/natssl-root.crt"

// InstallRootCA: импорт в системное хранилище + Firefox.
func InstallRootCA(pemBytes []byte) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("root privileges required to install CA")
	}
	if err := os.WriteFile(systemRootCAPath, pemBytes, 0o644); err != nil {
		return err
	}
	if err := exec.Command("update-ca-certificates").Run(); err != nil {
		// RHEL/CentOS/Rocky: иной путь и команда
		_ = os.WriteFile("/etc/pki/ca-trust/source/anchors/natssl-root.crt", pemBytes, 0o644)
		if err2 := exec.Command("update-ca-trust", "extract").Run(); err2 != nil {
			return fmt.Errorf("update-ca-certificates: %v; update-ca-trust: %v", err, err2)
		}
	}
	if err := installIntoFirefox(); err != nil {
		fmt.Printf("[natssl] WARN firefox: %v\n", err)
	}
	return nil
}

// installIntoFirefox: ищет профили и внедряет Root CA через certutil.
func installIntoFirefox() error {
	if _, err := exec.LookPath("certutil"); err != nil {
		return fmt.Errorf("certutil (libnss3-tools) not installed")
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
				"-i", systemRootCAPath,
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
	dirs = append(dirs, "/root")
	return dirs
}

func LoadInstalledRootCA() (*x509.Certificate, error) {
	b, err := os.ReadFile(systemRootCAPath)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("installed Root CA is not valid PEM")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func init() { _ = strings.TrimSpace } // keep import
