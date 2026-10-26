//go:build !masteronly

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestMasterOnlyBinary(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "natssl-master")
	build := exec.Command("go", "build", "-tags=masteronly", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("master build: %v\n%s", err, out)
	}
	for _, args := range [][]string{
		{"--mode=client"}, {"--mode", "client"}, {"-mode=client"},
		{"--promote-to-master"}, {"--mode=master", "--promote-to-master"},
		{"--decrypt-key=/tmp/unused.key.enc"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, err := exec.Command(binary, args...).CombinedOutput()
			if err == nil || !strings.Contains(string(out), "master-only build") {
				t.Fatalf("client operation not rejected: %v %s", err, out)
			}
		})
	}
	dir := t.TempDir()
	config := filepath.Join(dir, "config.yaml")
	data := filepath.Join(dir, "state")
	if err := os.WriteFile(config, []byte("data_dir: "+data+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	// No mode flag and no mode key: bootstrap/issuance must choose master.
	if out, err := exec.Command(binary, "--config="+config, "--bootstrap").CombinedOutput(); err != nil {
		t.Fatalf("master bootstrap failed: %v %s", err, out)
	}
	if out, err := exec.Command(binary, "--config="+config, "--issue=app.internal").CombinedOutput(); err != nil {
		t.Fatalf("master issuance failed: %v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(data, "issued/app.internal.crt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("mode: client\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(binary, "--config="+config, "--mode=master").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "master-only build") {
		t.Fatalf("client config accepted: %v %s", err, out)
	}
}
