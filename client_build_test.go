//go:build !clientonly

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientOnlyBinaryRejectsMasterOperations(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "natssl-client")
	build := exec.Command("go", "build", "-tags=clientonly", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("client build: %v\n%s", err, out)
	}
	for _, args := range [][]string{
		{"--mode=master"}, {"--mode", "master"}, {"-mode=master"},
		{"--bootstrap"}, {"--mode=client", "--bootstrap"}, {"--promote-to-master"},
		{"--reissue=app.internal"}, {"--revoke=123"}, {"--list-certs"},
		{"--block=127.0.0.1"}, {"--deregister=127.0.0.1"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			out, err := exec.Command(binary, args...).CombinedOutput()
			if err == nil || !strings.Contains(string(out), "client-only build") {
				t.Fatalf("master operation not rejected: %v %s", err, out)
			}
		})
	}
	config := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(config, []byte("data_dir: "+t.TempDir()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(binary, "--config="+config).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "master_address is required") {
		t.Fatalf("default mode is not client: %v %s", err, out)
	}
	if err := os.WriteFile(config, []byte("mode: master\n"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command(binary, "--config="+config, "--mode=client").CombinedOutput()
	if err == nil || !strings.Contains(string(out), "client-only build") {
		t.Fatalf("master config accepted: %v %s", err, out)
	}
}
