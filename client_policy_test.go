//go:build clientonly

package main

import "testing"

func TestClientOnlyEntrypoints(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Mode != "client" || cfg.InstallTrust {
		t.Fatal("unexpected client-only defaults")
	}
	if err := RunBootstrap(cfg); err == nil {
		t.Fatal("bootstrap allowed")
	}
	if err := RunMaster(cfg); err == nil {
		t.Fatal("master allowed")
	}
	if err := RunPromote(cfg, ""); err == nil {
		t.Fatal("promotion allowed")
	}
}
