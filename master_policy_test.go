//go:build masteronly

package main

import "testing"

func TestMasterOnlyEntrypoints(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Mode != "master" {
		t.Fatal("unexpected master-only default")
	}
	if err := RunClient(cfg); err == nil {
		t.Fatal("client allowed")
	}
	if err := RunClientIssue(cfg, "localhost", true); err == nil {
		t.Fatal("client issuance allowed")
	}
	if err := RunPromote(cfg, ""); err == nil {
		t.Fatal("client promotion allowed")
	}
}
