package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// buildRegisterRequest creates a POST to /acme/register carrying the enrollment
// token. Body is caller-provided ({} for liveness, or {"csr":...} for enroll).
func buildRegisterRequest(cfg *Config, body []byte) (*http.Request, error) {
	if cfg.MasterAddress == "" {
		return nil, fmt.Errorf("master_address is empty; cannot self-register")
	}
	url := fmt.Sprintf("https://%s:443/acme/register", host(cfg.MasterAddress))
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Enrollment-Token", cfg.EnrollmentToken)
	return req, nil
}

// RegisterWithMaster re-announces liveness (and lazily enrolls if no identity
// exists yet). Idempotent. Pinned transport.
func RegisterWithMaster(cfg *Config) error {
	if err := ensureClientIdentity(cfg); err != nil {
		return err
	}
	req, err := buildRegisterRequest(cfg, []byte("{}"))
	if err != nil {
		return err
	}
	resp, err := pinnedMasterClient(cfg).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration rejected (%d): %s",
			resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// StartRegistrationLoop re-registers periodically so the client survives a
// master restart / DB reset.
func StartRegistrationLoop(cfg *Config) {
	go func() {
		attempt := func() {
			if err := RegisterWithMaster(cfg); err != nil {
				log.Printf("self-registration: %v (will retry)", err)
			} else {
				log.Printf("self-registration with master %s OK", cfg.MasterAddress)
			}
		}
		attempt()
		t := time.NewTicker(cfg.PingInterval)
		defer t.Stop()
		for range t.C {
			attempt()
		}
	}()
}
