package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// RegisterWithMaster announces this client to the master so it gets added to
// the push list automatically. Identification is by source IP on the master
// side; this call carries no body. Idempotent.
func RegisterWithMaster(cfg *Config) error {
	if cfg.MasterAddress == "" {
		return fmt.Errorf("master_address is empty; cannot self-register")
	}
	url := fmt.Sprintf("https://%s:443/acme/register", host(cfg.MasterAddress))
	resp, err := insecureMasterClient().Post(url, "application/json", strings.NewReader("{}"))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("registration rejected (%d): %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// StartRegistrationLoop registers immediately and then re-registers
// periodically so the client survives a master restart / DB reset.
func StartRegistrationLoop(cfg *Config) {
	go func() {
		attempt := func() {
			if err := RegisterWithMaster(cfg); err != nil {
				log.Printf("self-registration: %v (will retry)", err)
			} else {
				log.Printf("self-registration with master %s OK", cfg.MasterAddress)
			}
		}
		attempt() // immediate
		t := time.NewTicker(cfg.PingInterval)
		defer t.Stop()
		for range t.C {
			attempt()
		}
	}()
}
