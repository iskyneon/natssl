package main

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

// parenIf renders an optional " (text)" suffix for log lines.
func parenIf(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return " (" + s + ")"
}

// subjectNote renders an optional ` (subject "x")` suffix.
func subjectNote(s string) string {
	if strings.TrimSpace(s) == "" {
		return ""
	}
	return fmt.Sprintf(" (subject %q)", s)
}

// normalizeSerial lowercases and strips ':' so "AB:CD" == "abcd".
func normalizeSerial(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	return strings.ReplaceAll(s, ":", "")
}

// propagateNow immediately fans the freshly-written encrypted cache and signed
// CRL out to every registered client, instead of waiting for the master's
// periodic ticker. Safe to call from the CLI process: both push helpers read
// the on-disk cache/CRL files that the calling command has just rebuilt, so it
// works whether or not a master daemon is also running. Failures are non-fatal
// (a client that is offline will catch up on the next pull).
func propagateNow(cfg *Config, st *Store) {
	fmt.Println("propagating to clients now ...")
	pushCacheToClients(cfg, st)
	pushCRLToClients(cfg, st)
}

// RunListCerts prints every certificate this master has issued, including its
// serial number, validity, and whether it has been revoked. Master-only.
func RunListCerts(cfg *Config) error {
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()

	certs, err := st.ListCerts()
	if err != nil {
		return err
	}
	if len(certs) == 0 {
		fmt.Println("No certificates have been issued yet.")
		return nil
	}
	revoked, err := st.RevokedSet()
	if err != nil {
		return err
	}

	now := time.Now()
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SERIAL\tSUBJECT\tSANS\tNOT_AFTER\tSTATUS")
	for _, c := range certs {
		var status string
		switch {
		case revoked[c.SerialHex]:
			status = "REVOKED"
		case now.After(c.NotAfter):
			status = "EXPIRED"
		case now.Before(c.NotBefore):
			status = "not-yet-valid"
		default:
			status = fmt.Sprintf("valid (%dd left)", int(time.Until(c.NotAfter).Hours()/24))
		}
		sans := c.SANs
		if sans == "" {
			sans = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			c.SerialHex, c.Subject, sans,
			c.NotAfter.Format("2006-01-02"), status)
	}
	tw.Flush()
	fmt.Printf("\n%d certificate(s) total, %d revoked.\n", len(certs), len(revoked))
	return nil
}

// RunListRevoked prints all revoked certificates. Master-only.
func RunListRevoked(cfg *Config) error {
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()

	revoked, err := st.ListRevoked()
	if err != nil {
		return err
	}
	if len(revoked) == 0 {
		fmt.Println("No certificates have been revoked.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SERIAL\tSUBJECT\tREASON\tREVOKED_AT")
	for _, r := range revoked {
		subj := r.Subject
		if subj == "" {
			subj = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n",
			r.SerialHex, subj, r.Reason, r.RevokedAt.Local().Format("2006-01-02 15:04:05"))
	}
	tw.Flush()
	fmt.Printf("\n%d revoked certificate(s).\n", len(revoked))
	return nil
}

// RunListClients prints every registered client and its registration time.
func RunListClients(cfg *Config) error {
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()

	clients, err := st.ListClientsInfo()
	if err != nil {
		return err
	}
	if len(clients) == 0 {
		fmt.Println("No clients have registered yet.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\tREGISTERED_AT")
	for _, c := range clients {
		fmt.Fprintf(tw, "%s\t%s\n", c.IP, c.AddedAt.Local().Format("2006-01-02 15:04:05"))
	}
	tw.Flush()
	fmt.Printf("\n%d client(s) registered.\n", len(clients))
	return nil
}

// RunListBlocked prints all blacklisted client IPs.
func RunListBlocked(cfg *Config) error {
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()

	blocked, err := st.ListBlocked()
	if err != nil {
		return err
	}
	if len(blocked) == 0 {
		fmt.Println("The blacklist is empty.")
		return nil
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\tREASON\tADDED_AT")
	for _, b := range blocked {
		reason := b.Reason
		if reason == "" {
			reason = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", b.IP, reason, b.AddedAt.Local().Format("2006-01-02 15:04:05"))
	}
	tw.Flush()
	fmt.Printf("\n%d blacklisted IP(s).\n", len(blocked))
	return nil
}

// RunRevokeCert revokes a certificate by serial, regenerates the CRL, rebuilds
// the encrypted snapshot, and propagates immediately. Master-only.
func RunRevokeCert(cfg *Config, serial string) error {
	serial = normalizeSerial(serial)
	if serial == "" {
		return fmt.Errorf("--revoke requires a certificate serial (hex)")
	}

	ca, err := LoadCA(cfg.caCertPath(), cfg.caKeyPath())
	if err != nil {
		return fmt.Errorf("no Root CA found (run --bootstrap first): %w", err)
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()

	if already, _ := st.IsRevoked(serial); already {
		return fmt.Errorf("certificate %s is already revoked", serial)
	}

	rec, found, err := st.CertBySerial(serial)
	if err != nil {
		return err
	}
	subject := ""
	if found {
		subject = rec.Subject
	} else {
		fmt.Printf("WARNING: serial %s is not in the issued list — revoking anyway.\n", serial)
	}

	if err := st.RevokeCert(serial, subject, crlReasonUnspecified); err != nil {
		return fmt.Errorf("record revocation: %w", err)
	}
	if err := WriteCRL(cfg, ca, st); err != nil {
		return fmt.Errorf("revoked in DB, but CRL write failed: %w", err)
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return fmt.Errorf("revoked, but cache rebuild failed: %w", err)
	}

	fmt.Printf("Revoked certificate %s%s.\n", serial, subjectNote(subject))
	propagateNow(cfg, st)
	return nil
}

// RunReissueCert revokes the current certificate(s) for a subject and issues a
// fresh one (revoke -> issue), then propagates immediately. Master-only.
func RunReissueCert(cfg *Config, subject string, localhost bool) error {
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return fmt.Errorf("--reissue requires a subject (domain or IP)")
	}

	ca, err := LoadCA(cfg.caCertPath(), cfg.caKeyPath())
	if err != nil {
		return fmt.Errorf("no Root CA found (run --bootstrap first): %w", err)
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}

	current, err := st.CertsBySubject(subject)
	if err != nil {
		st.Close()
		return err
	}
	revokedSet, err := st.RevokedSet()
	if err != nil {
		st.Close()
		return err
	}

	revokedN := 0
	for _, c := range current {
		if revokedSet[c.SerialHex] {
			continue
		}
		if err := st.RevokeCert(c.SerialHex, c.Subject, crlReasonSuperseded); err != nil {
			st.Close()
			return fmt.Errorf("revoke previous cert %s: %w", c.SerialHex, err)
		}
		fmt.Printf("revoked previous certificate for %q (serial %s)\n", subject, c.SerialHex)
		revokedN++
	}
	if revokedN == 0 {
		fmt.Printf("no active certificate found for %q — issuing a fresh one.\n", subject)
	}

	if err := WriteCRL(cfg, ca, st); err != nil {
		st.Close()
		return fmt.Errorf("write CRL: %w", err)
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		st.Close()
		return fmt.Errorf("rebuild cache after revoke: %w", err)
	}
	st.Close() // RunIssueCLI opens its own store/CA session.

	fmt.Println("issuing replacement certificate ...")
	if err := RunIssueCLI(cfg, subject, localhost); err != nil {
		return err
	}

	// Reopen to propagate the final state (CRL + cache including the new cert).
	st2, err := OpenStore(cfg.dbPath())
	if err != nil {
		return fmt.Errorf("reissued, but cannot reopen store to propagate: %w", err)
	}
	defer st2.Close()
	propagateNow(cfg, st2)
	return nil
}

// RunDeregisterClient removes a client from the push list, rebuilds the
// snapshot, and propagates immediately. Master-only.
func RunDeregisterClient(cfg *Config, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("--deregister requires a client IP")
	}

	ca, err := LoadCA(cfg.caCertPath(), cfg.caKeyPath())
	if err != nil {
		return fmt.Errorf("no Root CA found (run --bootstrap first): %w", err)
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()

	existing, err := st.ListClients()
	if err != nil {
		return err
	}
	if !contains(existing, ip) {
		return fmt.Errorf("client %q is not registered (nothing to do)", ip)
	}

	if err := st.RemoveClient(ip); err != nil {
		return fmt.Errorf("remove client: %w", err)
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return fmt.Errorf("client removed, but cache rebuild failed: %w", err)
	}

	fmt.Printf("Deregistered client %s (removed from push list and snapshot).\n", ip)
	propagateNow(cfg, st) // remaining clients get the updated snapshot now
	fmt.Println("------------------------------------------------------------")
	fmt.Println("NOTE: if natssl-client is still RUNNING on that host, it will")
	fmt.Println("      RE-REGISTER on its next ping. To keep it out for good,")
	fmt.Println("      use: natssl --mode=master --block=\"" + ip + "\"")
	return nil
}

// RunBlockClient blacklists a client IP (denying future self-registration),
// drops it from the push list, and propagates immediately. Master-only.
func RunBlockClient(cfg *Config, ip, reason string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("--block requires a client IP")
	}

	ca, err := LoadCA(cfg.caCertPath(), cfg.caKeyPath())
	if err != nil {
		return fmt.Errorf("no Root CA found (run --bootstrap first): %w", err)
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.BlockIP(ip, reason); err != nil {
		return fmt.Errorf("blacklist: %w", err)
	}
	if err := st.RemoveClient(ip); err != nil {
		return fmt.Errorf("blocked, but failed to drop from push list: %w", err)
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return fmt.Errorf("blocked, but cache rebuild failed: %w", err)
	}

	fmt.Printf("Blocked %s%s.\n", ip, parenIf(reason))
	fmt.Println("Future /acme/register from this IP will be DENIED, and it has")
	fmt.Println("been removed from the active push list. A running master picks")
	fmt.Println("this up immediately (same SQLite DB) — no restart required.")
	propagateNow(cfg, st)
	return nil
}

// RunUnblockClient removes an IP from the blacklist and propagates. Master-only.
func RunUnblockClient(cfg *Config, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return fmt.Errorf("--unblock requires a client IP")
	}

	ca, err := LoadCA(cfg.caCertPath(), cfg.caKeyPath())
	if err != nil {
		return fmt.Errorf("no Root CA found (run --bootstrap first): %w", err)
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()

	blocked, err := st.IsBlocked(ip)
	if err != nil {
		return err
	}
	if !blocked {
		return fmt.Errorf("%s is not blacklisted (nothing to do)", ip)
	}
	if err := st.UnblockIP(ip); err != nil {
		return fmt.Errorf("unblock: %w", err)
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return fmt.Errorf("unblocked, but cache rebuild failed: %w", err)
	}

	fmt.Printf("Unblocked %s. It may self-register again on its next ping.\n", ip)
	propagateNow(cfg, st)
	return nil
}

