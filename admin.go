package main

import (
	"fmt"
	"math/big"
	"net"
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
	s = strings.ReplaceAll(s, ":", "")
	if n, ok := new(big.Int).SetString(s, 16); ok && n.Sign() > 0 {
		return n.Text(16)
	}
	return s
}

// reportSnapshotPublished explains pull replication after an administrative change.
func reportSnapshotPublished() {
	fmt.Println("Snapshot updated; clients receive it on their next authenticated pull.")
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
// the encrypted snapshot, and publishes the new snapshot. Master-only.
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

	already, err := st.IsRevoked(serial)
	if err != nil {
		return err
	}
	if already {
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
	reportSnapshotPublished()
	return nil
}

// RunReissueCert revokes the current certificate(s) for a subject and issues a
// fresh one (revoke -> issue), then publishes the new snapshot. Master-only.
func RunReissueCert(cfg *Config, subject string, localhost bool) error {
	subject = canonicalTarget(subject)
	if subject == "" {
		return fmt.Errorf("--reissue requires a subject")
	}
	ca, err := LoadCA(cfg.caCertPath(), cfg.caKeyPath())
	if err != nil {
		return err
	}
	st, err := OpenStore(cfg.dbPath())
	if err != nil {
		return err
	}
	defer st.Close()
	res, err := ca.Issue(subject, nil, localhost)
	if err != nil {
		return err
	}
	unlock, err := lockIssuance(cfg, subject)
	if err != nil {
		return err
	}
	defer unlock()
	if err := writeIssuedFiles(cfg, subject, res); err != nil {
		return err
	}
	rec := certRecord(res.Cert, res.CertPEM)
	rec.Subject = subject
	n, err := st.replaceCertificate(rec)
	if err != nil {
		return err
	}
	if err := WriteCRL(cfg, ca, st); err != nil {
		return fmt.Errorf("reissued in DB, but CRL update failed: %w", err)
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return fmt.Errorf("reissued, but snapshot update failed: %w", err)
	}
	fmt.Printf("Reissued certificate for %q; revoked %d previous certificate(s).\n", subject, n)
	reportSnapshotPublished()
	return nil
}

// RunDeregisterClient removes a client from the registry, rebuilds the
// snapshot, and publishes the new snapshot. Master-only.
func RunDeregisterClient(cfg *Config, ip string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("--deregister requires a client IP")
	}
	ip = net.ParseIP(ip).String()

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

	fmt.Printf("Deregistered client %s (removed from registry and snapshot).\n", ip)
	reportSnapshotPublished() // clients receive the new state on their next pull
	fmt.Println("------------------------------------------------------------")
	fmt.Println("NOTE: if natssl-client is still RUNNING on that host, it will")
	fmt.Println("      RE-REGISTER on its next ping. To keep it out for good,")
	fmt.Println("      use: natssl --mode=master --block=\"" + ip + "\"")
	return nil
}

// RunBlockClient blacklists a client IP (denying future self-registration),
// drops it from the registry, and publishes the new snapshot. Master-only.
func RunBlockClient(cfg *Config, ip, reason string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("--block requires a client IP")
	}
	ip = net.ParseIP(ip).String()

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
		return fmt.Errorf("blocked, but failed to drop from registry: %w", err)
	}
	if err := RebuildEncryptedCache(cfg, ca, st); err != nil {
		return fmt.Errorf("blocked, but cache rebuild failed: %w", err)
	}

	fmt.Printf("Blocked %s%s.\n", ip, parenIf(reason))
	fmt.Println("Future /acme/register from this IP will be DENIED, and it has")
	fmt.Println("been removed from the active registry. A running master picks")
	fmt.Println("this up immediately (same SQLite DB) — no restart required.")
	reportSnapshotPublished()
	return nil
}

// RunUnblockClient removes an IP from the blacklist and publishes a snapshot. Master-only.
func RunUnblockClient(cfg *Config, ip string) error {
	ip = strings.TrimSpace(ip)
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("--unblock requires a client IP")
	}
	ip = net.ParseIP(ip).String()

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
	reportSnapshotPublished()
	return nil
}
