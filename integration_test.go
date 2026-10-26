package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func must[T any](t *testing.T, value T, err error) T {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func newCA(t *testing.T) *CA { t.Helper(); ca, err := BootstrapCA(); return must(t, ca, err) }
func csrFor(t *testing.T, name string, sans []string) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	dns, ips := splitSANs(sans)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: name}, DNSNames: dns, IPAddresses: ips}, key)
	check(t, err)
	return key, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}
func parseCSR(t *testing.T, s string) *x509.CertificateRequest {
	b, _ := pem.Decode([]byte(s))
	c, e := x509.ParseCertificateRequest(b.Bytes)
	return must(t, c, e)
}

type fixture struct {
	mnemonic        string
	master, client  *Config
	ca              *CA
	store           *Store
	recovery        *RecoveryKey
	public, control *httptest.Server
}

func setup(t *testing.T) *fixture {
	t.Helper()
	ca := newCA(t)
	rk, mnemonic, err := GenerateRecovery()
	check(t, err)
	cfg := DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.EnrollmentToken = "test-enrollment-token"
	cfg.ClientNetworks = []string{"127.0.0.0/8"}
	cfg.RecoveryPublicKey = rk.PublicBase64()
	check(t, ca.SaveToFiles(cfg.caCertPath(), cfg.caKeyPath()))
	st, err := OpenStore(cfg.dbPath())
	check(t, err)
	t.Cleanup(func() { st.Close() })
	check(t, WriteCRL(cfg, ca, st))
	check(t, RebuildEncryptedCache(cfg, ca, st))
	public, control := masterHandlers(cfg, ca, st)
	chain, key, err := ca.IssueServerCert([]string{"localhost"})
	check(t, err)
	pair, err := tls.X509KeyPair(chain, key)
	check(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	start := func(h http.Handler, mtls bool) *httptest.Server {
		s := httptest.NewUnstartedServer(h)
		s.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
		if mtls {
			s.TLS.ClientAuth = tls.RequireAndVerifyClientCert
			s.TLS.ClientCAs = pool
		}
		s.Config.ErrorLog = log.New(io.Discard, "", 0)
		s.StartTLS()
		t.Cleanup(s.Close)
		return s
	}
	api, mgmt := start(public, false), start(control, true)
	client := DefaultConfig()
	client.Mode = "client"
	client.DataDir = t.TempDir()
	client.path = filepath.Join(client.DataDir, "config.yaml")
	client.MasterAddress = strings.TrimPrefix(api.URL, "https://")
	client.MasterMgmtAddress = strings.TrimPrefix(mgmt.URL, "https://")
	client.MasterFingerprint = ca.Fingerprint()
	client.RecoveryPublicKey = rk.PublicBase64()
	client.EnrollmentToken = cfg.EnrollmentToken
	check(t, atomicWriteFile(client.caCertPath(), ca.certPEMBytes(), 0o644))
	return &fixture{mnemonic, cfg, client, ca, st, rk, api, mgmt}
}
func response(t *testing.T, c *http.Client, method, url string, body []byte) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, bytes.NewReader(body))
	check(t, err)
	res, err := c.Do(req)
	check(t, err)
	defer res.Body.Close()
	data, err := io.ReadAll(res.Body)
	check(t, err)
	return res.StatusCode, data
}
func enrolled(t *testing.T, f *fixture) *http.Client {
	t.Helper()
	check(t, RegisterWithMaster(f.client))
	c, err := mtlsClient(f.client)
	check(t, err)
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func TestEnrollmentAndMTLSIssuance(t *testing.T) {
	f := setup(t)
	// Public interface exposes neither general issuance nor replication.
	for _, path := range []string{"/acme/new-order", "/acme/sign-csr", "/cache", "/crl", "/sync/cache"} {
		code, _ := response(t, pinnedMasterClient(f.client), "GET", f.public.URL+path, nil)
		if code != 404 {
			t.Fatalf("public %s: %d", path, code)
		}
	}
	anon := pinnedMasterClient(f.client)
	if r, err := anon.Get(f.control.URL + "/sync/cache"); err == nil {
		r.Body.Close()
		t.Fatal("anonymous control request succeeded")
	}
	// Authentication gates must be independent.
	for _, kind := range []string{"missing-token", "bad-token", "outside-network", "blacklisted"} {
		t.Run(kind, func(t *testing.T) {
			cfg := *f.client
			switch kind {
			case "missing-token":
				cfg.EnrollmentToken = ""
			case "bad-token":
				cfg.EnrollmentToken = "bad"
			case "outside-network":
				f.master.ClientNetworks = []string{"10.0.0.0/8"}
			case "blacklisted":
				check(t, f.store.BlockIP("127.0.0.1", "test"))
			}
			req, err := buildRegisterRequest(&cfg, []byte("{}"))
			check(t, err)
			res, err := pinnedMasterClient(&cfg).Do(req)
			check(t, err)
			res.Body.Close()
			if res.StatusCode != 403 {
				t.Fatalf("got %d", res.StatusCode)
			}
			f.master.ClientNetworks = []string{"127.0.0.0/8"}
			check(t, f.store.UnblockIP("127.0.0.1"))
		})
	}
	client := enrolled(t, f)
	pair, err := tls.LoadX509KeyPair(f.client.identityCertPath(), f.client.identityKeyPath())
	check(t, err)
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	check(t, err)
	if cert.IsCA || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("identity has wrong privileges")
	}
	code, body := response(t, client, "GET", f.control.URL+"/sync/health", nil)
	if code != 200 || string(body) != "ok" {
		t.Fatalf("health: %d %s", code, body)
	}
	key, csr := csrFor(t, "localhost", []string{"localhost", "127.0.0.1", "::1"})
	certPEM, err := requestCSRSign(f.client, csr, "", true)
	check(t, err)
	check(t, validateIssuedCertificate(f.client, certPEM, key, "localhost"))
	for _, name := range []string{"app.internal", "192.168.1.20"} {
		_, csr := csrFor(t, name, []string{name})
		payload, _ := json.Marshal(map[string]any{"csr": csr, "localhost": true})
		code, _ := response(t, client, "POST", f.control.URL+"/acme/sign-csr", payload)
		if code != 403 {
			t.Fatalf("non-loopback %s accepted: %d", name, code)
		}
	}
	payload, _ := json.Marshal(map[string]any{"csr": csr, "localhost": false})
	code, _ = response(t, client, "POST", f.control.URL+"/acme/sign-csr", payload)
	if code != 403 {
		t.Fatal("missing localhost flag accepted")
	}
	code, _ = response(t, client, "GET", f.control.URL+"/acme/sign-csr", nil)
	if code != 405 {
		t.Fatalf("wrong method: %d", code)
	}
	code, _ = response(t, client, "POST", f.control.URL+"/acme/sign-csr", []byte(`{"csr":"`+strings.Repeat("a", maxBody)+`"}`))
	if code != 413 {
		t.Fatalf("oversize request: %d", code)
	}
	code, _ = response(t, client, "POST", f.control.URL+"/acme/sign-csr", []byte(`{} {}`))
	if code != 400 {
		t.Fatalf("multiple JSON objects: %d", code)
	}
	// Revocation is checked on every request, including reused TLS connections.
	check(t, f.store.RevokeCert(cert.SerialNumber.Text(16), cert.Subject.CommonName, 0))
	code, _ = response(t, client, "GET", f.control.URL+"/sync/health", nil)
	if code != 403 {
		t.Fatalf("revoked client: %d", code)
	}
}

func TestBlockDeregisterAndReenroll(t *testing.T) {
	f := setup(t)
	client := enrolled(t, f)
	check(t, RunBlockClient(f.master, "127.0.0.1", "test"))
	code, _ := response(t, client, "GET", f.control.URL+"/sync/cache", nil)
	if code != 403 {
		t.Fatalf("blocked client: %d", code)
	}
	if err := RegisterWithMaster(f.client); err == nil {
		t.Fatal("blocked client re-registered")
	}
	check(t, RunUnblockClient(f.master, "127.0.0.1"))
	check(t, RegisterWithMaster(f.client))
	check(t, RunDeregisterClient(f.master, "127.0.0.1"))
	code, _ = response(t, client, "GET", f.control.URL+"/sync/cache", nil)
	if code != 403 {
		t.Fatal("deregistered client can sync")
	}
	check(t, RegisterWithMaster(f.client))
	code, _ = response(t, client, "GET", f.control.URL+"/sync/cache", nil)
	if code != 200 {
		t.Fatalf("re-registered client: %d", code)
	}
}

func TestPinRequiresValidChain(t *testing.T) {
	f := setup(t)
	chain, _, err := f.ca.IssueServerCert(nil)
	check(t, err)
	var raw [][]byte
	for len(chain) > 0 {
		b, rest := pem.Decode(chain)
		if b == nil {
			break
		}
		raw = append(raw, b.Bytes)
		chain = rest
	}
	check(t, verifyMasterPin(f.client, raw))
	other := newCA(t)
	rogue, _, err := other.IssueServerCert(nil)
	check(t, err)
	b, _ := pem.Decode(rogue)
	if err := verifyMasterPin(f.client, [][]byte{b.Bytes, f.ca.CertDER}); err == nil {
		t.Fatal("appended pinned CA authenticated unrelated leaf")
	}
	if err := verifyMasterPin(f.client, [][]byte{f.ca.CertDER}); err == nil {
		t.Fatal("Root CA accepted as server TLS identity")
	}
	cfg := *f.client
	cfg.MasterFingerprint = other.Fingerprint()
	if err := verifyMasterPin(&cfg, raw); err == nil {
		t.Fatal("wrong fingerprint accepted")
	}
	cfg.MasterFingerprint = ""
	check(t, verifyMasterPin(&cfg, raw))
	cfg.DataDir = t.TempDir()
	if err := verifyMasterPin(&cfg, raw); err == nil {
		t.Fatal("unpinned first contact accepted")
	}
	_, csr := csrFor(t, "client", nil)
	cp, err := f.ca.IssueClientCert(parseCSR(t, csr), "client")
	check(t, err)
	cb, _ := pem.Decode([]byte(cp))
	if err := verifyMasterPin(f.client, [][]byte{cb.Bytes, f.ca.CertDER}); err == nil {
		t.Fatal("client identity accepted as TLS server")
	}
}

func TestSignedReplicationAndRecovery(t *testing.T) {
	f := setup(t)
	enrolled(t, f)
	check(t, RunIssueCLI(f.master, "app.internal", false))
	certs, err := f.store.CertsBySubject("app.internal")
	check(t, err)
	if len(certs) != 1 {
		t.Fatal("missing issued cert")
	}
	check(t, RunRevokeCert(f.master, certs[0].SerialHex))
	check(t, RunBlockClient(f.master, "10.0.0.8", "retired"))
	check(t, pullOnce(f.client))
	ec, err := ReadEncryptedCache(f.client.cachePath())
	check(t, err)
	check(t, ec.Verify(f.ca.Cert))
	plain, err := DecryptCache(ec, f.recovery)
	check(t, err)
	var snap Snapshot
	check(t, json.Unmarshal(plain, &snap))
	if snap.Sequence != ec.Sequence || snap.EnrollmentToken != f.master.EnrollmentToken || len(snap.ClientNetworks) != 1 || len(snap.Revoked) != 1 || len(snap.Blacklist) != 1 || len(snap.Clients) != 1 {
		t.Fatal("incomplete snapshot")
	}
	restored, err := LoadCAFromPEM(snap.CACertPEM, snap.CAKeyPEM)
	check(t, err)
	if !bytes.Equal(restored.CertDER, f.ca.CertDER) {
		t.Fatal("Root CA changed during recovery")
	}
	st, err := OpenStore(filepath.Join(t.TempDir(), "restored.db"))
	check(t, err)
	defer st.Close()
	check(t, st.RestoreSnapshot(&snap))
	check(t, st.RestoreSnapshot(&snap))
	records, err := st.ListCerts()
	check(t, err)
	if len(records) != len(snap.Certs) {
		t.Fatal("certificates lost")
	}
	revoked, err := st.IsRevoked(certs[0].SerialHex)
	check(t, err)
	if !revoked {
		t.Fatal("revocation lost")
	}
	blocked, err := st.IsBlocked("10.0.0.8")
	check(t, err)
	if !blocked {
		t.Fatal("blacklist lost")
	}
	seq, err := st.nextCacheSequence()
	check(t, err)
	if seq <= ec.Sequence {
		t.Fatal("recovered sequence rolled back")
	}
	number, err := st.nextCRLNumber(1)
	check(t, err)
	if number <= snap.CRLNumber {
		t.Fatal("CRL sequence rolled back")
	}
	other, _, err := GenerateRecovery()
	check(t, err)
	if _, err := DecryptCache(ec, other); err == nil {
		t.Fatal("wrong recovery seed decrypted cache")
	}
	old, err := os.ReadFile(f.client.cachePath())
	check(t, err)
	check(t, RebuildEncryptedCache(f.master, f.ca, f.store))
	current, err := os.ReadFile(f.master.cachePath())
	check(t, err)
	check(t, acceptCache(f.client, current))
	if err := acceptCache(f.client, old); err == nil {
		t.Fatal("stale snapshot accepted")
	}
	var changed EncryptedCache
	check(t, json.Unmarshal(current, &changed))
	changed.Sequence++
	forged, _ := json.Marshal(changed)
	if err := acceptCache(f.client, forged); err == nil {
		t.Fatal("forged sequence accepted")
	}
	check(t, acceptCache(f.client, current))
	before, err := os.ReadFile(f.client.cachePath())
	check(t, err)
	if err := acceptCache(f.client, []byte(`{"v":1}`)); err == nil {
		t.Fatal("malformed cache accepted")
	}
	after, err := os.ReadFile(f.client.cachePath())
	check(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid cache overwrote good snapshot")
	}
}

func TestCRLValidation(t *testing.T) {
	f := setup(t)
	original, err := os.ReadFile(f.master.crlPath())
	check(t, err)
	check(t, acceptCRL(f.client, original))
	check(t, WriteCRL(f.master, f.ca, f.store))
	newer, err := os.ReadFile(f.master.crlPath())
	check(t, err)
	check(t, acceptCRL(f.client, newer))
	if err := acceptCRL(f.client, original); err == nil {
		t.Fatal("old CRL accepted")
	}
	other := newCA(t)
	der, err := BuildCRLDER(other, f.store)
	check(t, err)
	if err := acceptCRL(f.client, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})); err == nil {
		t.Fatal("foreign CRL accepted")
	}
}

func TestCertificateValidityAndLoopbackMode(t *testing.T) {
	ca := newCA(t)
	for _, name := range []string{"app.internal", "192.168.1.2", "*.internal", "fd00::1"} {
		res, err := ca.Issue(name, nil, false)
		check(t, err)
		if d := time.Until(res.Cert.NotAfter); d < 89*24*time.Hour || d > 90*24*time.Hour {
			t.Fatalf("%s: lifetime %s", name, d)
		}
		if len(res.Cert.ExtKeyUsage) != 1 || res.Cert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
			t.Fatal("ordinary certificate usable as mTLS identity")
		}
	}
	if _, err := ca.Issue("myhost", nil, false); err == nil {
		t.Fatal("single-label domain accepted")
	}
	if _, err := ca.Issue("valid.internal", []string{"../../bad"}, false); err == nil {
		t.Fatal("malformed extra SAN accepted")
	}
	res, err := ca.Issue("app.internal", nil, true)
	check(t, err)
	if time.Until(res.Cert.NotAfter) < 364*24*time.Hour {
		t.Fatal("localhost lifetime is not one year")
	}
	if len(res.Cert.DNSNames) != 1 || res.Cert.DNSNames[0] != "localhost" {
		t.Fatal("localhost mode retained remote SAN")
	}
}

func TestMigrationSignatureFreshnessAndPersistence(t *testing.T) {
	f := setup(t)
	packet := MigrationPacket{NewMasterIP: "192.168.1.50", IssuedAt: time.Now().UTC()}
	sign := func() {
		d := migrationDigest(&packet)
		var err error
		packet.Signature, err = ecdsa.SignASN1(rand.Reader, f.ca.Key, d[:])
		check(t, err)
	}
	sign()
	check(t, applyMigration(f.client, &packet))
	saved, err := LoadConfig(f.client.path)
	check(t, err)
	if saved.MasterAddress != packet.NewMasterIP || !saved.LastMigration.Equal(packet.IssuedAt) {
		t.Fatal("migration not persisted")
	}
	if err := applyMigration(saved, &packet); err == nil {
		t.Fatal("replayed migration accepted after config reload")
	}
	packet.IssuedAt = time.Now().Add(-time.Hour)
	sign()
	if err := applyMigration(saved, &packet); err == nil {
		t.Fatal("stale migration accepted")
	}
	packet.IssuedAt = time.Now().Add(time.Hour)
	sign()
	if err := applyMigration(saved, &packet); err == nil {
		t.Fatal("future migration accepted")
	}
	packet.IssuedAt = time.Now()
	packet.NewMasterIP = "192.168.1.51"
	sign()
	packet.NewMasterIP = "192.168.1.52"
	if err := applyMigration(saved, &packet); err == nil {
		t.Fatal("tampered migration accepted")
	}
}

func TestKeyEncryptionAndFilePermissions(t *testing.T) {
	encrypted, err := encryptKey([]byte("private material"), "password")
	check(t, err)
	plain, err := decryptKey(encrypted, "password")
	check(t, err)
	if string(plain) != "private material" {
		t.Fatal("bad roundtrip")
	}
	if _, err := decryptKey(encrypted, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := decryptKey([]byte{1}, "password"); err == nil {
		t.Fatal("truncated encrypted key accepted")
	}
	f := setup(t)
	check(t, f.client.Save())
	info, err := os.Stat(f.client.path)
	check(t, err)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("config not private")
	}
	path := filepath.Join(t.TempDir(), "key")
	check(t, os.WriteFile(path, []byte("old"), 0o644))
	check(t, atomicWriteFile(path, []byte("new"), 0o600))
	info, err = os.Stat(path)
	check(t, err)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("replacement key retained unsafe permissions")
	}
	check(t, os.WriteFile(f.master.issuedDir(), []byte("not a directory"), 0o600))
	if err := RunIssueCLI(f.master, "app.internal", false); err == nil {
		t.Fatal("issuance hid a filesystem error")
	}
}

func TestConcurrentSnapshotPublication(t *testing.T) {
	f := setup(t)
	second, err := OpenStore(f.master.dbPath())
	check(t, err)
	defer second.Close()
	old, err := ReadEncryptedCache(f.master.cachePath())
	check(t, err)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			st := f.store
			if i%2 != 0 {
				st = second
			}
			errs <- RebuildEncryptedCache(f.master, f.ca, st)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		check(t, err)
	}
	current, err := ReadEncryptedCache(f.master.cachePath())
	check(t, err)
	check(t, current.Verify(f.ca.Cert))
	if current.Sequence != old.Sequence+8 {
		t.Fatalf("lost publications: %d -> %d", old.Sequence, current.Sequence)
	}
}

func TestMasterURLIPv6AndCustomPorts(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MasterAddress = "[::1]:9443"
	cfg.MasterMgmtAddress = "[::1]:9843"
	if cfg.masterURL(false, "/ca") != "https://[::1]:9443/ca" || cfg.masterURL(true, "/sync/cache") != "https://[::1]:9843/sync/cache" {
		t.Fatal("custom IPv6 address broken")
	}
	cfg.MasterAddress = "2001:db8::1"
	cfg.MasterMgmtAddress = ""
	if cfg.masterURL(false, "/ca") != "https://[2001:db8::1]:443/ca" {
		t.Fatal("IPv6 address not bracketed")
	}
}

func TestProductionRecoveryPath(t *testing.T) {
	f := setup(t)
	enrolled(t, f)
	check(t, RunIssueCLI(f.master, "app.internal", false))
	records, err := f.store.CertsBySubject("app.internal")
	check(t, err)
	check(t, RunRevokeCert(f.master, records[0].SerialHex))
	check(t, RunBlockClient(f.master, "10.0.0.9", "retired"))
	check(t, pullOnce(f.client))
	_, wrong, err := GenerateRecovery()
	check(t, err)
	if _, _, err := restoreMasterState(f.client, wrong, "192.168.1.50"); err == nil {
		t.Fatal("wrong recovery seed accepted")
	}
	if _, err := os.Stat(f.client.caKeyPath()); !os.IsNotExist(err) {
		t.Fatal("failed recovery wrote CA key")
	}
	ca, clients, err := restoreMasterState(f.client, f.mnemonic, "192.168.1.50")
	check(t, err)
	if !ca.Cert.Equal(f.ca.Cert) || len(clients) != 1 {
		t.Fatal("recovery changed CA or lost clients")
	}
	cfg, err := LoadConfig(f.client.path)
	check(t, err)
	if cfg.Mode != "master" || cfg.EnrollmentToken != f.master.EnrollmentToken || len(cfg.ClientNetworks) != 1 {
		t.Fatal("recovery lost enrollment policy")
	}
	st, err := OpenStore(cfg.dbPath())
	check(t, err)
	defer st.Close()
	blocked, err := st.IsBlocked("10.0.0.9")
	check(t, err)
	if !blocked {
		t.Fatal("recovery lost blacklist")
	}
	revoked, err := st.IsRevoked(records[0].SerialHex)
	check(t, err)
	if !revoked {
		t.Fatal("recovery lost revocation")
	}
	if _, _, err := restoreMasterState(cfg, f.mnemonic, "192.168.1.50"); err == nil {
		t.Fatal("recovery overwrote an existing master key")
	}
}

func TestPromotionRejectsLiveMasterOnCustomPort(t *testing.T) {
	f := setup(t)
	if err := RunPromote(f.client, "invalid seed"); err == nil || !strings.Contains(err.Error(), "ALIVE") {
		t.Fatalf("live master not detected: %v", err)
	}
}

func TestLegacyCacheUpgrade(t *testing.T) {
	f := setup(t)
	ec, err := ReadEncryptedCache(f.master.cachePath())
	check(t, err)
	ec.Sequence = 0
	ec.Signature = nil
	legacy, err := json.Marshal(ec)
	check(t, err)
	check(t, os.WriteFile(f.client.cachePath(), legacy, 0o600))
	signed, err := os.ReadFile(f.master.cachePath())
	check(t, err)
	check(t, acceptCache(f.client, signed))
	upgraded, err := ReadEncryptedCache(f.client.cachePath())
	check(t, err)
	check(t, upgraded.Verify(f.ca.Cert))
	if err := acceptCache(f.client, legacy); err == nil {
		t.Fatal("unsigned legacy cache accepted after upgrade")
	}
}

func TestOfflineClientPreservesState(t *testing.T) {
	f := setup(t)
	enrolled(t, f)
	check(t, pullOnce(f.client))
	before, err := os.ReadFile(f.client.cachePath())
	check(t, err)
	f.control.Close()
	if err := pullOnce(f.client); err == nil {
		t.Fatal("offline sync succeeded")
	}
	_, csr := csrFor(t, "localhost", []string{"localhost"})
	if _, err := requestCSRSign(f.client, csr, "", true); err == nil {
		t.Fatal("offline issuance succeeded")
	}
	after, err := os.ReadFile(f.client.cachePath())
	check(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("offline sync lost existing recovery state")
	}
}

func TestSignedMigrationReceiver(t *testing.T) {
	f := setup(t)
	changes := make(chan migrationRequest, 1)
	handler := migrationHandler(f.client, changes)
	packet := MigrationPacket{NewMasterIP: "192.168.1.50", IssuedAt: time.Now().UTC()}
	d := migrationDigest(&packet)
	sig, err := ecdsa.SignASN1(rand.Reader, f.ca.Key, d[:])
	check(t, err)
	packet.Signature = sig
	body, err := json.Marshal(packet)
	check(t, err)
	done := make(chan struct{})
	go func() { req := <-changes; req.result <- applyMigration(f.client, &req.packet); close(done) }()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/migrate", bytes.NewReader(body)))
	<-done
	if w.Code != 200 || f.client.MasterAddress != packet.NewMasterIP {
		t.Fatalf("migration receiver: %d %s", w.Code, w.Body)
	}
	packet.Signature = []byte("forged")
	body, _ = json.Marshal(packet)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("POST", "/migrate", bytes.NewReader(body)))
	if w.Code != 403 {
		t.Fatalf("forged migration: %d", w.Code)
	}
	for _, path := range []string{"/cache/push", "/crl/push"} {
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader("malicious")))
		if w.Code != 404 {
			t.Fatalf("push receiver still exposed: %s", path)
		}
	}
}

func TestReissueKeepsWorkingCertificateOnWriteFailure(t *testing.T) {
	f := setup(t)
	check(t, RunIssueCLI(f.master, "App.Internal", false))
	records, err := f.store.CertsBySubject("APP.INTERNAL")
	check(t, err)
	if len(records) != 1 {
		t.Fatal("case-insensitive subject lookup failed")
	}
	previousKey, err := os.ReadFile(filepath.Join(f.master.issuedDir(), "app.internal.key"))
	check(t, err)
	certPath := filepath.Join(f.master.issuedDir(), "app.internal.crt")
	check(t, os.Rename(certPath, certPath+".backup"))
	check(t, os.Mkdir(certPath, 0o700))
	if err := RunReissueCert(f.master, "APP.INTERNAL", false); err == nil {
		t.Fatal("reissue hid failed certificate write")
	}
	revoked, err := f.store.IsRevoked(records[0].SerialHex)
	check(t, err)
	if revoked {
		t.Fatal("failed reissue revoked working certificate")
	}
	afterKey, err := os.ReadFile(filepath.Join(f.master.issuedDir(), "app.internal.key"))
	check(t, err)
	if !bytes.Equal(previousKey, afterKey) {
		t.Fatal("failed certificate write did not restore previous private key")
	}
	check(t, os.Remove(certPath))
	check(t, os.Rename(certPath+".backup", certPath))
	check(t, RunReissueCert(f.master, "APP.INTERNAL", false))
	records, err = f.store.CertsBySubject("app.internal")
	check(t, err)
	if len(records) != 2 {
		t.Fatalf("replacement missing: %d", len(records))
	}
	list, err := f.store.ListRevoked()
	check(t, err)
	if len(list) != 1 || list[0].Reason != crlReasonSuperseded {
		t.Fatal("incorrect reissue revocation")
	}
	_, err = tls.LoadX509KeyPair(certPath, filepath.Join(f.master.issuedDir(), "app.internal.key"))
	check(t, err)
}

func TestBlockCanonicalIPv6(t *testing.T) {
	f := setup(t)
	check(t, RunBlockClient(f.master, "0:0:0:0:0:0:0:1", "test"))
	blocked, err := f.store.IsBlocked("::1")
	check(t, err)
	if !blocked {
		t.Fatal("expanded IPv6 bypasses blacklist")
	}
	check(t, RunUnblockClient(f.master, "0:0:0:0:0:0:0:1"))
	blocked, err = f.store.IsBlocked("::1")
	check(t, err)
	if blocked {
		t.Fatal("IPv6 unblock failed")
	}
}

func TestConcurrentReissueLeavesActiveCertificateOnDisk(t *testing.T) {
	f := setup(t)
	check(t, RunIssueCLI(f.master, "app.internal", false))
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- RunReissueCert(f.master, "app.internal", false) }()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		check(t, err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(f.master.issuedDir(), "app.internal.crt"), filepath.Join(f.master.issuedDir(), "app.internal.key"))
	check(t, err)
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	check(t, err)
	revoked, err := f.store.IsRevoked(cert.SerialNumber.Text(16))
	check(t, err)
	if revoked {
		t.Fatal("concurrent reissue left a revoked certificate on disk")
	}
	records, err := f.store.CertsBySubject("app.internal")
	check(t, err)
	revocations, err := f.store.ListRevoked()
	check(t, err)
	if len(records) != 5 || len(revocations) != 4 {
		t.Fatalf("incomplete reissue history: %d certs, %d revoked", len(records), len(revocations))
	}
}
