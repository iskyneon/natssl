# NATSSL — Deployment Guide

## 1. Topology

| Role | Count (OSS) | Ports | Privileges |
|---|---|---|---|
| Master | **1** (Raft disabled) | 443, 8443 | root (bind <1024, CAP_NET_RAW) |
| Client | N | 8443 (receive push) | root (CA installation) |

---

## 2. Authorization Model

NATSSL enforces a strict separation between who may issue what:

| Requester | Mechanism | Allowed targets |
|---|---|---|
| **Administrator** | `natssl --mode=master --issue "..."` (local CLI, bypasses HTTP) | **Any** `*.internal` / `*.local` / IP / domain |
| **Client** | `natssl --mode=client --issue "..."` → CSR-flow to master | **Loopback only**: `localhost`, `127.0.0.1`, `::1` |

> **Why loopback-only for clients?**
> All machines on the network trust the single Root CA. If a client could
> obtain a certificate for an arbitrary host (e.g. `gateway.internal` or
> another node's IP), it could impersonate that host and perform MITM attacks.
> Restricting clients to loopback makes any client-issued certificate useless
> anywhere except the requesting machine itself.

The rule is enforced **twice** (defense in depth):

1. **Client-side** (`isLoopbackTarget` in `client_issue.go`) — rejects
   non-loopback targets before a request ever leaves the machine.
2. **Master-side** (`enforceLoopbackOnly` in `server.go`) — returns **HTTP 403**
   for any CSR whose SANs are not strictly loopback, even if the client was
   bypassed or tampered with.

A third backstop lives in `ca.go` (`SignCSR` validates loopback-only whenever
`localhost=true`).

---

## 3. Installing from a Release

```bash
ARCH=$(uname -m); case "$ARCH" in
  x86_64) A=amd64;; aarch64|arm64) A=arm64;; esac

tar -xzf natssl-1.0.0-oss-linux-$A.tar.gz
sudo install -m0755 natssl-1.0.0-oss-linux-$A /usr/local/bin/natssl
sudo mkdir -p /etc/natssl /var/lib/natssl
```

Firefox dependencies:

```bash
# Debian/Ubuntu
sudo apt-get install -y libnss3-tools ca-certificates
# RHEL/Rocky/CentOS
sudo dnf install -y nss-tools
```

---

## 4. systemd

`/etc/systemd/system/natssl-master.service`:

```ini
[Unit]
Description=NATSSL Master (Private CA)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/natssl --mode=master --config=/etc/natssl/config.yaml
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/natssl-client.service`:

```ini
[Unit]
Description=NATSSL Client (Cert Store)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/natssl --mode=client --config=/etc/natssl/config.yaml
Restart=on-failure
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now natssl-master   # or natssl-client
```

---

## 5. Certificate Lifecycle

### 5.1 Administrator issues any cert on the master (`--issue`)

The master generates both the key and the certificate locally via the CLI —
this path bypasses the HTTP authorization layer and can target any name.

```mermaid
sequenceDiagram
    participant A as Admin (master CLI)
    participant CA as Root CA
    participant DB as SQLite
    A->>CA: natssl --mode=master --issue "app.internal"
    CA->>CA: generate key + sign leaf (90d)
    CA->>DB: store CertRecord
    CA->>CA: RebuildEncryptedCache (AES-GCM + sealed key)
    CA-->>A: write app.internal.crt + app.internal.key
```

### 5.2 Client issues a LOOPBACK cert for itself (`/acme/sign-csr`)

```mermaid
sequenceDiagram
    participant U as User on Client
    participant C as natssl client
    participant M as Master (CA)

    U->>C: natssl --mode=client --issue "localhost" --localhost
    C->>C: isLoopbackTarget("localhost")? ✔ allowed
    C->>C: generate ECDSA P-256 keypair LOCALLY
    C->>C: build CSR with loopback SANs only
    C->>M: POST /acme/sign-csr {csr, localhost:true}
    M->>M: enforceLoopbackOnly(csr) — reject if any non-loopback SAN
    M->>M: SignCSR (second loopback check)
    M-->>C: {certificate}
    C->>U: prompt for password
    C->>C: scrypt + AES-GCM encrypt private key
    C->>C: save localhost.crt + localhost.key.enc (0600)
    Note over C: the private key never left the machine
```

### 5.3 Client requests a NON-loopback target — DENIED

```mermaid
sequenceDiagram
    participant U as User on Client
    participant C as natssl client
    participant M as Master (CA)

    U->>C: natssl --mode=client --issue "dev.internal"
    C->>C: isLoopbackTarget("dev.internal")? �’✗ NOT allowed
    C-->>U: error: clients may only issue localhost / 127.0.0.1 / ::1
    Note over C,M: request never reaches the master

    rect rgb(255, 235, 235)
    Note over M: Even if the CLI were bypassed and a raw CSR were posted,
    M->>M: enforceLoopbackOnly(csr) → HTTP 403 DENIED
    end
```

---

## 6. Disaster Scenario (DR)

```mermaid
flowchart TD
    A[Master destroyed] --> B{promote-to-master --token}
    B --> C1[Check 1: TCP 443/8443]
    C1 -->|alive| X[ABORT]
    C1 -->|dead| C2[Check 2: ICMP/ARP]
    C2 -->|reachable| X
    C2 -->|silent| C3[Check 3: IP conflict]
    C3 -->|conflict| X
    C3 -->|ok| D[Recover key from seed]
    D --> E[Verify vs pinned pub]
    E --> F[Decrypt cache]
    F --> G[Restore Root CA byte-for-byte<br/>same SHA-256]
    G --> H[mode=master on new IP]
    H --> I[Signed migration broadcast]
    I --> J[Clients verify & update master IP]
```

### Verifying fingerprint identity

```bash
openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256
# the value matches before and after promotion
```

---

## 7. Hardening (Production)

| Risk | Action |
|---|---|
| `InsecureSkipVerify` in transport | Replace with `RootCAs` and Root CA pinning |
| `/cache/push` without mTLS | Require a client certificate signed by the Root CA |
| `/acme/sign-csr` without auth | Loopback-only is enforced, but it is **unauthenticated**; add mTLS or one-time enrollment tokens so only known clients can request even loopback certs |
| Source-IP trust | Do not rely on source IP for authorization — it is spoofable on a flat L2 segment. Use mTLS identity instead |
| localhost private key | scrypt(N=2¹⁵)+AES-GCM is **already enabled**; keep the password off the node |
| seed phrase | store offline (paper/HSM), not in a password manager on the node |
| file permissions | `root-ca.key`, `*.key.enc`, `network-cache.enc` → `0600` (already set) |

> **Note on the loopback rule:** `enforceLoopbackOnly` prevents *privilege
> escalation* (a client cannot obtain a cert for another host), but it does
> **not** authenticate *which* client is asking. Any reachable peer can request
> a `localhost` cert. For production, gate `/acme/sign-csr` behind mTLS so only
> enrolled clients can call it.

---

## 8. Diagnostics

```bash
# Master reachability
nc -vz 192.168.10.5 443
nc -vz 192.168.10.5 8443

# Logs
journalctl -u natssl-master -f
journalctl -u natssl-client -f

# Watch for denied CSRs on the master
journalctl -u natssl-master | grep "DENIED CSR"

# Root CA in the OS
trust list | grep -A2 NATSSL                              # RHEL family
ls -l /usr/local/share/ca-certificates/natssl-root.crt    # Debian family

# Root CA in a Firefox profile
certutil -L -d sql:$HOME/.mozilla/firefox/<profile> | grep NATSSL

# Inspect a client-issued (loopback) certificate
openssl x509 -in /var/lib/natssl/issued/localhost.crt -noout -text | \
  grep -A2 "Subject Alternative Name"
# Expect ONLY: DNS:localhost, IP:127.0.0.1, IP:::1
```

---

## 9. Common Errors

### "issue failed: clients may only issue certificates for localhost / 127.0.0.1 / ::1"

**Expected** — the client tried to request a non-loopback target. Domains/IPs
must be issued by the administrator on the master:

```bash
sudo natssl --mode=master --issue "dev.internal"
```

### "master rejected request: clients may only request 'localhost' ..." (HTTP 403)

The master refused a CSR whose SANs were not strictly loopback. This is the
server-side backstop firing. Check `journalctl -u natssl-master | grep DENIED`
to see the offending peer.

### "issue failed: master is OFFLINE"

**Expected** (ReadOnly). The client cannot issue while the master is
unreachable. Options:

1. Bring the master back up.
2. If the master is physically lost — run `--promote-to-master`.
3. Already-issued certificates keep working until they expire.

---

## 10. FAQ

**Why doesn't the client sign on its own?**
Trust is built on a single Root CA. Distributing its key to every machine
would compromise the entire network. The CSR-flow keeps signing centralized
while the leaf private key stays on the client.

**Why can a client only issue loopback certificates?**
To prevent host impersonation. A loopback certificate is useless anywhere
except the requesting machine, so a compromised or malicious client cannot use
the shared Root CA to MITM other hosts. Real domain/IP certificates are an
administrator action on the master.

**What if the seed phrase is lost?**
Recovery is impossible — there is nothing to decrypt the cache with. This is
by design.

**Why can't the Root CA be regenerated with the same fingerprint without a backup?**
The SHA-256 fingerprint is the hash of the DER encoding (including the
non-deterministic ECDSA signature). The only correct approach is a
byte-for-byte restore from the encrypted recovery cache.
