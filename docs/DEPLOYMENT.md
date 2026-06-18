# NATSSL — Deployment Guide

## 1. Topology

| Role | Count (OSS) | Ports | Notes |
|---|---|---|---|
| Master | 1 | 443 (bootstrap), 8443 (mTLS) | Root CA signs only; TLS via server leaf |
| Client | N | 8443 (migration receiver) | mTLS identity after enrollment |

---

## 2. Security Controls

<details open>
<summary><b>2.1 Enrollment token (mandatory)</b></summary>

Self-registration requires a shared secret in `X-Enrollment-Token`, compared in
constant time. **The master refuses to start** with `client_networks` set but
an empty `enrollment_token` (fail-closed — no silent CIDR-only mode).

```bash
openssl rand -hex 32   # same value on master + every client
```
</details>

<details open>
<summary><b>2.2 Root CA pinning + server leaf (point 2 & 6)</b></summary>

The Root CA key **only signs**. The master serves TLS with a dedicated server
leaf (`server.crt`/`server.key`) issued by the CA; the served chain is
`[leaf‖root]` so pinning clients can verify it during bootstrap.

`verifyMasterPin` pins explicitly to the **Root CA**:
1. If `master_fingerprint` is set, a **CA** cert with that SHA-256 must be in
   the presented chain, and the leaf must chain to it (ServerAuth).
2. Else the leaf must chain to the locally installed Root CA.
3. Else **fail closed**.
</details>

<details open>
<summary><b>2.3 mTLS control plane (point 4)</b></summary>

`:8443` uses `RequireAndVerifyClientCert` with the Root CA as `ClientCAs`. Each
client receives a client-auth identity at enrollment. `/sync/cache`,
`/sync/crl`, and `/acme/sign-csr` are reachable only by authenticated clients.
</details>

<details open>
<summary><b>2.4 Pull-only replication (point 4)</b></summary>

There is **no `/cache/push`**. Clients pull `/sync/cache` and honor a monotonic
`X-Cache-Version`; a version lower than the local one is rejected (anti-replay /
stale protection). Writes are atomic (temp + rename); bodies are size-capped.
</details>

<details>
<summary><b>2.5 Issuance authorization model (point 3)</b></summary>

`/acme/new-order` was **removed**. There are two distinct issuance paths:

| Path | Who | Targets | Transport |
|---|---|---|---|
| `RunIssueCLI` (`--issue`) | **Admin on master** | any domain / IP / wildcard | CLI only (no network) |
| `/acme/sign-csr` | **Enrolled client** | loopback only | mTLS on `:8443` |

The client path is enforced twice — `enforceLoopbackOnly` (server) and
`SignCSR` (CA) — returning HTTP 403 for anything non-loopback. A compromised
client therefore cannot mint a certificate impersonating another host on the
shared CA.
</details>

---

## 3. Install

```bash
ARCH=$(uname -m); case "$ARCH" in x86_64) A=amd64;; aarch64|arm64) A=arm64;; esac
tar -xzf natssl-1.0.x-oss-linux-$A.tar.gz
sudo install -m0755 natssl-1.0.x-oss-linux-$A /usr/local/bin/natssl
sudo mkdir -p /etc/natssl /var/lib/natssl

# Firefox deps
sudo apt-get install -y libnss3-tools ca-certificates   # Debian/Ubuntu
sudo dnf install -y nss-tools                            # RHEL/Rocky

sudo cp config.master.yaml /etc/natssl/config.yaml       # master
sudo cp config.client.yaml /etc/natssl/config.yaml       # client
sudo chmod 600 /etc/natssl/config.yaml                   # token is secret
```

---

## 4. systemd

`natssl-master.service` / `natssl-client.service` ship with capability scoping
and filesystem hardening:

- **Master:** `CAP_NET_BIND_SERVICE` (bind `:443`), `ProtectSystem=strict`,
  only `/var/lib/natssl` writable.
- **Client:** `CAP_NET_RAW` (ICMP during the promotion safety chain),
  `ProtectSystem=full`, plus write access to the OS trust-store anchor dirs so
  it can install the Root CA.

```bash
sudo cp natssl-*.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now natssl-master   # or natssl-client
systemd-analyze security natssl-master.service
```

---

## 5. Rollout

```mermaid
flowchart TD
    T[openssl rand -hex 32] --> A[master --bootstrap]
    A --> FP[note SHA-256 fingerprint]
    A --> B[write 24 words OFFLINE]
    B --> C[set token + client_networks on master]
    C --> D[start natssl-master]
    FP --> E[client: master_address + master_fingerprint + token + recovery_public_key]
    E --> F[start natssl-client]
    F --> G[pin + fetch + install Root CA]
    G --> H[enroll: token + CIDR -> mTLS identity]
    H --> I[pull /sync/cache over mTLS]
```

---

## 6. Certificate Lifecycle

### 6.1 Administrator issuance (any target) — on the master

The master generates both the certificate and its private key. CLI only.

```bash
# Domain
sudo natssl --mode=master --issue "app.internal"

# IP address (v4 or v6)
sudo natssl --mode=master --issue "192.168.1.2"
sudo natssl --mode=master --issue "fd00::1"

# Wildcard
sudo natssl --mode=master --issue "*.internal"
```

| Target | SAN entry | Validity |
|---|---|---|
| Domain with a dot | `DNS:<name>` | 1 year |
| IPv4 / IPv6 | `IP Address:<ip>` | 1 year |
| Wildcard | `DNS:*.<suffix>` | 1 year |
| `--localhost` | `DNS:localhost` + loopback IPs | 1 year |

Files land in `/var/lib/natssl/issued/<sanitized-target>.{crt,key}` (key `0600`),
the record is written to the database, and the encrypted cache is rebuilt so the
issuance propagates to clients on their next pull.

```bash
# Confirm the SAN (browsers read SAN, not CommonName):
openssl x509 -in /var/lib/natssl/issued/192.168.1.2.crt \
  -noout -text | grep -A1 "Alternative Name"
```

> Single-label names without a dot (`myhost`) are rejected by
> `validIssuanceTarget` unless `--localhost` is passed.

### 6.2 Client issuance (loopback only) — on the client

```bash
sudo natssl --mode=client --issue "localhost" --localhost
natssl --mode=client --decrypt-key=/var/lib/natssl/issued/localhost.key.enc > key.pem
```

CSR-flow over mTLS; the private key is generated locally and never leaves the
client. If the master is down, issuance is blocked (ReadOnly).

### 6.3 Revoke

```bash
sudo natssl --mode=master --revoke "<serial-hex>"
# serial: openssl x509 -in <cert>.crt -noout -serial
```

Recorded, cache rebuilt, clients fetch `/sync/crl` on next pull.

---

## 7. Disaster Recovery

```mermaid
flowchart TD
    B[promote-to-master --token] --> C1[TCP 443/8443]
    C1 -->|alive| X[ABORT]
    C1 -->|dead| C2[ICMP/ARP]
    C2 -->|reachable| X
    C2 -->|silent| C3[local IP conflict]
    C3 -->|conflict| X
    C3 -->|ok| D[seed -> recovery key, verify vs pinned pub]
    D --> E[decrypt cache, parse snapshot]
    E --> F[restore CA byte-for-byte; verify fingerprint]
    F --> G[transactional RestoreSnapshot]
    G --> H[mode=master on new IP]
    H --> I[signed migration broadcast :8443/migrate]
    I --> J[clients verify Root-CA signature, update master_address]
```

Integrity: if `master_fingerprint` is set, promotion **aborts** unless the
restored CA's fingerprint matches. DB restore is a single transaction.

---

## 8. Hardening Status

| Risk | Status |
|---|---|
| Root CA as TLS key | ✅ Fixed — server leaf; CA signs only (`0600`) |
| `/acme/new-order` open | ✅ Removed; admin issuance CLI-only |
| Unauthenticated push | ✅ Removed; pull-only mTLS + versioning |
| Control-plane auth | ✅ mTLS, per-client identity |
| Spoofable registration | ✅ Mandatory token (fail-closed) + CIDR |
| Pin ambiguity | ✅ Pin to Root CA + chain verify |
| Revocation | ⚠️ List via `/sync/crl`; full CRL/OCSP = next step |
| Shared token | ⚠️ Rotate on compromise; one-time tokens |
| Migration transport | ⚠️ Unverified TLS, but payload signed by Root CA |

---

## 9. Diagnostics

```bash
journalctl -u natssl-master | grep AUDIT          # registration / signing / revocation
journalctl -u natssl-client | grep -i "pull\|enroll\|fingerprint\|stale"
nc -vz <master> 443 ; nc -vz <master> 8443

openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256
openssl x509 -in /var/lib/natssl/issued/192.168.1.2.crt -noout -text | grep -A2 "Alternative Name"
```

---

## 10. Common Errors

| Message | Meaning / Fix |
|---|---|
| `client_networks is set but enrollment_token is empty` | Fail-closed startup. Set a token on the master. |
| `invalid or missing enrollment token` (403) | Token mismatch — same value on both sides. |
| `not in any allowed client network` (403) | Widen `client_networks`. |
| `target not allowed for issuance` | Single-label name without a dot; add a dot, use an IP, or pass `--localhost`. |
| `master leaf does not chain to pinned Root CA` | Wrong/stale `master_fingerprint`, or a rogue master. |
| `cannot verify master: set master_fingerprint or install the Root CA first` | Fail-closed — set the fingerprint. |
| `clients may only request localhost ...` | Expected — use the master for domain/IP certs. |
| `rejecting stale cache vN (have vM)` | Anti-replay working; check master version counter. |
| `issue failed: master is OFFLINE` | ReadOnly — bring the master back or promote. |

---

## 11. FAQ

**Can I issue a certificate for an IP address?** Yes — on the master:
`natssl --mode=master --issue "192.168.1.2"`. The IP goes into the SAN as
`IP Address:`, valid 1 year. Clients cannot do this (loopback-only); it is an
administrator action.

**Why is the Root CA never the TLS key?** A network-facing key is exposed to
far more attack surface. The CA key only signs; a short-lived server leaf takes
the TLS role.

**How do clients trust the master before having the CA?** They pin
`master_fingerprint`; the served chain includes the root so verification
succeeds on first contact.

**What replaced push?** Authenticated pull over mTLS with monotonic versioning.
No inbound listener accepts cache data anymore.

**Can I rotate the enrollment token?** Yes — update master + clients; clients
re-enroll on the next `ping_interval`.
