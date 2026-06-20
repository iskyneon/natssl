# NATSSL

**Zero-Configuration Distributed TLS for Private Infrastructure.**

A single binary acting as a Certificate Authority (Root CA) for private
networks, with disaster recovery via a 24-word BIP-39 seed phrase — no mDNS,
no cloud.

![status](https://img.shields.io/badge/version-1.0.9--oss-blue)
![platform](https://img.shields.io/badge/linux-amd64%20%7C%20arm64-informational)

---

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Building](#building)
- [Quick Start](#quick-start)
- [Security Model](#security-model)
- [Issuing Certificates as the Administrator (Master)](#issuing-certificates-as-the-administrator-master)
- [Client Auto-Registration](#client-auto-registration)
- [Issuing a Certificate as a Client (CSR-flow)](#issuing-a-certificate-as-a-client-csr-flow)
- [Reissuing a Certificate](#reissuing-a-certificate)
- [Certificate & Client Management](#certificate--client-management)
- [Revocation](#revocation)
- [Configuration](#configuration)
- [Disaster Recovery](#disaster-recovery)
- [Command Reference](#command-reference)
- [License](#license)

---

## Features

| Category | Capabilities |
|---|---|
| **Master** | Bootstrap Root CA (10y), CLI-only admin issuance (any target), mTLS CSR signing, replicated AES-GCM-256 cache, revocation |
| **Management** | List issued / revoked certs, list registered clients; **reissue** (revoke+issue) a subject; **deregister** and **block/unblock** clients from the CLI |
| **Client** | Auto-install Root CA into OS + Firefox, auto-enroll (token + subnet), receive an **mTLS identity**, issue loopback certs for itself, ReadOnly when master is down |
| **Transport** | Bootstrap path **pinned to the Root CA**; control plane is **mutual TLS** on `:8443` |
| **Replication** | **Pull-only** encrypted cache with **monotonic versioning** (anti-replay/stale); no inbound push surface |
| **Isolation** | Root CA key **only ever signs** — TLS is served with a dedicated server leaf |
| **DR** | 24-word seed (BIP-39), promote-to-master restoring the *identical* fingerprint |
| **Localhost** | 1-year, Same-PC-only certs; private key encrypted with scrypt + AES-GCM |

---

## Architecture

```mermaid
flowchart LR
    subgraph M["MASTER"]
        RCA["Root CA<br/>(signs only)"]
        SRV["server leaf<br/>(TLS identity)"]
        DB["SQLite"]
        TOK["enrollment token"]
    end

    subgraph C["CLIENT"]
        CID["mTLS identity"]
        ENC["encrypted cache<br/>(versioned)"]
        PIN["pinned Root CA"]
    end

    C -- "GET /ca + enroll (443)<br/>pinned TLS + token" --> M
    M -- "issue client identity" --> C
    C -- "PULL /sync/cache (8443)<br/>MUTUAL TLS" --> M
    C -- "sign loopback CSR (8443)<br/>MUTUAL TLS" --> M
    M -. "AES-GCM(snapshot), key sealed<br/>by recovery PUBLIC key" .-> ENC
```

The Root CA private key signs the **server leaf**, the **client identities**,
and issued certificates — it is never used as an online TLS key.

---

## Requirements

- **Go 1.22+** (build)
- Linux: Ubuntu/Debian/CentOS/RHEL/Rocky
- Firefox integration: `certutil` (`libnss3-tools` / `nss-tools`)

---

## Building

```bash
make release         # cross-compile amd64 + arm64 tarballs into dist/
# or:
./build.sh
```

Output:

```
dist/
├── natssl-1.0.7-oss-linux-amd64.tar.gz
├── natssl-1.0.7-oss-linux-arm64.tar.gz
└── SHA256SUMS.txt
```

Pack the source tree:

```bash
./pack.sh            # -> natssl-src.tar.gz (git archive when in a repo)
```

Install:

```bash
tar -xzf natssl-1.0.7-oss-linux-amd64.tar.gz
sudo install -m 0755 natssl-1.0.7-oss-linux-amd64 /usr/local/bin/natssl
natssl --version
```

> Pure-Go build (`modernc.org/sqlite`, `CGO_ENABLED=0`) — no C toolchain, clean
> cross-compile.

---

## Quick Start

<details>
<summary>1 → 2 → 3: token, master, client</summary>

```bash
# 1. Shared enrollment token (same value on master + every client)
openssl rand -hex 32

# 2. Master
sudo natssl --mode=master --bootstrap     # writes 24 words + prints fingerprint
#   - set enrollment_token + client_networks in /etc/natssl/config.yaml
sudo systemctl enable --now natssl-master
sudo natssl --mode=master --issue "app.internal"
sudo natssl --mode=master --issue "192.168.1.2"

# 3. Client
#   set master_address, master_fingerprint, enrollment_token, recovery_public_key
sudo systemctl enable --now natssl-client
```

The client pins the master's Root CA, installs it, enrolls (token + CIDR), and
receives its own mTLS identity automatically.
</details>

---

## Security Model

Four independent controls:

| Control | Protects against | Mechanism |
|---|---|---|
| **Enrollment token** | Rogue self-registration / IP spoofing | Shared secret in `X-Enrollment-Token`, constant-time compare, **mandatory** when registration is on |
| **Root CA pinning** | Rogue master / MITM | Client verifies the master leaf chains to a **pinned Root CA** (by fingerprint, or the installed CA). Fail-closed |
| **mTLS control plane** | Unauthenticated callers on `:8443` | `RequireAndVerifyClientCert`; every client has its own identity cert |
| **Loopback-only clients** | Host impersonation via the shared CA | Clients can only mint `localhost`/`127.0.0.1`/`::1`; enforced client- and server-side |

<details>
<summary>Additional guarantees & honest gaps</summary>

- The Root CA key is isolated: it **only signs** (server leaf, client identities,
  certs). TLS is served with the server leaf — never the CA key.
- The recovery private key is **never written to disk**.
- The cache is AES-GCM-256 encrypted; its symmetric key is sealed with the
  recovery public key (NaCl SealedBox) — clients cannot decrypt it.
- Replication is **pull-only** with a **monotonic version**; stale/replayed
  caches are rejected. There is **no inbound cache-push surface**.
- HTTP handlers enforce method, 1 MiB body cap, timeouts, atomic writes, and
  emit `AUDIT` log lines.

**Residual gaps (OSS edition):**
- The enrollment token is **shared** — rotate after any client compromise.
  One-time/expiring join tokens are the next step (commercial edition).
- The signed migration broadcast (`:8443 /migrate`) is delivered over an
  unverified transport, but the **payload is ECDSA-signed by the Root CA** and
  verified by the receiver.
- Revocation is a propagated list (`/sync/crl`), not full CRL/OCSP yet.
</details>

---

## Issuing Certificates as the Administrator (Master)

The administrator can mint a certificate for **any** target directly on the
master via the CLI. This path never traverses the network — the master
generates both the certificate and its private key.

```bash
# Domain
sudo natssl --mode=master --issue "app.internal"

# IP address (v4 or v6)
sudo natssl --mode=master --issue "192.168.1.2"

# Wildcard
sudo natssl --mode=master --issue "*.internal"
```

| Target type | Goes into SAN as | Example |
|---|---|---|
| Domain (has a dot) | `DNS:` | `app.internal`, `nas.local` |
| IP address (v4/v6) | `IP Address:` | `192.168.1.2`, `fd00::1` |
| Wildcard | `DNS:` | `*.internal` |

**Validity:** 90 days. Re-issue with the same command to renew (a new serial is
minted; revoke the old one with `--revoke` if needed).

**Output files:**

```
/var/lib/natssl/issued/192.168.1.2.crt   # certificate (0644)
/var/lib/natssl/issued/192.168.1.2.key   # private key  (0600)
```

The certificate is also recorded in the database and the encrypted cache is
rebuilt automatically, so it propagates to clients on their next pull.

**Verify the SAN** (browsers ignore CommonName and read only the SAN):

```bash
openssl x509 -in /var/lib/natssl/issued/192.168.1.2.crt \
  -noout -text | grep -A1 "Alternative Name"
# X509v3 Subject Alternative Name:
#     IP Address:192.168.1.2
```

### Allowed targets

`validIssuanceTarget` accepts:
- any DNS name containing a dot (`app.internal`, `db.corp.lan`)
- the suffixes `.local` and `.internal` explicitly
- any valid IPv4 / IPv6 address

Single-label names without a dot (e.g. `myhost`) are rejected unless you also
pass `--localhost` (which forces a Same-PC-only loopback certificate).

> **Why is this CLI-only?** Arbitrary-target issuance is an administrator action
> by design. The networked `/acme/sign-csr` endpoint (over mTLS) is restricted
> to **loopback** targets, so a compromised client cannot mint a certificate
> impersonating another host on the shared CA. See the
> [Security Model](#security-model).

---

## Client Auto-Registration

Two gates must **both** pass: a valid **enrollment token** *and* a source IP
inside `client_networks`. On success the master issues the client an **mTLS
identity certificate** used for all `:8443` operations.

```bash
journalctl -u natssl-master | grep AUDIT
# AUDIT client 192.168.10.20 enrolled (issued mTLS identity)
```

---

## Issuing a Certificate as a Client (CSR-flow)

> **Hard rule:** clients may issue **only loopback** certs. Enforced locally,
> then again on the master (HTTP 403). Domain/IP certs are an administrator
> action on the master (see [above](#issuing-certificates-as-the-administrator-master)).

```bash
sudo natssl --mode=client --issue "localhost" --localhost   # over mutual TLS
natssl --mode=client --decrypt-key=/var/lib/natssl/issued/localhost.key.enc > key.pem
```

The leaf private key is generated locally and never leaves the machine. If the
master is unreachable, issuance is blocked (ReadOnly); existing certs keep
working.

---

## Reissuing a Certificate

To rotate a certificate for a host, **reissue** revokes the current
certificate(s) for that subject and issues a fresh one — in a single step on
the master:

```bash
sudo natssl --mode=master --reissue "192.168.1.2"
sudo natssl --mode=master --reissue "app.internal"
```

1. All active (non-revoked) certs for the subject are revoked (reason
   *superseded*) and added to the revocation list.
2. The encrypted cache is rebuilt so clients pick up the change on their next
   pull.
3. A new certificate is issued, overwriting `issued/<subject>.{crt,key}`.

Add `--localhost` to reissue a Same-PC-only loopback certificate.

---

## Certificate & Client Management

All commands run on the **master** and read/update the SQLite store; a running
master sees the changes immediately (same database).

```bash
# Certificates
sudo natssl --mode=master --list-certs       # serial, subject, SANs, expiry, status
sudo natssl --mode=master --list-revoked     # revoked serials

# Clients
sudo natssl --mode=master --list-clients     # IP + registered-at
sudo natssl --mode=master --deregister "192.168.10.21"   # drop from the registry

# Blacklist
sudo natssl --mode=master --block "192.168.10.21" --block-reason "decommissioned"
sudo natssl --mode=master --unblock "192.168.10.21"
sudo natssl --mode=master --list-blocked
```

<details>
<summary>deregister vs block</summary>

- **`--deregister`** removes the IP from the registry. If `natssl-client` is
  still running on that host, it **re-registers** on its next ping (token + CIDR
  still pass).
- **`--block`** additionally blacklists the IP: enrollment is denied regardless
  of token/CIDR, so the host stays out until `--unblock`.
</details>

---

## Revocation

```bash
# On the master:
sudo natssl --mode=master --revoke "<serial-hex>"
sudo natssl --mode=master --list-revoked
```

The revocation is recorded, the encrypted cache is rebuilt, and clients fetch
the updated list from `/sync/crl` on their next pull.

Find a certificate's serial:

```bash
openssl x509 -in /var/lib/natssl/issued/app.internal.crt -noout -serial
# serial=0A1B2C...
# or:
sudo natssl --mode=master --list-certs
```

---

## Configuration

<details>
<summary>Master / Client examples</summary>

```yaml
# config.master.yaml
mode: master
data_dir: /var/lib/natssl
listen: { acme: ":443", mgmt: ":8443" }
recovery_public_key: ""          # auto-filled on bootstrap
enrollment_token: "REPLACE_ME"   # REQUIRED when client_networks is set
client_networks:
  - "192.168.10.0/24"
pull_interval: 1h
```

```yaml
# config.client.yaml
mode: client
data_dir: /var/lib/natssl
master_address: "192.168.10.5"
master_fingerprint: "AB:CD:...:99"   # SHA-256 from master bootstrap
recovery_public_key: "<paste from master>"
enrollment_token: "REPLACE_ME"       # SAME value as the master
ping_interval: 5m
```
</details>

| Field | Where | Purpose |
|---|---|---|
| `enrollment_token` | both | Shared secret to enroll. **Mandatory** on the master when `client_networks` is set (fail-closed). |
| `master_fingerprint` | client | SHA-256 of the master Root CA. Clients pin to it. |
| `client_networks` | master | CIDRs allowed to self-register. |
| `recovery_public_key` | both | Auto-filled on bootstrap; needed to decrypt the cache during recovery. |

```bash
# fingerprint (also printed at bootstrap):
openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256
```

---

## Disaster Recovery

```bash
sudo natssl --mode=client --promote-to-master --token="word1 ... word24"
```

Safety chain before activation: TCP health (443/8443) → ICMP+ARP → local IP
conflict. The Root CA is restored **byte-for-byte** (same fingerprint), so
existing client pins keep working; only `master_address` changes (delivered via
the signed migration packet). The promoted master also restores the last
replicated **clients, issued certs, revoked serials and blacklist** from its
local encrypted cache. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## Command Reference

| Command | Purpose |
|---|---|
| `--mode=master --bootstrap` | Initialize Root CA + seed; print fingerprint |
| `--mode=master` | Run master (`:443` bootstrap, `:8443` mTLS) |
| `--mode=master --issue "X" [--localhost]` | CLI-only issuance (any domain / IP / wildcard) |
| `--mode=master --reissue "X" [--localhost]` | Revoke current cert(s) for X and issue a fresh one |
| `--mode=master --revoke "<serial>"` | Revoke by hex serial |
| `--mode=master --list-certs` | List issued certificates (serial, subject, expiry, status) |
| `--mode=master --list-revoked` | List revoked certificates |
| `--mode=master --list-clients` | List registered clients |
| `--mode=master --list-blocked` | List blacklisted IPs |
| `--mode=master --deregister "<IP>"` | Remove a client from the registry |
| `--mode=master --block "<IP>" [--block-reason "..."]` | Blacklist a client IP |
| `--mode=master --unblock "<IP>"` | Remove an IP from the blacklist |
| `--mode=client` | Run client (install CA, enroll, pull) |
| `--mode=client --issue "localhost"` | Issue a loopback cert (CSR-flow over mTLS) |
| `--mode=client --decrypt-key=FILE` | Decrypt a `.key.enc` to stdout |
| `--mode=client --promote-to-master --token="..."` | DR promotion |
| `--version` | Show version |

---

## License

Apache-2.0 (OSS).
