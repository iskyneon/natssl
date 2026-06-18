# NATSSL

**Zero-Configuration Distributed TLS for Private Infrastructure.**

A single binary acting as a Certificate Authority (Root CA) for private
networks, with disaster recovery via a 24-word BIP-39 seed phrase — no mDNS,
no cloud.

![status](https://img.shields.io/badge/version-1.0.7--oss-blue)
![platform](https://img.shields.io/badge/linux-amd64%20%7C%20arm64-informational)

---

## Table of Contents
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Building](#building)
- [Quick Start](#quick-start)
- [Security Model](#security-model)
- [Client Auto-Registration](#client-auto-registration)
- [Issuing a Certificate as a Client (CSR-flow)](#issuing-a-certificate-as-a-client-csr-flow)
- [Revocation](#revocation)
- [Configuration](#configuration)
- [Disaster Recovery](#disaster-recovery)
- [Command Reference](#command-reference)
- [License](#license)

---

## Features

| Category | Capabilities |
|---|---|
| **Master** | Bootstrap Root CA (10y), CLI-only admin issuance, mTLS CSR signing, replicated AES-GCM-256 cache, revocation |
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

<details open>
<summary><b>1 → 2 → 3: token, master, client</b></summary>

```bash
# 1. Shared enrollment token (same value on master + every client)
openssl rand -hex 32

# 2. Master
sudo natssl --mode=master --bootstrap     # writes 24 words + prints fingerprint
#   - set enrollment_token + client_networks in /etc/natssl/config.yaml
sudo systemctl enable --now natssl-master
sudo natssl --mode=master --issue "app.internal"

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
<summary><b>Additional guarantees & honest gaps</b></summary>

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
> action on the master.

```bash
sudo natssl --mode=client --issue "localhost" --localhost   # over mutual TLS
natssl --mode=client --decrypt-key=/var/lib/natssl/issued/localhost.key.enc > key.pem
```

The leaf private key is generated locally and never leaves the machine. If the
master is unreachable, issuance is blocked (ReadOnly); existing certs keep
working.

---

## Revocation

```bash
# On the master:
sudo natssl --mode=master --revoke "<serial-hex>"
```

The revocation is recorded, the encrypted cache is rebuilt, and clients fetch
the updated list from `/sync/crl` on their next pull.

---

## Configuration

<details open>
<summary><b>Master / Client examples</b></summary>

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
the signed migration packet). See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## Command Reference

| Command | Purpose |
|---|---|
| `--mode=master --bootstrap` | Initialize Root CA + seed; print fingerprint |
| `--mode=master` | Run master (`:443` bootstrap, `:8443` mTLS) |
| `--mode=master --issue "X" [--localhost]` | CLI-only issuance (any target) |
| `--mode=master --revoke "<serial>"` | Revoke by hex serial |
| `--mode=client` | Run client (install CA, enroll, pull) |
| `--mode=client --issue "localhost"` | Issue a loopback cert (CSR-flow over mTLS) |
| `--mode=client --decrypt-key=FILE` | Decrypt a `.key.enc` to stdout |
| `--mode=client --promote-to-master --token="..."` | DR promotion |
| `--version` | Show version |

---

## License

Apache-2.0 (OSS). Clustering (Raft, N>1 masters) and one-time per-client
enrollment identities are part of the commercial edition.
