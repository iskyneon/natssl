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
- [Issuing Certificates as the Administrator (Master)](#issuing-certificates-as-the-administrator-master)
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
| **Master** | Bootstrap Root CA (10y), CLI-only admin issuance (any target), mTLS CSR signing, replicated AES-GCM-256 cache, revocation |
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
