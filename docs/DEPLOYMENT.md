# NATSSL — Deployment Guide

This guide deploys one master and native clients on Linux using release
[1.0.11](https://github.com/iskyneon/natssl/releases/tag/1.0.11). Choose either a
native master or a master-only Docker container; clients use the native binary.
Go is needed only to build from source, not to run release binaries.

Start with the path that matches your deployment:

| Deployment path | What you prepare | Follow |
|---|---|---|
| Ansible-managed native master + clients | Controller, SSH/sudo/Python access, inventory and one vaulted token | [Automated deployment](#13-container-and-ansible-roles); roles install binaries/packages and connect clients for you |
| Manually managed native master + clients | Linux hosts and native packages/binaries | [Installation](#3-install), [units](#4-systemd), [native master](#51-native-master), then [client connection](#53-connect-a-native-client) |
| Docker master + native clients | Docker host plus native client hosts | [Docker master](#52-docker-master), then native installation/units and [client connection](#53-connect-a-native-client) |

The supplied Ansible playbook manages a native master, not Docker Compose.
Choose one owner for the master deployment; do not run the full native-master
playbook on a host already serving the same CA/ports through Docker.

Examples use master **192.168.10.5**, optional DNS name **ca.internal**, and
client **192.168.10.20** on **192.168.10.0/24**. Replace these with your actual
addresses. Configure DNS first if using a hostname.

## Contents

- [1. Topology](#1-topology)
- [2. Prepare addresses and enrollment settings](#2-prepare-addresses-and-enrollment-settings)
- [3. Install](#3-install)
- [4. systemd](#4-systemd)
- [5. Rollout](#5-rollout): [native master](#51-native-master), [Docker master](#52-docker-master), [client connection](#53-connect-a-native-client), [custom ports](#54-custom-ports-and-dns)
- [6. Certificate Lifecycle](#6-certificate-lifecycle)
- [7. Disaster Recovery](#7-disaster-recovery)
- [8. Configuration changes and backups](#8-configuration-changes-and-backups)
- [9. Diagnostics](#9-diagnostics)
- [10. Common Errors](#10-common-errors)
- [11. Deployment acceptance checks](#11-deployment-acceptance-checks)
- [12. Protocol upgrade and local development](#12-protocol-upgrade-and-local-development)
- [13. Container and Ansible roles](#13-container-and-ansible-roles)

## 1. Topology

| Connection | Destination | Purpose | Required? |
|---|---|---|---|
| Client → master | TCP 443 | Pinned HTTPS: fetch Root CA, token/CIDR enrollment | Yes |
| Client → master | TCP 8443 | mTLS: signed cache/CRL pull, loopback CSR signing | Yes |
| Promoted master → clients | TCP 8443 | Root-CA-signed migration announcement | Only for automatic address migration after DR |

The master has two listeners. Each native client also listens on 8443 for signed
migration announcements. Normal enrollment and synchronization need no inbound
client connection. Cache/CRL replication is **pull-only**.

For Docker, host **443 → container 9443** and host **8443 → container 8443**.
Configure clients with the reachable **host** IP/DNS name and published ports.
Do not point clients at container port 9443 unless you deliberately publish that
port on the host. Native master and native client services should normally run
on separate hosts because both use 8443.

## 2. Prepare addresses and enrollment settings

Before starting, choose the master address clients can reach, ensure DNS points
to it when using a name, and allow the two outbound connections from section 1.
Synchronize host clocks so certificate validation succeeds. Native deployments
need systemd and supported Debian/RedHat-family Linux on amd64/arm64.

Generate one token for this deployment and keep the same value on master and
clients. For Ansible put it in Vault; for manual deployment put it in each
private role config. The fingerprint and recovery public key become available
only **after the master is bootstrapped**.

### Connection settings and trust

| Control | Configuration / behavior |
|---|---|
| Enrollment | Same `enrollment_token` on master and clients, plus the client's observed source IP inside `client_networks`; empty master tokens and `REPLACE_ME` do not enable enrollment |
| Server identity | Dedicated TLS leaf signed by the Root CA; the CA key is used for signing, not as the online TLS key |
| Pinning | Client validates the pinned Root CA, server chain and host name; first contact fails closed without a fingerprint or trusted local Root CA |
| mTLS | Enrollment issues a private client identity; control-plane requests check registration, blacklist and revocation |
| Client issuance | Only loopback SANs; arbitrary domain/IP certificates are master CLI operations |
| Replication | Signed encrypted snapshots, persisted monotonic sequence and verified signed CRLs |

`server_names` on the master must include the host IP/DNS names used by clients.
This is especially important for Docker/NAT: the external host address is not
necessarily one of the container's own interface addresses.

## 3. Install

### 3.1 Native prerequisites

For the **manual** path, run on each native master/client host. Ansible installs
these dependencies itself; skip manual installation when using section 13.
Use the package command for your distro.

Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y curl openssl ca-certificates tar libnss3-tools iputils-ping
```

RHEL/Rocky/CentOS:

```bash
sudo dnf install -y curl openssl ca-certificates tar nss-tools iputils
```

`certutil` supports Firefox trust installation on clients. `ping` is required by
the native disaster-recovery safety checks. macOS binaries are also available,
but the systemd/Ansible and automatic OS-trust instructions here target Linux.

### 3.2 Download matching support files

On the Ansible controller, Docker host, or manually managed native host, obtain
the matching source archive. It supplies service units, Docker configs and
Ansible roles; downloading it does not build or install NATSSL:

```bash
set -euo pipefail
mkdir -p ~/natssl-install
cd ~/natssl-install
curl -fLO https://github.com/iskyneon/natssl/releases/download/1.0.11/natssl-src-1.0.11.tar.gz
curl -fLO https://github.com/iskyneon/natssl/releases/download/1.0.11/SHA256SUMS.txt
sha256sum --ignore-missing -c SHA256SUMS.txt
# Continue only if the downloaded archive reports OK.
tar -xzf natssl-src-1.0.11.tar.gz
```

The support files are now under `~/natssl-install/natssl/`. A Git checkout at
tag `1.0.11` is an alternative. Docker needs Engine/Compose on its host; Ansible
needs the controller prerequisites in section 13. Neither path requires a
manual native binary installation on the controller/Docker host.

### 3.3 Install the native binary manually

Only on **manually managed native** master/client hosts; Ansible does this for
managed nodes. From the directory prepared in 3.2:

```bash
set -euo pipefail
cd ~/natssl-install
case "$(uname -m)" in
  x86_64|amd64) A=amd64 ;;
  aarch64|arm64) A=arm64 ;;
  *) echo 'Unsupported architecture' >&2; exit 1 ;;
esac
curl -fLO "https://github.com/iskyneon/natssl/releases/download/1.0.11/natssl-1.0.11-oss-linux-$A.tar.gz"
sha256sum --ignore-missing -c SHA256SUMS.txt
tar -xzf "natssl-1.0.11-oss-linux-$A.tar.gz"
sudo install -m 0755 "natssl-1.0.11-oss-linux-$A" /usr/local/bin/natssl
sudo install -d -m 0750 /etc/natssl
sudo install -d -m 0700 /var/lib/natssl
natssl --version
```

The binary archive contains only the executable. The matching units are in the
source archive from 3.2. Both native roles use `/etc/natssl/config.yaml` by
default; create a different config on each host using section 5 and protect it
with mode **0600**.

## 4. systemd

Install **only the unit for this host's native role**. From `~/natssl-install`:

On the native master:

```bash
sudo install -m 0644 natssl/natssl-master.service /etc/systemd/system/natssl-master.service
sudo systemctl daemon-reload
```

On each native client:

```bash
sudo install -m 0644 natssl/natssl-client.service /etc/systemd/system/natssl-client.service
sudo systemctl daemon-reload
```

Do not start the native master before its one-time bootstrap, or the client
before filling its connection values. The ordered startup commands follow below.
A Docker master uses Compose, not `natssl-master.service` on the host.

## 5. Rollout

Choose **5.1 or 5.2** for the single master, then repeat **5.3** on every client.

### 5.1 Native master

**On 192.168.10.5**, generate the enrollment token:

```bash
openssl rand -hex 32
sudoedit /etc/natssl/config.yaml
```

Save this master config. Replace the token placeholder with the generated value:

```yaml
mode: master
data_dir: /var/lib/natssl
listen:
  acme: ":443"
  mgmt: ":8443"
server_names:
  - "192.168.10.5"
  - "ca.internal"
recovery_public_key: "" # populated by bootstrap; preserve it afterwards
enrollment_token: "REPLACE_ME"
client_networks:
  - "192.168.10.0/24"
pull_interval: 1h
```

Bootstrap **once**, then start the service:

```bash
sudo chmod 600 /etc/natssl/config.yaml
sudo natssl --mode=master --bootstrap --config=/etc/natssl/config.yaml
# Record the 24-word recovery phrase OFFLINE. It is not stored by NATSSL.
sudo systemctl enable --now natssl-master
sudo systemctl status natssl-master --no-pager
sudo curl -fsS --cacert /var/lib/natssl/root-ca.crt https://127.0.0.1/health
```

The health response must be `ok`. On an existing master, retain its config, CA
and database and start the service **without another bootstrap**.

Read the values needed by clients:

```bash
sudo openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256
sudo grep '^recovery_public_key:' /etc/natssl/config.yaml
```

Use the fingerprint value **after `=`**, with or without colons. Do not use the
fingerprint of the server leaf. Bootstrap fills the recovery public key in the
config automatically; do not clear it on the next deployment.

### 5.2 Docker master

The image is **master-only**. It supports bootstrap and administrative CLI
commands; client mode/configs and `--promote-to-master` are rejected. All clients
still use the native binary from section 3.

On the Docker host, from the extracted source directory:

```bash
cd ~/natssl-install/natssl/docker
cp .env.example .env
cp master/config.example.yaml master/config.yaml
mkdir -p data
chmod 700 master data
chmod 600 master/config.yaml
openssl rand -hex 32
```

Edit `.env` to match the host. Use the actual owner IDs from `id -u` / `id -g`:

```dotenv
NATSSL_VERSION=1.0.11-oss
NATSSL_IMAGE=ghcr.io/iskyneon/natssl:1.0.11
NATSSL_BIND=192.168.10.5
ACME_PORT=443
MGMT_PORT=8443
NATSSL_UID=1000
NATSSL_GID=1000
```

Save `master/config.yaml` with the same token/CIDRs as the intended clients:

```yaml
mode: master
data_dir: /var/lib/natssl
listen:
  acme: ":9443" # internal port; Compose publishes it as host 443
  mgmt: ":8443"
server_names:
  - "192.168.10.5" # the Docker HOST address used by clients
  - "ca.internal"
recovery_public_key: ""
enrollment_token: "REPLACE_ME"
client_networks:
  - "192.168.10.0/24"
pull_interval: 1h
```

Run the one-time bootstrap, record its recovery phrase, then start:

```bash
docker compose pull
docker compose run --rm natssl-master --bootstrap
# Record the displayed 24 words offline.
docker compose up -d
docker compose ps
docker compose exec natssl-master curl -fsS --cacert /var/lib/natssl/root-ca.crt https://127.0.0.1:9443/health
docker compose exec natssl-master openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256
grep '^recovery_public_key:' master/config.yaml
```

Clients use `192.168.10.5` (host port 443) and `192.168.10.5:8443`, exactly as in
the native-master example. Do **not** substitute `192.168.10.5:9443` while keeping
the default host mapping. `master/` is a writable directory mount because
bootstrap saves the recovery public key using an atomic rename; `data/` retains
the CA, database, issued certificates, cache and CRL across container restarts.

### 5.3 Connect a native client

**On 192.168.10.20**, install the native binary and client unit from sections 3–4.
Obtain the following values through your trusted administrative channel:

| Client field | Where to obtain it |
|---|---|
| `master_address` | Reachable master host IP/DNS and bootstrap/API port; default 443 |
| `master_mgmt_address` | Reachable control-plane host:port; defaults to master host on 8443 |
| `master_fingerprint` | Root CA SHA-256 from bootstrap or the master's `openssl x509` command above |
| `enrollment_token` | The same token configured on the master |
| `recovery_public_key` | Master's config after bootstrap; required for future native DR, not a private key |

The 24-word recovery phrase and `root-ca.key` remain with the administrator;
they are **not** client enrollment credentials and must not be copied into a
client config. Each client generates its own mTLS private key locally.

Create `/etc/natssl/config.yaml` on the client:

```yaml
mode: client
data_dir: /var/lib/natssl
master_address: "192.168.10.5"
master_mgmt_address: "192.168.10.5:8443"
master_fingerprint: "PASTE_MASTER_ROOT_CA_SHA256"
recovery_public_key: "PASTE_MASTER_RECOVERY_PUBLIC_KEY"
enrollment_token: "REPLACE_ME"
listen:
  mgmt: ":8443" # signed migration receiver on THIS client
install_trust: true
pull_interval: 1h
ping_interval: 5m
```

Replace every `PASTE_...` value and set `REPLACE_ME` to the real shared token
before starting. The client's observed source IP
must be inside the master's `client_networks` and not blacklisted. With NAT or
Docker port forwarding, check the IP reported in the master's logs rather than
assuming it equals the workstation's configured address.

```bash
sudo chmod 600 /etc/natssl/config.yaml
sudo systemctl enable --now natssl-client
sudo systemctl status natssl-client --no-pager
sudo journalctl -u natssl-client -n 50 --no-pager
```

On first startup the client:

1. Connects to the master API, checks the Root CA pin, server chain and hostname,
   then fetches `/ca`. There is no manual "accept unknown CA" step.
2. Sends enrollment token + its CSR to `/acme/register`; the master checks token,
   source CIDR and blacklist, then issues the mTLS identity.
3. Uses that identity on 8443 to pull `/sync/cache` and `/sync/crl`.
4. Verifies signatures/freshness and persists state; subsequent pulls follow
   `pull_interval`, and registration/health attempts follow `ping_interval`.

`install_trust: true` also attempts OS/Firefox trust installation on this client.
Check the trust-store messages separately from enrollment. Set it to `false`
when applications will use the explicit CA file instead; this does **not**
disable TLS pinning, enrollment or cache verification. The Root CA for the
connection is fetched automatically by NATSSL; a manual public-CA copy is only
needed for an independent `curl` diagnostic before first enrollment.

Verify on the client after successful enrollment:

```bash
sudo ls -l /var/lib/natssl/root-ca.crt \
  /var/lib/natssl/client-identity.crt /var/lib/natssl/client-identity.key \
  /var/lib/natssl/network-cache.enc /var/lib/natssl/root-ca.crl
sudo openssl verify -purpose sslclient -CAfile /var/lib/natssl/root-ca.crt /var/lib/natssl/client-identity.crt
sudo curl -fsS --cacert /var/lib/natssl/root-ca.crt \
  --cert /var/lib/natssl/client-identity.crt \
  --key /var/lib/natssl/client-identity.key \
  https://192.168.10.5:8443/sync/health
```

Expected: identity verification reports `OK`, mTLS health returns `ok`, and logs
contain `cache and signed CRL pulled from master`. The identity key is **0600**;
it is distinct from application certificate keys.

On a native master, confirm the client is registered:

```bash
sudo natssl --mode=master --config=/etc/natssl/config.yaml --list-clients
```

For a Docker master, use `docker compose exec natssl-master natssl --list-clients`
from its Compose directory. A PID/active service alone does not establish that
enrollment and synchronization succeeded.

### 5.4 Custom ports and DNS

For a **native** master using API 9443 and control 9843, replace its listen values:

```yaml
listen:
  acme: ":9443"
  mgmt: ":9843"
server_names: ["192.168.10.5", "ca.internal"]
```

On the client, replace the two endpoint fields (keep the remaining client config):

```yaml
master_address: "192.168.10.5:9443"
master_mgmt_address: "192.168.10.5:9843"
```

A custom API port does **not** change the default control port: specify
`master_mgmt_address` when control is not on 8443. For Docker, these fields use
the **published host ports** (`ACME_PORT` / `MGMT_PORT`), not internal listen ports.

For DNS use `ca.internal` / `ca.internal:8443` in the client; include `ca.internal`
in master `server_names` and ensure it resolves from the client. IPv6 endpoints
with ports must be bracketed, e.g. `[fd00::5]:443` and `[fd00::5]:8443`; put the
unbracketed IP `fd00::5` in `server_names`.

After changing a running service's config, restart that role (`systemctl restart
natssl-master`, `systemctl restart natssl-client`, or `docker compose restart
natssl-master`). Updating server SANs does not require a new CA/bootstrap.
Custom client migration ports are not announced by DR; use the standard client
receiver port 8443 for automatic migration notifications.

## 6. Certificate Lifecycle

### 6.1 Admin issuance (master)

Native master:

```bash
sudo natssl --mode=master --config=/etc/natssl/config.yaml --issue app.internal
sudo natssl --mode=master --config=/etc/natssl/config.yaml --issue 192.168.10.20
sudo natssl --mode=master --config=/etc/natssl/config.yaml --issue '*.internal'
```

Docker master: `docker compose exec natssl-master natssl --issue app.internal`.
Files are in master `data_dir/issued/`; standard certificates last 90 days.
Names are canonicalized (lowercase DNS, compressed IPv6, unsafe filename
characters replaced). Private keys are **0600**. Domain/IP certificate delivery
to applications is a separate admin operation; the encrypted recovery cache is
not a plaintext download of application keys for clients.

### 6.2 Reissue / rotate (master)

```bash
sudo natssl --mode=master --config=/etc/natssl/config.yaml --reissue app.internal
```

Generates a replacement, revokes previous certificates as superseded, updates
CRL/cache and replaces the files. For Docker, run the same flag via
`docker compose exec natssl-master natssl`. Clients see published changes on
the next pull, not via an inbound cache push.

### 6.3 Client issuance (loopback only)

On the enrolled native client:

```bash
sudo natssl --mode=client --config=/etc/natssl/config.yaml --issue localhost --localhost
```

This sends a locally generated CSR over mTLS and prompts for a password to
encrypt the local application private key. Outputs:
`/var/lib/natssl/issued/localhost.crt` and `localhost.key.enc`. Validity is one year;
only loopback names/IPs are permitted. It does not replace `client-identity.*`.

For an application requiring an unencrypted key, create a private output file:

```bash
umask 077
sudo natssl --mode=client --config=/etc/natssl/config.yaml --decrypt-key=/var/lib/natssl/issued/localhost.key.enc > localhost.key
```

Decryption prompts for the password; protect the resulting PEM file. If the
master is unreachable, new issuance fails in READ-ONLY mode while existing
certificates and cached state remain available.

### 6.4 Revoke & CRL

```bash
sudo natssl --mode=master --config=/etc/natssl/config.yaml --revoke SERIAL_HEX
sudo natssl --mode=master --config=/etc/natssl/config.yaml --list-revoked
sudo openssl crl -in /var/lib/natssl/root-ca.crl -noout -text
```

Find a serial with `--list-certs` or `openssl x509 -in CERT.crt -noout -serial`.
The master regenerates the signed X.509 CRL and publishes a signed encrypted
snapshot. Enrolled clients pull them from `/sync/crl` and `/sync/cache` over
mTLS; there is no public `/crl` or `/cache` replication endpoint.

### 6.5 Client management

```bash
sudo natssl --mode=master --config=/etc/natssl/config.yaml --list-clients
sudo natssl --mode=master --config=/etc/natssl/config.yaml --deregister 192.168.10.20
sudo natssl --mode=master --config=/etc/natssl/config.yaml --block 192.168.10.20 --block-reason decommissioned
sudo natssl --mode=master --config=/etc/natssl/config.yaml --unblock 192.168.10.20
sudo natssl --mode=master --config=/etc/natssl/config.yaml --list-blocked
```

Use the IP recorded by the master. Deregistration removes the registry entry;
a running client can register again on its next ping. Blocking additionally
denies enrollment and control requests, including existing TLS connections.
Unblocking permits registration again; it does not undo explicit certificate
revocation. For Docker, prefix master admin flags with
`docker compose exec natssl-master natssl`.

## 7. Disaster Recovery

DR is a **native client** operation; the master-only image does not support
`--promote-to-master`. Before promotion:

1. Fence/isolate the old master. Failed TCP/ICMP/ARP probes cannot distinguish
   an outage from a network partition and cannot guarantee absence of split-brain.
2. Confirm the client has a recent signed `network-cache.enc`, local Root CA,
   `recovery_public_key`, and the administrator's matching 24-word seed.
3. Ensure `ping` is installed and stop this host's client service to release 8443.

```bash
sudo systemctl stop natssl-client
sudo natssl --mode=client --config=/etc/natssl/config.yaml --promote-to-master --token="word1 ... word24"
```

Replace the placeholder with the actual seed on a trusted admin console. Promotion
checks liveness/address conflicts and the recovery key, verifies the signed
cache and pinned CA, then restores the original CA byte-for-byte, certificate
records, identities, revocations, blacklist, enrollment policy and counters.
The command starts the master in the foreground after updating its config and
sending signed address announcements. Stop that foreground process before
starting the master systemd unit; disable the old client unit. Section 4 shows
how to install the master unit on a former client.

Automatic announcements use the standard master ports and client receiver 8443.
For custom port deployments, update clients' endpoints manually. Clients that
missed the announcement also need an address update; their Root CA pin remains
the same. Freshness equals the last successful sync before the outage. Back up
master state/config and retain the recovery phrase offline.

## 8. Configuration changes and backups

Edit the config for the role you manage, then restart that role:

| Change | Action |
|---|---|
| Client master address/port, pin, token or pull interval | Edit client YAML and restart `natssl-client` |
| Master token, allowed CIDRs or `server_names` | Edit master config, restart native service or Compose master, then verify enrollment/HTTPS again |
| Token rotation | Update master and all client configs and restart the roles; applications' existing certificates are separate from enrollment |
| Native binary upgrade | Preserve config/state, replace binary, restart only its service |
| Docker upgrade | Preserve `master/` and `data/`, update `NATSSL_IMAGE`, run `docker compose pull && docker compose up -d` |
| Ansible configuration/upgrade | Edit inventory/group variables/Vault and rerun the full playbook; roles restart changed services |

Do not rerun bootstrap for these changes. Keep the CA pin and recovery public
key when retaining the same CA. For a filesystem backup, stop the master first
or use a SQLite-consistent backup procedure; copy its entire state directory
and config together, and protect private keys/token. Keep the recovery phrase
separately offline. A client backup should retain its config, Root CA, identity
and signed cache, not just application certificates.

## 9. Diagnostics

For a native role:

```bash
sudo journalctl -u natssl-master -n 100 --no-pager
sudo journalctl -u natssl-client -n 100 --no-pager
sudo openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256
sudo openssl crl -in /var/lib/natssl/root-ca.crl -noout -text
```

On a Docker master use `docker compose logs --tail 100 natssl-master` and inspect
its `master/` and `data/` mounts. Never regenerate a CA to fix a port/pinning issue.

Before enrollment, independently test the API with a **verified public** CA copy
obtained from the master through your administrative channel. For example, on
the native master export `sudo cat /var/lib/natssl/root-ca.crt > ~/natssl-root-ca.crt`
(or copy `data/root-ca.crt` on the Docker host), then transfer that public file to
the client. Match its SHA-256 fingerprint to the master's trusted output first:

```bash
openssl x509 -in /tmp/natssl-root-ca.crt -noout -fingerprint -sha256
curl -fsS --cacert /tmp/natssl-root-ca.crt https://192.168.10.5/health
```

The public `/health` returning `ok` proves API/TLS reachability. It does not prove
enrollment or control authorization: run the client identity verification and
mTLS `/sync/health` commands from section 5.3 for those. A failed curl without
`--cert`/`--key` on port 8443 is expected. Do not use `curl -k` to hide a pin/SAN error.

## 10. Common Errors

| Symptom/message | What to check |
|---|---|
| Timeout/refused connection | Client → reachable master **host** ports 443/8443; Docker port mapping, binding interface, firewall and listener conflicts |
| `master_address is required` | Client YAML must contain the reachable API endpoint |
| `invalid master_fingerprint` / `cannot verify master` | Paste the complete Root CA SHA-256 after `=`; a first client needs a real pin, not the example placeholder |
| `master certificate does not chain to pinned Root CA` / hostname mismatch | Correct Root CA, endpoint DNS/IP in `server_names`, DNS resolution and machine clock; restart master after SAN changes |
| `enrollment denied: token, network or blacklist` (403) | Same real token on both roles, actual observed source CIDR, `--list-blocked`; do not widen CIDRs blindly |
| `client is blocked, revoked or not registered` (403) | Master registry/blacklist/revocation state; unblocking does not un-revoke an identity |
| Missing identity/cache after service start | Client journal: initial Root CA fetch, token/CIDR enrollment, then mTLS pull; an active PID alone is insufficient |
| OS/Firefox trust error | Native client privileges, `certutil`, profile availability and trust-store tools; `install_trust` controls import separately from protocol trust |
| `master-only build` | You are using the Docker binary for a client/promotion command; install the full native release on clients |
| `Root CA already exists` | Retain existing master state; bootstrap is one-time, not an upgrade/restart command |
| READ-ONLY messages | Master temporarily unavailable; existing state is retained, new issuance needs the master |
| `target not allowed for issuance` | Use dotted DNS/IP on master; client CSR issuance is restricted to loopback |

## 11. Deployment acceptance checks

A deployment is connected when all of these hold:

1. The master answers verified HTTPS `/health` as `ok` at its published address.
2. The client's Root CA fingerprint matches the master's trusted fingerprint.
3. `--list-clients` on the master contains the client's observed source IP.
4. The client identity verifies for client authentication and its mTLS
   `/sync/health` request returns `ok`.
5. Client state includes the signed cache and CRL and the journal records a
   successful pull. With Ansible also check the role readiness results.

An active process alone is insufficient. Application certificates are a separate
post-enrollment step: choose loopback client issuance or administrative
master-issued domain/IP certificates from section 6.

## 12. Protocol upgrade and local development

Upgrade legacy pre-mTLS master/clients together and complete a fresh successful
sync. Unsigned legacy caches may be replaced by an authenticated signed snapshot,
but are never accepted as DR sources. Do not bootstrap over an existing CA.
The published 1.0.10 Docker image is client-only; 1.0.11 restores the intended
master-only image. Use full native binaries for clients.

For local development use private temporary state and unprivileged ports from
section 5.4; set `install_trust: false` on test clients to leave system trust alone.
Run `go vet ./...`, `CGO_ENABLED=1 go test -race ./...` and the documented builds.
CI includes real TLS/mTLS, signed-state and recovery tests, a Docker master/native
client smoke test, and isolated Ansible-role tests. Systemd/package management and
OS/Firefox trust on the target distribution require their own deployment check.

## 13. Container and Ansible roles

The Docker path is described in [5.2](#52-docker-master) and
[docker/README.md](../docker/README.md). This section automates **full native**
master and clients with the playbook described in
[ansible/README.md](../ansible/README.md). No Docker image is installed by those roles.

### 13.1 Prepare the Ansible controller and hosts

The controller needs Python 3.11+ and Ansible; the checked requirements use
`ansible-core 2.19.3`. Managed hosts need SSH access, Python 3, supported Linux
and sudo/root privileges. Set up/verify SSH host keys and authentication before
running the playbook. The roles install native packages/binaries, directories
and service units on the managed hosts.

Download/verify the support files on the controller using **3.2**, or check out
tag `1.0.11`. Do not perform the manual binary/unit installation from 3.3–4 on
Ansible-managed nodes.

```bash
cd ~/natssl-install/natssl
python3 -m venv ~/.venvs/natssl-ansible
. ~/.venvs/natssl-ansible/bin/activate
pip install -r tests/requirements-ansible.txt
cd ansible
```

### 13.2 Inventory

Edit `inventory/hosts.ini`, changing addresses and SSH user to your environment:

```ini
[natssl_master]
ca-master ansible_host=192.168.10.5

[natssl_clients]
node-1 ansible_host=192.168.10.20
node-2 ansible_host=192.168.10.21

[natssl:children]
natssl_master
natssl_clients

[natssl:vars]
ansible_user=deploy
ansible_become=true
```

Exactly one host belongs to `natssl_master`; its host must not also belong to
`natssl_clients`. Replace `deploy` with the actual SSH account. If sudo requires
a password, add `--ask-become-pass` to the Ansible commands below.

### 13.3 Shared variables and token

Adjust these entries in the existing `group_vars/all.yml`, preserving its other
path/service defaults:

```yaml
natssl_release_tag: "1.0.11"
natssl_server_names: ["192.168.10.5", "ca.internal"]
natssl_client_networks: ["192.168.10.0/24"]
natssl_acme_listen: ":443"
natssl_mgmt_listen: ":8443"
natssl_client_mgmt_listen: ":8443"
natssl_pull_interval: "1h"
natssl_ping_interval: "5m"
natssl_install_trust: true
```

`natssl_pkg_version` is derived from the release tag. Use
`natssl_master_address` / `natssl_master_mgmt_address` only to override the client
endpoints explicitly; by default the roles derive them from the master host and
its configured listen ports.

Generate `openssl rand -hex 32`, put the result in `group_vars/vault.yml`, then
encrypt that file. The example is a placeholder, not a usable deployment token:

```yaml
natssl_enrollment_token: "REPLACE_ME"
```

```bash
ansible-vault encrypt group_vars/vault.yml
# If it is already encrypted, edit it with: ansible-vault edit group_vars/vault.yml
```

The master/client plays explicitly load this Vault file. Keep the same shared
token there; no manual fingerprint or recovery public key needs to be entered
for each client in the inventory.

### 13.4 Deploy in the playbook's order

From `ansible/` on the controller:

```bash
ansible natssl_master:natssl_clients -m ping
ansible-playbook playbook-install-natssl.yml --syntax-check --ask-vault-pass
ansible-playbook playbook-install-natssl.yml --ask-vault-pass
```

The full run performs:

1. **Common:** platform detection, prerequisites, SHA-256-verified native binary
   installation, private config/state directories.
2. **Master:** config → one-time bootstrap → service startup/HTTPS readiness →
   fingerprint/recovery-public-key facts. Record the displayed recovery phrase
   offline and protect the initial playbook output.
3. **Clients:** render `/etc/natssl/config.yaml` with master endpoints, shared
   token and facts from the master → start services → enroll → verify identity
   and initial signed cache.

The resulting YAML corresponds to the complete examples in sections 5.1 and
5.3. The client generates its own mTLS private key during enrollment; Ansible
does not distribute the master CA private key to clients. Repeat the full
playbook for updates: existing CA/recovery/replay state is preserved and changed
binaries/configs restart the appropriate services.

### 13.5 Verify the managed deployment

```bash
ansible natssl_master -b -m command -a "systemctl status natssl-master --no-pager"
ansible natssl_clients -b -m command -a "systemctl status natssl-client --no-pager"
ansible natssl_master -b -m command -a "/usr/local/bin/natssl --mode=master --config=/etc/natssl/config.yaml --list-clients"
```

Use the mTLS health/state checks from section 5.3 on a client for an independent
end-to-end check. See section 10 and the client/master journal if a readiness
task fails; do not treat a successful SSH ping as NATSSL enrollment.

### 13.6 Optionally issue and deliver application certificates

Initial deployment does **not** mint domain/IP application certificates for every
node. The fourth play is opt-in (`never` / `issue_client_certs` tags) and uses
master admin CLI issuance, independently of client loopback-only CSR issuance:

```bash
ansible-playbook playbook-install-natssl.yml --ask-vault-pass --tags issue_client_certs
ansible-playbook playbook-install-natssl.yml --ask-vault-pass --tags issue_client_certs -e natssl_reissue=true
```

Default subjects are node addresses; files are delivered to client `issued/`
with keys mode 0600. Use `-e natssl_client_cert_subject=both` for IP plus FQDN
inventory names, or `-e natssl_deliver_certs=false` to keep files on the master.
A dot-less inventory alias is not a DNS certificate subject. Normal issuance is
idempotent; `natssl_reissue=true` performs rotation and redelivery. Further
variables and role details are in [ansible/README.md](../ansible/README.md).
