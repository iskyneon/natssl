# NATSSL — Ansible

Automated deployment of [NATSSL](https://github.com/iskyneon/natssl) onto your
infrastructure: one **master** (Root CA) and N **clients** that self-register via
`enrollment_token` + allowed subnets and pin the master's Root CA by SHA-256.

The playbook is a wrapper around the `natssl` binary and its two systemd units
(`natssl-master.service`, `natssl-client.service`). It installs the binary, renders
the configs, performs a **one-time** CA bootstrap, and fans out the master's fingerprint
and `recovery_public_key` to clients via `hostvars`.

---

## What the playbook does

Three plays in order (`playbook-install-natssl.yml`), plus one **optional** tag-gated play:

| Play | Group | Role | Actions |
| --- | --- | --- | --- |
| 1. common | `natssl_master:natssl_clients` | `natssl_common` | arch-detect, directories, `nss-tools`/`libnss3-tools`, download+install binary |
| 2. master | `natssl_master` | `natssl_master` | config → bootstrap (once) → start → **export fingerprint + recovery key** as facts |
| 3. clients | `natssl_clients` | `natssl_client` | config (pin fingerprint from master's `hostvars`) → start → enroll |
| 4. issue *(opt, tag)* | `natssl_clients` | `natssl_issue` | **after a successful deploy:** issue a leaf cert **on the master** for every client (sequential, `serial: 1`) and optionally deliver `.crt`/`.key` back to the client |

> ⚠️ The playbook deliberately **does not** save the **24-word seed phrase** — it is
> printed once at bootstrap (the `natssl_master` role outputs it via `debug`).
> Record it **offline** right during the run. See [Secrets](#secrets).

> ℹ️ Play 4 is **opt-in only**. It carries the `never` tag, so a normal run never
> issues certs; you trigger it explicitly with `--tags issue_client_certs`.
> See [Per-client certificate issuance](#per-client-certificate-issuance).

---

## Directory layout

```
ansible/
├── ansible.cfg                      # inventory=inventory/hosts.ini, roles_path=roles, become
├── playbook-install-natssl.yml      # plays: common → master → clients → (opt) issue
├── inventory/
│   └── hosts.ini                    # groups natssl_master / natssl_clients
├── group_vars/
│   ├── all.yml                      # versions, paths, ports, intervals, client_networks
│   ├── vault.yml                    # enrollment_token (ENCRYPT with ansible-vault!)
│   ├── natssl_master.yml            # (empty — for master overrides)
│   └── natssl_clients.yml           # (empty — for client overrides)
└── roles/
    ├── natssl_common/
    │   └── tasks/main.yml           # arch map, dirs, certutil, download+install
    ├── natssl_master/
    │   ├── tasks/main.yml           # preserve recovery key → render → bootstrap → export facts
    │   ├── handlers/main.yml        # reload systemd / restart natssl-master
    │   └── templates/
    │       ├── config.master.yaml.j2
    │       └── natssl-master.service.j2
    ├── natssl_client/
    │   ├── tasks/main.yml           # resolve master → render (pin) → enroll
    │   ├── handlers/main.yml        # reload systemd / restart natssl-client
    │   └── templates/
    │       ├── config.client.yaml.j2
    │       └── natssl-client.service.j2
    └── natssl_issue/                # OPTIONAL, tag-gated: per-client issuance + delivery
        ├── defaults/main.yml        # subject mode, reissue flag, delivery toggle/dir
        └── tasks/main.yml           # issue on master (serial) → slurp → copy to client
```

---

## Requirements

- **Ansible** 2.14+ on the control node.
- Target hosts: Debian/Ubuntu (`libnss3-tools`) or RHEL/Rocky (`nss-tools`),
  architecture `x86_64` (→`amd64`) or `aarch64` (→`arm64`).
- SSH + root (`become: true`).
- Hosts must have access to **GitHub Releases** to download the tarball
  (see `natssl_download_base` in `group_vars/all.yml`).
- `openssl` must be present on the master — the role uses it to read the Root CA fingerprint.

---

## Inventory

`inventory/hosts.ini` (example from the repository):

```ini
[natssl_master]
ca-master ansible_host=192.168.10.5

[natssl_clients]
node-1 ansible_host=192.168.10.20
node-2 ansible_host=192.168.10.21
node-3 ansible_host=192.168.10.22

[natssl:children]
natssl_master
natssl_clients

[natssl:vars]
ansible_user=root
```

> The **`natssl_master` group must contain exactly one host** — the client takes it
> as `groups['natssl_master'][0]`.

> 🔎 **For issuance by hostname (Play 4):** NATSSL refuses dot-less DNS names. A subject
> is accepted only if it is an **IP**, or an FQDN that contains a dot / ends in
> `.local` / `.internal`. So `node-1` is **not** issuable by name — use the IP
> (default) or rename the host to e.g. `node-1.internal`. See
> [Per-client certificate issuance](#per-client-certificate-issuance).

---

## Variables

### `group_vars/all.yml` — common (editable)

| Variable | Default | Purpose |
| --- | --- | --- |
| `natssl_release_tag` | `1.0.8` | release git tag on GitHub |
| `natssl_pkg_version` | `1.0.8-oss` | version in the asset name and in `--version` |
| `natssl_download_base` | `https://github.com/iskyneon/natssl/releases/download` | download base |
| `natssl_bin` | `/usr/local/bin/natssl` | binary path |
| `natssl_conf_dir` | `/etc/natssl` | config directory (`0750`) |
| `natssl_conf_file` | `/etc/natssl/config.yaml` | the config itself (`0600`) |
| `natssl_data_dir` | `/var/lib/natssl` | CA keys + sqlite (`0700`) |
| `natssl_acme_listen` | `:443` | master bootstrap/ACME API |
| `natssl_mgmt_listen` | `:8443` | mTLS control-plane (pull-only) |
| `natssl_pull_interval` | `1h` | how often the master refreshes its own |
| `natssl_ping_interval` | `5m` | how often a client pings/refreshes |
| `natssl_client_networks` | `["192.168.10.0/24"]` | CIDRs from which self-enroll is allowed |

The downloaded asset name is assembled as:
```
natssl-{{ natssl_pkg_version }}-linux-{{ natssl_arch }}.tar.gz
# e.g. natssl-1.0.8-oss-linux-amd64.tar.gz
```

### `roles/natssl_issue/defaults/main.yml` — issuance (Play 4 only)

| Variable | Default | Purpose |
| --- | --- | --- |
| `natssl_client_cert_subject` | `ip` | what to use as the cert subject per client: `ip` (= `ansible_host`), `hostname` (= `inventory_hostname`, FQDN only), or `both` |
| `natssl_reissue` | `false` | when `true`, drops idempotency and **re-issues** (overwrites) the cert/key on the master — use for rotation |
| `natssl_deliver_certs` | `true` | copy the issued `.crt`/`.key` from the master back onto the client itself |
| `natssl_client_issued_dir` | `{{ natssl_data_dir }}/issued` | where on the **client** delivered leaf certs are placed (`0700`) |

> Subjects are auto-derived from the `[natssl_clients]` group — **nothing to type by
> hand**. With `subject=hostname`/`both`, dot-less names (like `node-1`) are skipped
> with a warning instead of failing the run.

### `group_vars/vault.yml` — secret (must be encrypted)

```yaml
natssl_enrollment_token: "REPLACE_WITH_openssl_rand_hex_32"
```

### Facts the master publishes for clients

After bootstrap, the `natssl_master` role sets the following via `set_fact`
(visible to clients through `hostvars`):

| Fact | Source |
| --- | --- |
| `natssl_master_fingerprint` | `openssl x509 ... -fingerprint -sha256` on `root-ca.crt` |
| `natssl_recovery_public_key` | read back from the rendered config after bootstrap |

The client pins them in `config.client.yaml.j2`:
```yaml
master_fingerprint: "{{ hostvars[_master].natssl_master_fingerprint }}"
recovery_public_key: "{{ hostvars[_master].natssl_recovery_public_key }}"
```

> Therefore you **must not run `client.yml` in isolation from the master play** in a
> single run — otherwise the master's facts won't be gathered. Run the full
> `playbook-install-natssl.yml`.

---

## Usage

### 1. Generate and encrypt the enrollment token

```bash
cd ansible

# token
openssl rand -hex 32          # paste into group_vars/vault.yml -> natssl_enrollment_token

# encrypt the vault
ansible-vault encrypt group_vars/vault.yml
```

### 2. Adjust the inventory and (if needed) `group_vars/all.yml`

- host addresses in `inventory/hosts.ini`;
- `natssl_client_networks` for your network;
- the release version, if you need something other than `1.0.8`.

### 3. Run the playbook

```bash
ansible-playbook playbook-install-natssl.yml --ask-vault-pass
```

> On the first run, `--bootstrap` will execute on the master and the output will show
> the **24-word seed phrase** (the `>>> RECORD THIS 24-WORD SEED OFFLINE NOW <<<` task).
> Write it down immediately — it is not printed again.

### Targeted runs (after the initial deployment)

```bash
# common only (update the binary)
ansible-playbook playbook-install-natssl.yml --tags ... # (no tags in roles yet — limit by hosts)

# restrict to part of the clients
ansible-playbook playbook-install-natssl.yml -l node-3 --ask-vault-pass
```

> Useful: to update a client, run the master play anyway (it's light and
> idempotent) — otherwise the client won't have the master's `hostvars` facts.

---

## Per-client certificate issuance

Play 4 (`natssl_issue`) issues a leaf certificate **on the master** for every host in
`[natssl_clients]`, then optionally delivers the `.crt`/`.key` back to the client. It is
designed to run **after a successful deploy** of the master and all clients.

Key properties:

- **Tag-gated** — the play carries `never`, so it runs **only** when you pass
  `--tags issue_client_certs`. A normal deploy never issues certs.
- **Zero manual subjects** — the target list comes straight from the
  `[natssl_clients]` group (`ansible_host` / `inventory_hostname`).
- **Strictly sequential** — `serial: 1` means one host is fully processed before the
  next; the delegated `--issue` commands on the master run host-by-host.
- **Idempotent** — uses `creates:` on the master's `issued/<subject>.crt`. Re-runs do
  nothing unless you ask for a reissue.

```bash
# Issue + deliver (by IP, idempotent):
ansible-playbook playbook-install-natssl.yml \
  --ask-vault-pass --tags issue_client_certs

# Deploy AND issue in one run:
ansible-playbook playbook-install-natssl.yml \
  --ask-vault-pass --tags all,issue_client_certs

# REISSUE (rotation) — overwrite certs on the master and redeliver:
ansible-playbook playbook-install-natssl.yml \
  --ask-vault-pass --tags issue_client_certs -e natssl_reissue=true

# Issue without delivery (keep files on the master only):
ansible-playbook playbook-install-natssl.yml \
  --ask-vault-pass --tags issue_client_certs -e natssl_deliver_certs=false

# Issue by FQDN hostname (+ IP) — hosts must be FQDNs (e.g. nas.internal):
ansible-playbook playbook-install-natssl.yml \
  --ask-vault-pass --tags issue_client_certs -e natssl_client_cert_subject=both
```

**Where files land**

- On the **master**: `/var/lib/natssl/issued/<subject>.crt` (`0644`) and `<subject>.key`
  (`0600`); the issuance is also recorded in sqlite and the encrypted cache is rebuilt.
- On the **client** (if `natssl_deliver_certs=true`): the same pair under
  `natssl_client_issued_dir` (default `/var/lib/natssl/issued`), `.key` as `0600`,
  `.crt` as `0644`. Delivery is done via `slurp` → `copy` (in-memory, nothing is left
  on the control node).

> 🔁 **Rotation note:** leaf certs are valid for 90 days. Because of `creates:`, an
> expired cert is **not** renewed automatically — always rotate with
> `-e natssl_reissue=true`.

> ⛔ **Dot-less hostnames** (`node-1`) are rejected by NATSSL for issuance. With
> `subject=ip` (default) this is a non-issue. With `hostname`/`both` such names are
> skipped with a warning; rename to `node-1.internal` to issue by name.

---

## Bootstrap and fingerprint flow

```
[common] arch → dirs → certutil → install natssl
                     │
                     ▼
[master] preserve recovery_public_key (if config already existed)
         → render config.master.yaml (0600)
         → install unit
         → bootstrap  (creates: /var/lib/natssl/root-ca.crt) ── 24 words + fingerprint
         → start natssl-master
         → openssl: read the Root CA fingerprint
         → set_fact: natssl_master_fingerprint, natssl_recovery_public_key
                     │  (via hostvars)
                     ▼
[client] resolve master (groups['natssl_master'][0])
         → render config.client.yaml  ← PIN fingerprint + recovery key + token
         → install unit
         → start natssl-client  (installs CA, enroll, periodic pull)
                     │
                     ▼ (optional, --tags issue_client_certs)
[issue]  for each client (serial:1):
         → natssl --issue <ip|fqdn>  ON THE MASTER  (creates: issued/<subject>.crt)
         → slurp .crt/.key from master → copy onto the client
```

Bootstrap idempotency is ensured by `creates: {{ natssl_data_dir }}/root-ca.crt` —
repeated runs do **not** touch the CA and do **not** regenerate the seed. And
`recovery_public_key` is preserved between runs (the role reads it back from the
existing config before rendering).

---

## Secrets

| What | Where | How to store |
| --- | --- | --- |
| `enrollment_token` | `group_vars/vault.yml` | `ansible-vault encrypt` — do **not** commit in plaintext |
| 24-word seed | bootstrap task output | **offline only**, the playbook does not write it to disk |
| `recovery_public_key` | `/etc/natssl/config.yaml` (master) | public — not a secret, but needed for DR |
| Root CA + key + sqlite | `/var/lib/natssl` (`0700`) | back it up! this is your CA |
| Issued leaf `.key` | `/var/lib/natssl/issued/*.key` (`0600`) | private keys of leaf certs — treat as secret |

Back up the CA from the master:
```bash
ansible natssl_master -b -m archive \
  -a 'path=/var/lib/natssl dest=/root/natssl-ca-backup.tar.gz format=gz'
```

---

## Day-2 operations

`exec` the binary on the master via ad-hoc:

```bash
# issue a certificate
ansible natssl_master -b -m command \
  -a "{{ '/usr/local/bin/natssl --mode=master --issue app.internal --config=/etc/natssl/config.yaml' }}"

# revoke by serial
ansible natssl_master -b -m command \
  -a "/usr/local/bin/natssl --mode=master --revoke <serial-hex> --config=/etc/natssl/config.yaml"

# Root CA fingerprint (what clients pin)
ansible natssl_master -b -m shell \
  -a "openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256"
```

Bulk issuance / rotation for all clients (preferred over ad-hoc — sequential & idempotent):
```bash
# issue for everyone in [natssl_clients]
ansible-playbook playbook-install-natssl.yml --ask-vault-pass --tags issue_client_certs

# rotate everyone
ansible-playbook playbook-install-natssl.yml --ask-vault-pass \
  --tags issue_client_certs -e natssl_reissue=true
```

Service status:
```bash
ansible natssl_master  -b -m command -a "systemctl status natssl-master --no-pager"
ansible natssl_clients -b -m command -a "systemctl status natssl-client --no-pager"
```

Version upgrade: bump `natssl_release_tag` / `natssl_pkg_version` in
`group_vars/all.yml` and run the playbook — `natssl_common` will compare against
`--version` and reinstall only if they differ.

---

## Troubleshooting

<details>
<summary>Client: empty master_fingerprint in the config</summary>

The `natssl_master_fingerprint` fact is gathered **only** in the master play. Run the
full `playbook-install-natssl.yml`, not `roles/natssl_client` in isolation.
Check that `natssl_master` has exactly one host and that `root-ca.crt` exists.
</details>

<details>
<summary>Binary download fails (404 / no network)</summary>

Check that the asset
`natssl-{{ natssl_pkg_version }}-linux-{{ natssl_arch }}.tar.gz` actually exists in
the `natssl_release_tag` release on GitHub. For air-gapped environments — host the
tarballs on an internal HTTP server and override `natssl_download_base`.
</details>

<details>
<summary>"the seed is no longer shown"</summary>

This is by design: bootstrap runs once (`creates: root-ca.crt`). If the seed wasn't
recorded — the only recovery path is via `recovery_public_key` / the DR procedure
(see `recovery.go` and `docs/DEPLOYMENT.md`), otherwise recreating the CA = new trust
for all clients.
</details>

<details>
<summary>certutil/NSS won't install</summary>

The role installs `libnss3-tools` (Debian/Ubuntu) or `nss-tools` (RHEL). If the package
isn't found — check the repositories/proxy on the target host.
</details>

<details>
<summary>Issuance: "target not allowed for issuance" / hostname skipped</summary>

NATSSL refuses dot-less DNS names. Issue by **IP** (`natssl_client_cert_subject=ip`,
the default), or give clients an FQDN (`node-1.internal`) and use
`subject=hostname`/`both`. Dot-less names are skipped with a warning, not a failure.
</details>

<details>
<summary>Issuance: cert exists but isn't refreshed</summary>

The issue task is idempotent via `creates:`. To re-issue/rotate (incl. expired certs),
run with `-e natssl_reissue=true` — this overwrites the cert/key on the master and
redelivers to the client.
</details>

---

## See also

- The project's main [`README.md`](../README.md)
- [`docs/DEPLOYMENT.md`](../docs/DEPLOYMENT.md) — manual deployment and the security model
- systemd units: [`natssl-master.service`](../natssl-master.service), [`natssl-client.service`](../natssl-client.service)
