# NATSSL — Ansible

Automated deployment of [NATSSL](https://github.com/iskyneon/natssl): one
**master** (Root CA) and N **clients** that self-register via `enrollment_token`
+ allowed subnets and pin the master's Root CA by SHA-256.

---

## Plays

| Play | Group | Role | Actions |
| --- | --- | --- | --- |
| 1. common | `natssl_master:natssl_clients` | `natssl_common` | arch-detect, dirs, nss-tools, install binary |
| 2. master | `natssl_master` | `natssl_master` | config → bootstrap (once) → start → export fingerprint + recovery key |
| 3. clients | `natssl_clients` | `natssl_client` | config (pin) → start → enroll |
| 4. issue *(opt, tag)* | `natssl_clients` | `natssl_issue` | issue a leaf cert on the master per client (sequential) and deliver it back |

> Play 4 is **opt-in** (`never` tag). Trigger with `--tags issue_client_certs`.

---

## Directory layout

```
ansible/
├── ansible.cfg
├── playbook-install-natssl.yml      # common → master → clients → (opt) issue
├── inventory/hosts.ini
├── group_vars/{all,vault,natssl_master,natssl_clients}.yml
└── roles/
    ├── natssl_common/
    ├── natssl_master/
    ├── natssl_client/
    └── natssl_issue/                # OPTIONAL, tag-gated
        ├── defaults/main.yml
        └── tasks/main.yml
```

---

## Inventory

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

> The `natssl_master` group must contain exactly one host.

> 🔎 Issuance by hostname requires an FQDN (dot / `.local` / `.internal`).
> `node-1` is not issuable by name — use the IP (default) or rename it.

---

## Variables — `roles/natssl_issue/defaults/main.yml`

| Variable | Default | Purpose |
| --- | --- | --- |
| `natssl_client_cert_subject` | `ip` | subject per client: `ip` / `hostname` / `both` |
| `natssl_reissue` | `false` | `true` ⇒ revoke current cert(s) and issue a fresh one (rotation) |
| `natssl_deliver_certs` | `true` | copy issued `.crt`/`.key` from master back to the client |
| `natssl_client_issued_dir` | `{{ natssl_data_dir }}/issued` | client-side delivery dir (`0700`) |

---

## Usage

```bash
cd ansible

# initial deploy
ansible-playbook playbook-install-natssl.yml --ask-vault-pass

# issue + deliver per-client certs (sequential, idempotent)
ansible-playbook playbook-install-natssl.yml --ask-vault-pass --tags issue_client_certs

# reissue (rotation): revoke + issue + redeliver
ansible-playbook playbook-install-natssl.yml --ask-vault-pass \
  --tags issue_client_certs -e natssl_reissue=true

# issue without delivery
ansible-playbook playbook-install-natssl.yml --ask-vault-pass \
  --tags issue_client_certs -e natssl_deliver_certs=false

# by FQDN (+ IP)
ansible-playbook playbook-install-natssl.yml --ask-vault-pass \
  --tags issue_client_certs -e natssl_client_cert_subject=both
```

---

## Day-2 operations

```bash
# issue / reissue (rotate) / revoke
ansible natssl_master -b -m command -a "/usr/local/bin/natssl --mode=master --issue app.internal --config=/etc/natssl/config.yaml"
ansible natssl_master -b -m command -a "/usr/local/bin/natssl --mode=master --reissue app.internal --config=/etc/natssl/config.yaml"
ansible natssl_master -b -m command -a "/usr/local/bin/natssl --mode=master --revoke <serial-hex> --config=/etc/natssl/config.yaml"

# inventory of state
ansible natssl_master -b -m command -a "/usr/local/bin/natssl --mode=master --list-certs   --config=/etc/natssl/config.yaml"
ansible natssl_master -b -m command -a "/usr/local/bin/natssl --mode=master --list-revoked --config=/etc/natssl/config.yaml"
ansible natssl_master -b -m command -a "/usr/local/bin/natssl --mode=master --list-clients --config=/etc/natssl/config.yaml"

# client management
ansible natssl_master -b -m command -a "/usr/local/bin/natssl --mode=master --deregister 192.168.10.21 --config=/etc/natssl/config.yaml"
ansible natssl_master -b -m command -a "/usr/local/bin/natssl --mode=master --block 192.168.10.21 --block-reason decommissioned --config=/etc/natssl/config.yaml"
ansible natssl_master -b -m command -a "/usr/local/bin/natssl --mode=master --unblock 192.168.10.21 --config=/etc/natssl/config.yaml"

# Root CA fingerprint + CRL
ansible natssl_master -b -m shell -a "openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256"
ansible natssl_master -b -m shell -a "openssl crl  -in /var/lib/natssl/root-ca.crl -noout -text | head -n 20"
```

> Administrative changes publish a new signed snapshot immediately. Clients
> receive it on their next `pull_interval` over mTLS; cache/CRL push is disabled.

Service status:
```bash
ansible natssl_master  -b -m command -a "systemctl status natssl-master --no-pager"
ansible natssl_clients -b -m command -a "systemctl status natssl-client --no-pager"
```

---

## Troubleshooting

<details>
<summary>Client: empty master_fingerprint</summary>

The fact is read from the native master after bootstrap. Run the full playbook;
client config receives both the Root CA pin and recovery public key.
</details>

<details>
<summary>Issuance: "target not allowed" / hostname skipped</summary>

Dot-less names are rejected. Use IP (default) or an FQDN with
`subject=hostname`/`both`.
</details>

<details>
<summary>Issuance: cert exists but not refreshed</summary>

Idempotent via `creates:`. Use `-e natssl_reissue=true` to revoke + reissue.
</details>


## Version and protocol compatibility

The default native release is **1.0.11** (`natssl_release_tag`); its package
version is derived automatically. Downloads are verified against the release's
`SHA256SUMS.txt` before extraction. Installing a changed binary restarts the
corresponding service. Native master/client binaries support both roles; the
GHCR image is master-only. These systemd roles deploy full native binaries
for both master and clients; they do not install the container image.

`group_vars/vault.yml` is explicitly loaded by the master/client plays. Put the
same `natssl_enrollment_token` there and encrypt it with `ansible-vault encrypt`.
Initial bootstrap displays the recovery phrase once: record it offline and
protect playbook output. Never replace an existing CA to upgrade binaries.

The client template includes both API addresses, custom ports, `pull_interval`,
`ping_interval`, the migration listener and `install_trust`. The master template
includes `server_names`; add any DNS aliases used by clients to
`natssl_server_names`. Existing recovery public keys and client migration replay
protection are preserved using YAML parsing. Signed migration requires a writable
config directory, which the client systemd unit permits.

Per-client issuance uses the native master over the administrative CLI. Delegated
paths come from that master's host variables; certificate names are canonicalized
exactly as the Go CLI (including compressed IPv6 and lowercase DNS names).
Private keys are delivered with mode 0600 and are suppressed from Ansible logs.
Specifying `hostname` for a dot-less inventory name fails with an explanation.

## Validation

```bash
pip install -r ../tests/requirements-ansible.txt
ansible-playbook playbook-install-natssl.yml --syntax-check
```

CI runs `tests/test_ansible.py` against the **real roles and native binary** in
private local directories. It checks checksum rejection, repeat deployment,
preserved CA/policy, real mTLS enrollment/pull from rendered configs, delegated
IPv6/DNS issuance, idempotent delivery and rotation. System packages/systemd
management are disabled for these isolated tests; no host trust stores change.
Deployment still requires supported Debian/RedHat Linux hosts and systemd.

For externally managed services/tests use `natssl_manage_services: false`;
`natssl_manage_packages` and `natssl_install_binary` can independently disable
those provisioning steps. Native file ownership defaults to root and is
configurable with `natssl_file_owner`/`natssl_file_group`. The normal deployment
keeps all provisioning enabled and checks HTTPS readiness plus client enrollment.
