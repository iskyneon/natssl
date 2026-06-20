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

> Revoke / reissue / block / unblock / deregister **propagate the cache + CRL to
> clients immediately** (no need to wait for the master's ticker).

Service status:
```bash
ansible natssl_master  -b -m command -a "systemctl status natssl-master --no-pager"
ansible natssl_clients -b -m command -a "systemctl status natssl-client --no-pager"
```

---

## Troubleshooting

<details>
<summary>Client: empty master_fingerprint</summary>

The fact is gathered only in the master play. Run the full playbook.
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

