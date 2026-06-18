# NATSSL — Руководство по развёртыванию

## 1. Топология

| Роль | Кол-во (OSS) | Порты | Привилегии |
|---|---|---|---|
| Master | **1** (Raft отключён) | 443, 8443 | root (bind <1024, CAP_NET_RAW) |
| Client | N | 8443 (приём push) | root (установка CA) |

---

## 2. Установка из релиза

```bash
ARCH=$(uname -m); case "$ARCH" in
  x86_64) A=amd64;; aarch64|arm64) A=arm64;; esac

tar -xzf natssl-1.0.0-oss-linux-$A.tar.gz
sudo install -m0755 natssl-1.0.0-oss-linux-$A /usr/local/bin/natssl
sudo mkdir -p /etc/natssl /var/lib/natssl
```

Зависимости Firefox:

```bash
# Debian/Ubuntu
sudo apt-get install -y libnss3-tools ca-certificates
# RHEL/Rocky/CentOS
sudo dnf install -y nss-tools
```

---

## 3. systemd

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
sudo systemctl enable --now natssl-master   # или natssl-client
```

---

## 4. Жизненный цикл сертификата

```mermaid
sequenceDiagram
    participant C as Client
    participant M as Master (CA)
    C->>M: POST /acme/new-order {subject, sans}
    M->>M: Issue(leaf), store in SQLite
    M->>M: RebuildEncryptedCache (AES-GCM + sealed key)
    M-->>C: {certificate, private_key}
    M-->>C: push network-cache.enc (8443)
```

---

## 5. Сценарий катастрофы (DR)

```mermaid
flowchart TD
    A[Master уничтожен] --> B{promote-to-master --token}
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

### Проверка идентичности отпечатка

```bash
# До катастрофы (на старом мастере, если есть бэкап):
openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256

# После promote (на новом мастере) — значение совпадает.
openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256
```

---

## 6. Hardening (production)

| Риск | Действие |
|---|---|
| `InsecureSkipVerify` в транспорте | Заменить на `RootCAs` с пиннингом Root CA |
| `/cache/push` без mTLS | Требовать клиентский сертификат, подписанный Root CA |
| localhost private key в открытом виде | scrypt + AES-GCM, пароль пользователя |
| seed-фраза | хранить offline (бумага/HSM), не в pass-менеджере на узле |
| права на файлы | `root-ca.key`, `network-cache.enc` → `0600` (уже задано) |

---

## 7. Диагностика

```bash
# Проверить доступность мастера
nc -vz 192.168.10.5 443
nc -vz 192.168.10.5 8443

# Логи
journalctl -u natssl-master -f
journalctl -u natssl-client -f

# Проверить установку Root CA в системе
trust list | grep -A2 NATSSL          # RHEL family
ls -l /usr/local/share/ca-certificates/natssl-root.crt  # Debian family

# Проверить Root CA в Firefox-профиле
certutil -L -d sql:$HOME/.mozilla/firefox/<profile> | grep NATSSL
```

---

## 8. FAQ

**Почему нельзя «регенерировать» Root CA с тем же отпечатком без бэкапа?**
SHA-256 fingerprint — хеш DER-кодирования сертификата, включающего подпись CA
(недетерминированную для ECDSA). Единственный корректный способ — хранить
оригинальный сертификат и ключ в зашифрованном recovery-кэше и восстанавливать
их байт-в-байт. NATSSL делает именно так.

**Что если seed-фраза утеряна?**
Восстановление невозможно — кэш расшифровать нечем. Это by design
(zero-knowledge на стороне клиента).
