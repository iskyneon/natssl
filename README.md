# NATSSL

**Zero-Configuration Distributed TLS for Private Infrastructure.**

Единый бинарник — Центр Сертификации (Root CA) для приватных сетей с
аварийным восстановлением по 24-словной seed-фразе (BIP-39), без mDNS и
без облака.

![status](https://img.shields.io/badge/version-1.0.0--oss-blue)
![platform](https://img.shields.io/badge/linux-amd64%20%7C%20arm64-informational)

---

## Содержание
- [Возможности](#возможности)
- [Архитектура](#архитектура)
- [Требования](#требования)
- [Сборка](#сборка)
- [Быстрый старт](#быстрый-старт)
- [Конфигурация](#конфигурация)
- [Аварийное восстановление](#аварийное-восстановление)
- [Безопасность](#безопасность)
- [Лицензия](#лицензия)

---

## Возможности

| Категория | Что умеет |
|---|---|
| **Master** | Bootstrap Root CA (10 лет), выпуск сертификатов, реплицируемый AES-GCM-256 кэш |
| **Client** | Авто-установка Root CA в ОС и Firefox, ReadOnly-режим при падении мастера |
| **DR** | 24-словная seed (BIP-39), promote-to-master с восстановлением *идентичного* fingerprint |
| **Сеть** | IPv4/IPv6, статическое обнаружение, порты `443` (ACME) и `8443` (mTLS) |
| **Локалхост** | Сертификаты на `127.0.0.1` сроком 1 год, режим *Same-PC only* |

---

## Архитектура

```
        ┌──────────────┐  443 ACME / 8443 mTLS   ┌──────────────┐
        │   MASTER      │ ───── issue / cache ───▶ │   CLIENT      │
        │  Root CA      │                          │  Cert Store   │
        │  SQLite       │ ◀──── pull (1h) ──────── │  (read-only   │
        │  recovery-pub │                          │   enc cache)  │
        └──────┬───────┘                          └──────┬───────┘
               │ AES-GCM-256(snapshot)                    │
               │ key sealed by recovery PUBLIC key        │
               ▼                                          ▼
        network-cache.enc  ───────── реплицируется ─────▶ хранится
                                                          «мёртвым грузом»
```

При катастрофе клиент с seed-фразой расшифровывает кэш и становится мастером
**с тем же серийным номером и SHA-256 отпечатком** Root CA.

---

## Требования

- **Go 1.22+** (для сборки)
- Linux: Ubuntu/Debian/CentOS/RHEL/Rocky
- Для интеграции с Firefox: `certutil`
  - Debian/Ubuntu: `apt-get install libnss3-tools`
  - RHEL/Rocky/CentOS: `dnf install nss-tools`

---

## Сборка

```bash
# Кросс-компиляция amd64 + arm64
make release
# или
./build.sh
```

Результат:

```
dist/
├── natssl-1.0.0-oss-linux-amd64.tar.gz
├── natssl-1.0.0-oss-linux-arm64.tar.gz
└── SHA256SUMS.txt
```

Установка:

```bash
tar -xzf natssl-1.0.0-oss-linux-amd64.tar.gz
sudo install -m 0755 natssl-1.0.0-oss-linux-amd64 /usr/local/bin/natssl
natssl --version
```

---

## Быстрый старт

### Master

```bash
sudo natssl --mode=master --bootstrap
# Запишите 24 слова OFFLINE — они показываются ОДИН раз!

sudo systemctl enable --now natssl-master
sudo natssl --mode=master --issue "app.internal"
sudo natssl --mode=master --issue "127.0.0.1" --localhost
```

### Client

Скопируйте `recovery_public_key` и `master_address` в `/etc/natssl/config.yaml`:

```bash
sudo systemctl enable --now natssl-client
```

---

## Конфигурация

`/etc/natssl/config.yaml`:

```yaml
mode: client
data_dir: /var/lib/natssl
listen:
  acme: ":443"
  mgmt: ":8443"
master_address: "192.168.10.5"
recovery_public_key: ""    # авто-заполняется на мастере при bootstrap
clients:
  - "192.168.10.20"
  - "192.168.10.21"
pull_interval: 1h
ping_interval: 5m
```

---

## Аварийное восстановление

```bash
sudo natssl --mode=client --promote-to-master \
  --token="word1 word2 ... word24"
```

Перед активацией выполняется **«цепочка соуса»**:

1. TCP health-check старого мастера (`443`/`8443`) → жив → **abort**.
2. ICMP + ARP (`/proc/net/arp`) → отвечает → **block**.
3. Конфликт локального IP со старым → **block**.

Подробнее — см. [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## Безопасность

- Приватный recovery-ключ **никогда не пишется на диск** мастера.
- Кэш сети зашифрован AES-GCM-256; симметричный ключ запечатан публичным
  recovery-ключом (NaCl SealedBox) → клиент не может расшифровать.
- Пакет миграции подписывается ключом Root CA и верифицируется клиентами.

> ⚠️ В OSS-версии транспорт раздачи кэша упрощён (`InsecureSkipVerify`).
> Для production включите пиннинг Root CA и строгий mTLS — см. раздел
> «Hardening» в `docs/DEPLOYMENT.md`.

---

## Лицензия

Apache-2.0 (OSS-версия). Кластеризация (Raft, N>1 мастеров) — в коммерческой версии.