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
- [Выпуск сертификата клиентом (CSR-flow)](#выпуск-сертификата-клиентом-csr-flow)
- [Конфигурация](#конфигурация)
- [Аварийное восстановление](#аварийное-восстановление)
- [Безопасность](#безопасность)
- [Лицензия](#лицензия)

---

## Возможности

| Категория | Что умеет |
|---|---|
| **Master** | Bootstrap Root CA (10 лет), выпуск сертификатов, подпись CSR, реплицируемый AES-GCM-256 кэш |
| **Client** | Авто-установка Root CA в ОС и Firefox, **выпуск собственных сертификатов через CSR**, ReadOnly при падении мастера |
| **DR** | 24-словная seed (BIP-39), promote-to-master с восстановлением *идентичного* fingerprint |
| **Сеть** | IPv4/IPv6, статическое обнаружение, порты `443` (ACME) и `8443` (mTLS) |
| **Локалхост** | Сертификаты на `127.0.0.1`/`::1`/`localhost` сроком 1 год, режим *Same-PC only*, ключ зашифрован паролем |

---

## Архитектура

```
        ┌──────────────┐  443 ACME / 8443 mTLS   ┌──────────────┐
        │   MASTER      │ ───── issue / cache ───▶ │   CLIENT      │
        │  Root CA      │ ◀──── CSR sign ───────── │  Cert Store   │
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
# или без make:
./build.sh
```

Результат:

```
dist/
├── natssl-1.0.0-oss-linux-amd64.tar.gz
├── natssl-1.0.0-oss-linux-arm64.tar.gz
└── SHA256SUMS.txt
```

Упаковать весь исходный код в архив:

```bash
./pack.sh     # -> natssl-src.tar.gz
```

Установка бинарника:

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
```

### Client

Скопируйте `recovery_public_key` и `master_address` в `/etc/natssl/config.yaml`:

```bash
sudo systemctl enable --now natssl-client
```

---

## Выпуск сертификата клиентом (CSR-flow)

> **Кто может подписывать?** Только мастер (у него ключ Root CA).
> **Где живёт приватный ключ листа?** Только на вашей машине — он генерируется
> локально, в CSR уходит лишь публичная часть.

### Сертификат на localhost / 127.0.0.1 (Same-PC only, 1 год)

```bash
sudo natssl --mode=client --issue "localhost" --localhost
# ↳ утилита спросит пароль для шифрования приватного ключа
```

Результат:

```
✔ Certificate issued for "localhost"
  cert: /var/lib/natssl/issued/localhost.crt
  key : /var/lib/natssl/issued/localhost.key.enc  (encrypted, this PC only)
```

### Сертификат на внутренний домен/IP (90 дней)

```bash
sudo natssl --mode=client --issue "dev.internal"
sudo natssl --mode=client --issue "192.168.10.42"
```

### Расшифровать приватный ключ для использования

```bash
natssl --mode=client \
  --decrypt-key=/var/lib/natssl/issued/localhost.key.enc > /tmp/localhost.key
chmod 600 /tmp/localhost.key
```

Подключение в dev-сервере (Go-пример):

```go
cert, _ := tls.LoadX509KeyPair(
    "/var/lib/natssl/issued/localhost.crt",
    "/tmp/localhost.key",
)
srv := &http.Server{
    Addr:      ":8443",
    TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
}
```

Браузер уже доверяет сертификату — Root CA установлен клиентом в ОС и Firefox.

> ⚠️ Если мастер недоступен, выпуск новых сертификатов **блокируется**
> (ReadOnly). Ранее выданные продолжают работать до конца срока.

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
- Приватный ключ клиентского сертификата **не покидает машину** (CSR-flow) и
  хранится зашифрованным (scrypt N=2¹⁵ + AES-GCM-256) под паролем пользователя.
- Пакет миграции подписывается ключом Root CA и верифицируется клиентами.

> ⚠️ В OSS-версии транспорт раздачи кэша упрощён (`InsecureSkipVerify`).
> Для production включите пиннинг Root CA и строгий mTLS — см. раздел
> «Hardening» в `docs/DEPLOYMENT.md`.

---

## Полный список команд

| Команда | Назначение |
|---|---|
| `natssl --mode=master --bootstrap` | Инициализация Root CA + seed-фраза |
| `natssl --mode=master` | Запуск мастера (443 + 8443) |
| `natssl --mode=master --issue "X" [--localhost]` | Выдача (ключ генерит мастер) |
| `natssl --mode=client` | Запуск клиента (установка CA, пинг, приём кэша) |
| `natssl --mode=client --issue "X" [--localhost]` | **Выписать себе** (CSR-flow) |
| `natssl --mode=client --decrypt-key=FILE` | Расшифровать `.key.enc` в stdout |
| `natssl --mode=client --promote-to-master --token="..."` | Аварийная активация |
| `natssl --version` | Версия |

---

## Лицензия

Apache-2.0 (OSS-версия). Кластеризация (Raft, N>1 мастеров) — в коммерческой версии.
