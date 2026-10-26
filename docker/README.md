# NATSSL master-only container

`ghcr.io/iskyneon/natssl:1.0.11` runs **only the master role**, which is also
the default. Linux amd64 and arm64 are published in one image index. Clients
run the full native release binaries, including when provisioned by Ansible.

The compiled `masteronly` policy rejects client mode, client configs, client
issuance/decryption and client-to-master promotion. Bypassing the Docker
entrypoint does not bypass this policy. Master bootstrap, administrative
issuance/reissue/revocation and the mTLS control plane are supported.

## Prepare the master

```bash
cd docker
cp .env.example .env
cp master/config.example.yaml master/config.yaml
mkdir -p data
chmod 700 master data
chmod 600 master/config.yaml
openssl rand -hex 32
```

Put the generated token into `enrollment_token`, set the allowed client CIDRs,
and replace `server_names` with the host IP/DNS names clients actually use.
The TLS leaf must contain those externally reachable names; a Docker bridge IP
alone is insufficient. Set `NATSSL_UID`/`NATSSL_GID` in `.env` to the directories'
owner (`id -u` / `id -g`).

The container runs without root/capabilities: internal port 9443 is mapped to
host port 443, and internal 8443 to host port 8443. Native clients use those
host ports. Set `NATSSL_BIND` to the intended host interface and allow access
from your client networks.

## Bootstrap once, then start

```bash
docker compose pull
docker compose run --rm natssl-master --bootstrap
# Record the displayed 24-word recovery phrase offline.
docker compose up -d
docker compose ps
docker compose logs --tail 50 natssl-master
```

Bootstrap defaults to master mode and atomically updates `recovery_public_key`
in `master/config.yaml`. The directory is mounted read/write for that rename.
For a local build use `docker compose build` before bootstrap/start.

Bootstrap only a new master state directory. For an existing master retain its
original config, CA key/certificate and database; do not bootstrap over them.
The client-only 1.0.10 image/state must not be treated as an initialized master.
Do not reuse a client state directory as the `data/` directory of a new CA.

## Verify and administer

```bash
openssl x509 -in data/root-ca.crt -noout -fingerprint -sha256
docker compose exec natssl-master natssl --issue app.internal
docker compose exec natssl-master natssl --reissue app.internal
docker compose exec natssl-master natssl --list-certs
docker compose exec natssl-master natssl --revoke SERIAL_HEX
```

Configure native clients with the published host address, Root CA fingerprint,
enrollment token and recovery public key. Their mTLS identities are issued on
enrollment; signed cache/CRL synchronization and CSR signing use port 8443.
Arbitrary domain/IP issuance remains administrative CLI-only.

`data/` retains the CA, database, CRL, cache and issued certificates across
container restarts. Back it up together with the private master config. Native
clients install trust on their own hosts; the master container does not install
trust into the Docker host or its browsers.

Disaster-recovery promotion is a native-client operation: fence the old master
and use the full native binary with the synchronized recovery state and seed.
The master-only image does not run a client or accept `--promote-to-master`.

## Publishing and verification

`.github/workflows/container.yml` builds the master-only image, rejects client
mode through direct flags/config/entrypoint override, bootstraps its CA and
runs a real native client against it. Smoke checks cover verified HTTPS,
mTLS enrollment/pull/CSR, CLI issue/reissue/revoke, persistent CA/database after
restart and offline client state retention. Version tags publish
`ghcr.io/iskyneon/natssl:<version>`, `<version>-oss` and `latest` for Linux
amd64/arm64. Pull requests run the same smoke checks without publishing.
