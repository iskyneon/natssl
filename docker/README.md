# NATSSL client-only container

`ghcr.io/iskyneon/natssl:1.0.10` runs only the **client** role, which is the
binary's default mode. Linux amd64 and arm64 are published in one image index.
Native release binaries are used for the master and disaster-recovery promotion.

The `clientonly` build policy rejects master mode, bootstrap, promotion and
administrative commands, including when bypassing the Docker entrypoint or
mounting a master-mode config. This restriction is independent of Compose.

## Start a client

```bash
cd docker
cp .env.example .env
cp client/config.example.yaml client/config.yaml
mkdir -p data
chmod 700 client data
chmod 600 client/config.yaml
```

Set `master_address`, `master_fingerprint`, `recovery_public_key` and the shared
`enrollment_token` from the **native master**. Set `NATSSL_UID`/`NATSSL_GID` in
`.env` to your host user's `id -u`/`id -g`, so the container can read the private
config and write `data/`. For custom master ports also set
`master_mgmt_address`.

```bash
docker compose pull
docker compose up -d
docker compose ps
docker compose logs --tail 50 natssl-client
```

For a local build use `docker compose up -d --build`. There is no ACME listener
or CA bootstrap command in the image. Outbound HTTPS to the native master's
443/8443 ports is sufficient for enrollment, issuance and pull replication.

The optional inbound 8443 mapping handles **signed migration announcements
only**, never cache/CRL push. It binds loopback by default. To receive remote
announcements set `MGMT_BIND` to a reachable host interface and restrict access
with the host firewall. Container promotion remains disabled.

## State and host trust

Config is mounted as a directory because signed migration updates use atomic
renames. `data/` retains the pinned Root CA, private client identity, signed
recovery cache and CRL across restarts. Keep both directories private and back
up state; removing the container does not remove these bind mounts.

The image runs as UID/GID 1000 by default with capabilities dropped in Compose.
It does **not** install trust anchors into the host or Firefox profiles.
`install_trust: false` is the container default. To trust the CA on the host,
verify the exported fingerprint and install `data/root-ca.crt` using the host's
supported trust-store tools. The normal native client keeps automatic OS/Firefox
installation enabled by default.

Health checks require an enrolled, valid client identity and a synchronized
cache. An unreachable master puts the client in READ-ONLY mode; synchronized
state is retained. New issuance requires the master.

## Issue a loopback certificate

```bash
docker compose exec natssl-client natssl --issue localhost --localhost
docker compose exec natssl-client natssl --decrypt-key=/var/lib/natssl/issued/localhost.key.enc
```

Issuance prompts for the private-key encryption password. Decryption writes the
PEM key to stdout; protect its destination. Domain/IP administration must run
on the native master, not inside this image.

## Publishing

`.github/workflows/container.yml` smoke-tests a real image against a native
master, checks the client-only policy and offline state retention, then publishes
`ghcr.io/iskyneon/natssl:<version>`, `<version>-oss` and `latest` for version tags.
Pull requests run the smoke test without publishing. A repository's existing
GHCR package must grant that repository Actions write access.
