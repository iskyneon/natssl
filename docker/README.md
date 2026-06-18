# NATSSL — master-only mode docker deployment

Runs the NATSSL private CA **master** (Root CA + mTLS control plane) in a container.
Mirrors the systemd unit: same binary path, config path, data dir, ports and caps.

## Quick start

# 0. Enter to docker directory
    cd docker
    cp .env.example .env

# 1. Generate the enrollment token
    openssl rand -hex 32                 # paste into master/config.yaml -> enrollment_token

# 2. Build the image
    docker compose build

# 3. ONE-TIME — bootstrap the Root CA (interactive, prints the 24-word seed!)
    docker compose run --rm natssl-master --mode=master --bootstrap --config=/etc/natssl/config.yaml
#   ⚠️ WRITE DOWN THE 24 WORDS OFFLINE — shown only once (recovery.go)
#   ⚠️ recovery_public_key is auto-written into master/config.yaml

# 4. Start the service
    docker compose up -d

# 5. Verify
    docker compose ps
    docker compose logs -f natssl-master


## Fingerprint (clients pin this)

    docker compose exec natssl-master \
      sh -c 'openssl x509 -in /var/lib/natssl/root-ca.crt -noout -fingerprint -sha256'

## Issue / revoke

    docker compose exec natssl-master natssl --mode=master --issue "app.internal" --config=/etc/natssl/config.yaml
    docker compose exec natssl-master natssl --mode=master --issue "172.16.1.2" --config=/etc/natssl/config.yaml
    docker compose exec natssl-master natssl --mode=master --revoke "<serial>"     --config=/etc/natssl/config.yaml

## Notes

- Ports 443 (enroll/CA) and 8443 (mTLS) must be reachable from client subnets.
- Set client_networks in master/config.yaml to the CIDRs allowed to self-enroll.
- Root CA + sqlite live in the `natssl-master-data` volume — back it up.
- The 24-word seed is the Disaster Recovery key: shown once, store offline.
- Never run `docker compose down -v` in production (wipes the CA volume).

