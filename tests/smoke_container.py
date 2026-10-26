"""Verify a master-only container with a real native client and persistent CA."""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run(*args, **kw):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


image = os.environ['NATSSL_TEST_IMAGE']
binary = os.environ['NATSSL_TEST_BINARY']
for args in [('--mode=client',), ('--promote-to-master',), ('--decrypt-key=/tmp/unused.key.enc',)]:
    result = run('docker', 'run', '--rm', image, *args)
    assert result.returncode and 'master-only build' in result.stderr, (args, result.stderr)
result = run('docker', 'run', '--rm', '--entrypoint', '/usr/local/bin/natssl', image, '--mode=client')
assert result.returncode and 'master-only build' in result.stderr, result.stderr

with tempfile.TemporaryDirectory(prefix='natssl-master-container-') as tmp:
    tmp = Path(tmp)
    api, mgmt = port(), port()
    while mgmt == api:
        mgmt = port()
    config, state, client_state = tmp/'config', tmp/'master-state', tmp/'client-state'
    config.mkdir(); state.mkdir()
    token = os.urandom(32).hex()
    # Omit mode to verify that the compiled binary also defaults to master.
    (config/'config.yaml').write_text(f'''data_dir: /var/lib/natssl
listen: {{acme: "127.0.0.1:{api}", mgmt: "127.0.0.1:{mgmt}"}}
enrollment_token: "{token}"
client_networks: ["127.0.0.0/8"]
''')
    (config/'config.yaml').chmod(0o600)
    options = ['--network', 'host', '--cap-drop=ALL', '--security-opt', 'no-new-privileges:true',
               '--user', f'{os.getuid()}:{os.getgid()}',
               '-v', f'{config}:/etc/natssl', '-v', f'{state}:/var/lib/natssl']
    # A client config must remain forbidden even when mode is overridden by CLI.
    (config/'client.yaml').write_text('mode: client\n')
    result = run('docker', 'run', '--rm', *options, image, '--mode=master', '--config=/etc/natssl/client.yaml')
    assert result.returncode and 'master-only build' in result.stderr, result.stderr
    (config/'client.yaml').unlink()
    result = run('docker', 'run', '--rm', *options, image, '--bootstrap')
    if result.returncode:
        raise RuntimeError(result.stderr)
    del result  # Never retain the temporary recovery phrase from bootstrap stdout.
    root = state/'root-ca.crt'
    original_root = root.read_bytes()
    assert (state/'root-ca.key').stat().st_mode & 0o777 == 0o600
    fingerprint = run('openssl', 'x509', '-in', str(root), '-noout', '-fingerprint', '-sha256', check=True).stdout.strip().split('=')[1]
    context = ssl.create_default_context(cafile=str(root))
    public = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    container = native = None
    try:
        result = run('docker', 'run', '--detach', *options, image, check=True)
        container = result.stdout.strip()

        def ready():
            for _ in range(150):
                try:
                    with public.open(f'https://127.0.0.1:{api}/health', timeout=.5) as response:
                        assert response.read() == b'ok'
                        return
                except (OSError, urllib.error.URLError):
                    time.sleep(.1)
            raise RuntimeError('Container master did not become HTTPS-ready')

        ready()
        # Exercise the same curl/CA verification used by Compose health checks.
        health = run('docker', 'exec', container, 'curl', '-fsS', '--cacert', '/var/lib/natssl/root-ca.crt', f'https://127.0.0.1:{api}/health', check=True)
        assert health.stdout == 'ok'
        with public.open(f'https://127.0.0.1:{api}/ca') as response:
            assert response.read() == original_root
        try:
            public.open(f'https://127.0.0.1:{mgmt}/sync/health', timeout=2)
        except (OSError, urllib.error.URLError):
            pass
        else:
            raise AssertionError('Control plane accepted an anonymous connection')

        client = tmp/'client.yaml'
        client.write_text(f'''mode: client
data_dir: {client_state}
install_trust: false
master_address: "127.0.0.1:{api}"
master_mgmt_address: "127.0.0.1:{mgmt}"
master_fingerprint: "{fingerprint}"
enrollment_token: "{token}"
listen: {{mgmt: "127.0.0.1:0"}}
pull_interval: 1s
ping_interval: 1s
''')
        client.chmod(0o600)
        native = subprocess.Popen([binary, '--mode=client', '--config='+str(client)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(150):
            if (client_state/'network-cache.enc').exists():
                break
            if native.poll() is not None:
                raise RuntimeError('Native client exited')
            time.sleep(.1)
        envelope = json.loads((client_state/'network-cache.enc').read_text())
        assert envelope['sequence'] > 0 and envelope['signature']
        context = ssl.create_default_context(cafile=str(client_state/'root-ca.crt'))
        context.load_cert_chain(str(client_state/'client-identity.crt'), str(client_state/'client-identity.key'))
        control = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        with control.open(f'https://127.0.0.1:{mgmt}/sync/health') as response:
            assert response.read() == b'ok'
        key, csr = tmp/'leaf.key', tmp/'leaf.csr'
        run('openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', str(key), '-out', str(csr), check=True)
        body = json.dumps({'csr': csr.read_text(), 'localhost': True}).encode()
        with control.open(urllib.request.Request(f'https://127.0.0.1:{mgmt}/acme/sign-csr', data=body, headers={'Content-Type':'application/json'})) as response:
            leaf = json.load(response)['certificate']
        (tmp/'leaf.crt').write_text(leaf)
        run('openssl', 'verify', '-CAfile', str(root), '-verify_hostname', 'localhost', str(tmp/'leaf.crt'), check=True)

        # Administrative CLI is available inside the image, without mode flags.
        def admin(*args):
            return run('docker', 'exec', container, 'natssl', *args, check=True)
        admin('--issue=app.internal')
        cert = state/'issued/app.internal.crt'
        run('openssl', 'verify', '-CAfile', str(root), '-verify_hostname', 'app.internal', str(cert), check=True)
        first = cert.read_bytes()
        admin('--reissue=app.internal')
        assert first != cert.read_bytes()
        serial = run('openssl', 'x509', '-in', str(cert), '-noout', '-serial', check=True).stdout.strip().split('=')[1]
        admin('--revoke='+serial)
        assert 'REVOKED' in admin('--list-certs').stdout
        run('docker', 'restart', container, check=True)
        ready()
        assert root.read_bytes() == original_root, 'Restart changed the CA'
        assert 'REVOKED' in admin('--list-certs').stdout, 'Restart lost database state'
        run('docker', 'stop', container, check=True)
        time.sleep(1)
        before = (client_state/'network-cache.enc').read_bytes()
        time.sleep(2)
        assert native.poll() is None and (client_state/'network-cache.enc').read_bytes() == before
        print('Master-only Docker smoke passed: default master, client/promotion rejected, bootstrap, verified HTTPS, native client mTLS/pull/CSR, admin issue/reissue/revoke, persistent CA/restart and offline client state.')
    finally:
        if container:
            run('docker', 'rm', '-f', container)
        if native is not None and native.poll() is None:
            native.terminate(); native.wait(timeout=10)
