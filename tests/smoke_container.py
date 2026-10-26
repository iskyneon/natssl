"""Run the client-only image against a real native master on an isolated port."""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.request


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run(*args, **kw):
    return subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kw)


image = os.environ['NATSSL_TEST_IMAGE']
binary = os.environ['NATSSL_TEST_BINARY']
for args in [('--mode=master',), ('--bootstrap',), ('--promote-to-master',),
             ('--mode=client', '--revoke=123')]:
    result = run('docker', 'run', '--rm', image, *args)
    assert result.returncode and 'client-only build' in result.stderr, (args, result.stderr)
# The restriction also holds when bypassing the image's entrypoint.
result = run('docker', 'run', '--rm', '--entrypoint', '/usr/local/bin/natssl', image, '--mode=master')
assert result.returncode and 'client-only build' in result.stderr, result.stderr

with tempfile.TemporaryDirectory(prefix='natssl-container-') as tmp:
    tmp = Path(tmp)
    api, mgmt = port(), port()
    master = tmp/'master.yaml'
    data = tmp/'master-state'
    config, state = tmp/'config', tmp/'client-state'
    config.mkdir(); state.mkdir()
    token = os.urandom(32).hex()
    master.write_text(f'''mode: master
data_dir: {data}
listen: {{acme: "127.0.0.1:{api}", mgmt: "127.0.0.1:{mgmt}"}}
enrollment_token: "{token}"
client_networks: ["127.0.0.0/8"]
''')
    master.chmod(0o600)
    result = run(binary, '--mode=master', '--bootstrap', '--config='+str(master))
    if result.returncode:
        raise RuntimeError(result.stderr)
    # Discard the temporary recovery phrase from stdout.
    del result
    fingerprint = run('openssl', 'x509', '-in', str(data/'root-ca.crt'), '-noout', '-fingerprint', '-sha256', check=True).stdout.strip().split('=')[1]
    (config/'config.yaml').write_text(f'''data_dir: /var/lib/natssl
install_trust: false
master_address: "127.0.0.1:{api}"
master_mgmt_address: "127.0.0.1:{mgmt}"
master_fingerprint: "{fingerprint}"
enrollment_token: "{token}"
listen: {{mgmt: "127.0.0.1:0"}}
pull_interval: 1s
ping_interval: 1s
''')
    (config/'config.yaml').chmod(0o600)
    native = subprocess.Popen([binary, '--mode=master', '--config='+str(master)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    container = None
    try:
        for _ in range(100):
            try:
                with socket.create_connection(('127.0.0.1', api), timeout=.1):
                    break
            except OSError:
                time.sleep(.1)
        result = run('docker', 'run', '--detach', '--network', 'host', '--cap-drop=ALL',
                     '--security-opt', 'no-new-privileges:true',
                     '--user', f'{os.getuid()}:{os.getgid()}',
                     '-v', f'{config}:/etc/natssl', '-v', f'{state}:/var/lib/natssl', image, check=True)
        container = result.stdout.strip()
        for _ in range(150):
            if (state/'network-cache.enc').exists():
                break
            if run('docker', 'inspect', '--format', '{{.State.Running}}', container).stdout.strip() != 'true':
                raise RuntimeError('Client exited: '+run('docker', 'logs', container).stderr.replace(token, '[redacted]'))
            time.sleep(.1)
        assert (state/'network-cache.enc').exists(), 'Container did not enroll and pull state'
        envelope = json.loads((state/'network-cache.enc').read_text())
        assert envelope['sequence'] > 0 and envelope['signature'], 'Unsigned cache persisted'
        context = ssl.create_default_context(cafile=str(state/'root-ca.crt'))
        context.load_cert_chain(str(state/'client-identity.crt'), str(state/'client-identity.key'))
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
        with opener.open(f'https://127.0.0.1:{mgmt}/sync/health') as response:
            assert response.read() == b'ok'
        # READ-ONLY must keep the already synchronized state and the process alive.
        native.terminate(); native.wait(timeout=10)
        time.sleep(1)
        before = (state/'network-cache.enc').read_bytes()
        time.sleep(2)
        assert run('docker', 'inspect', '--format', '{{.State.Running}}', container).stdout.strip() == 'true'
        assert before == (state/'network-cache.enc').read_bytes()
        print('Client-only Docker smoke passed: default client, blocked master/promotion, mTLS enrollment, signed pull and offline state retention.')
    finally:
        if container:
            run('docker', 'rm', '-f', container)
        if native.poll() is None:
            native.terminate(); native.wait(timeout=10)
