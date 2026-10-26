"""Exercise real Ansible roles on isolated local paths and real NATSSL processes.

System packages and systemd management are disabled; no OS trust stores change.
"""
import contextlib
import grp
import http.server
import importlib.util
import json
import os
from pathlib import Path
import pwd
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.request
import hashlib
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('natssl_filters', ROOT/'ansible/filter_plugins/natssl.py')
filters = importlib.util.module_from_spec(spec)
spec.loader.exec_module(filters)


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Filters(unittest.TestCase):
    def test_go_compatible_subjects(self):
        self.assertEqual(filters.canonical_subject('2001:0DB8::0001'), '2001:db8::1')
        self.assertEqual(filters.certificate_name('2001:0DB8::0001'), '2001_db8__1')
        self.assertEqual(filters.certificate_name(' App.INTERNAL '), 'app.internal')
        self.assertEqual(filters.certificate_name('*.internal'), '_.internal')
        for bad in ['node', '../../bad', 'app.internal;echo bad', 'bad_.internal', '*.bad.*', '']:
            with self.subTest(bad=bad), self.assertRaises(Exception):
                filters.canonical_subject(bad)


class Deployment(unittest.TestCase):
    def test_deployment_idempotence_enrollment_delivery_and_checksum(self):
        binary = Path(os.environ['NATSSL_TEST_BINARY']).resolve()
        version = yaml.safe_load((ROOT/'ansible/group_vars/all.yml').read_text())['natssl_release_tag']
        with tempfile.TemporaryDirectory(prefix='natssl-ansible-') as tmp:
            tmp = Path(tmp)
            api, mgmt = free_port(), free_port()
            master, client = tmp/'master', tmp/'client'
            for path in [master, client, tmp/'bin', tmp/'release'/version]:
                path.mkdir(parents=True, exist_ok=True)
            archive = tmp/'release'/version/f'natssl-{version}-oss-linux-amd64.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                tar.add(binary, arcname=f'natssl-{version}-oss-linux-amd64')
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            manifest = archive.parent/'SHA256SUMS.txt'
            manifest.write_text(checksum+'  '+archive.name+'\n')

            class Handler(http.server.SimpleHTTPRequestHandler):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, directory=str(tmp/'release'), **kwargs)
                def log_message(self, *args):
                    pass

            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
            token = os.urandom(32).hex()
            vars_ = {
                'ansible_connection': 'local', 'ansible_become': False,
                'ansible_python_interpreter': sys.executable,
                'ansible_remote_tmp': str(tmp/'remote-tmp'),
                'natssl_manage_services': False, 'natssl_manage_packages': False,
                'natssl_install_trust': False, 'natssl_show_recovery_seed': False,
                'natssl_file_owner': pwd.getpwuid(os.getuid()).pw_name,
                'natssl_file_group': grp.getgrgid(os.getgid()).gr_name,
                'natssl_bin': str(tmp/'bin/natssl'),
                'natssl_download_base': f'http://127.0.0.1:{server.server_port}',
                'natssl_enrollment_token': token,
                'natssl_client_networks': ['127.0.0.0/8'],
            }
            inventory = {
                'all': {'vars': vars_, 'children': {
                    'natssl_master': {'hosts': {'ca-master': {
                        'ansible_host': '127.0.0.1',
                        'natssl_conf_dir': str(master/'config'),
                        'natssl_data_dir': str(master/'state'),
                        'natssl_acme_listen': f'127.0.0.1:{api}',
                        'natssl_mgmt_listen': f'127.0.0.1:{mgmt}',
                    }}},
                    'natssl_clients': {'hosts': {'Node.INTERNAL': {
                        'ansible_host': '2001:0DB8::0001',
                        'natssl_conf_dir': str(client/'config'),
                        'natssl_data_dir': str(client/'state'),
                        'natssl_client_mgmt_listen': '127.0.0.1:0',
                        'natssl_ping_interval': '1s', 'natssl_pull_interval': '1s',
                    }}},
                }},
            }
            inv = tmp/'inventory.json'
            inv.write_text(json.dumps(inventory))
            extra = tmp/'vars.json'
            extra.write_text(json.dumps(vars_))
            extra.chmod(0o600)
            env = dict(os.environ, ANSIBLE_HOME=str(tmp/'ansible'),
                       ANSIBLE_LOCAL_TEMP=str(tmp/'ansible-tmp'),
                       ANSIBLE_CONFIG=str(ROOT/'ansible/ansible.cfg'),
                       ANSIBLE_NOCOLOR='1')

            def play(*args, success=True):
                cmd = ['ansible-playbook', str(ROOT/'ansible/playbook-install-natssl.yml'),
                       '-i', str(inv), '-e', '@'+str(extra), *args]
                result = subprocess.run(cmd, env=env, cwd=ROOT/'ansible', text=True,
                                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                if success and result.returncode:
                    self.fail('Ansible role execution failed:\n'+result.stdout.replace(token, '[redacted]'))
                if not success:
                    self.assertNotEqual(result.returncode, 0, 'Bad checksum was accepted')
                return result.stdout

            play()
            master_cfg = yaml.safe_load((master/'config/config.yaml').read_text())
            client_cfg = yaml.safe_load((client/'config/config.yaml').read_text())
            self.assertEqual(client_cfg['master_address'], f'127.0.0.1:{api}')
            self.assertEqual(client_cfg['master_mgmt_address'], f'127.0.0.1:{mgmt}')
            self.assertEqual(client_cfg['pull_interval'], '1s')
            self.assertEqual(client_cfg['enrollment_token'], token)
            self.assertEqual(client_cfg['recovery_public_key'], master_cfg['recovery_public_key'])
            self.assertEqual((client/'config/config.yaml').stat().st_mode & 0o777, 0o600)
            original_root = (master/'state/root-ca.crt').read_bytes()
            # Replay protection survives a subsequent Ansible configuration run.
            with (client/'config/config.yaml').open('a') as f:
                f.write('last_migration: "2026-01-01T00:00:00Z"\n')
            play()
            third = play()
            self.assertEqual(original_root, (master/'state/root-ca.crt').read_bytes())
            self.assertEqual(yaml.safe_load((client/'config/config.yaml').read_text())['last_migration'], '2026-01-01T00:00:00Z')
            self.assertRegex(third, r'ca-master\s+: ok=\d+\s+changed=0')
            self.assertRegex(third, r'Node.INTERNAL\s+: ok=\d+\s+changed=0')

            with contextlib.ExitStack() as stack:
                for mode, config in [('master', master/'config/config.yaml'), ('client', client/'config/config.yaml')]:
                    proc = subprocess.Popen([str(tmp/'bin/natssl'), '--mode='+mode, '--config='+str(config)],
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    stack.callback(lambda p=proc: (p.terminate(), p.wait(timeout=10)) if p.poll() is None else None)
                    if mode == 'master':
                        for _ in range(100):
                            try:
                                with socket.create_connection(('127.0.0.1', api), timeout=.1):
                                    break
                            except OSError:
                                time.sleep(.1)
                for _ in range(150):
                    if (client/'state/network-cache.enc').exists():
                        break
                    time.sleep(.1)
                self.assertTrue((client/'state/network-cache.enc').exists(), 'Ansible-rendered configs did not enroll and sync')
                context = ssl.create_default_context(cafile=str(client/'state/root-ca.crt'))
                context.load_cert_chain(str(client/'state/client-identity.crt'), str(client/'state/client-identity.key'))
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
                with opener.open(f'https://127.0.0.1:{mgmt}/sync/health') as response:
                    self.assertEqual(response.read(), b'ok')

                # This is the actual tagged, delegated issuance role, not a reimplementation.
                play('--tags', 'issue_client_certs', '-e', 'natssl_client_cert_subject=both')
                for name in ['node.internal', '2001_db8__1']:
                    cert = client/'state/issued'/f'{name}.crt'
                    key = client/'state/issued'/f'{name}.key'
                    self.assertEqual(cert.read_bytes(), (master/'state/issued'/cert.name).read_bytes())
                    self.assertEqual(key.read_bytes(), (master/'state/issued'/key.name).read_bytes())
                    self.assertEqual(key.stat().st_mode & 0o777, 0o600)
                cert = client/'state/issued/node.internal.crt'
                before = cert.read_bytes()
                again = play('--tags', 'issue_client_certs', '-e', 'natssl_client_cert_subject=both')
                self.assertEqual(before, cert.read_bytes())
                self.assertRegex(again, r'Node.INTERNAL\s+: ok=\d+\s+changed=0')
                play('--tags', 'issue_client_certs', '-e', 'natssl_client_cert_subject=both', '-e', 'natssl_reissue=true')
                self.assertNotEqual(before, cert.read_bytes())

            # A mismatched manifest must prevent installation, even in a clean target.
            manifest.write_text('0'*64+'  '+archive.name+'\n')
            bad = tmp/'bin/unverified-natssl'
            play('--limit', 'ca-master', '-e', 'natssl_bin='+str(bad), success=False)
            self.assertFalse(bad.exists(), 'Unverified binary was installed')


if __name__ == '__main__':
    unittest.main()
