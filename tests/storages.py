# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""The storages of the tests of ofzhur.ansible.facts (test_facts.py) and
of host files in a storage (test_host_storage.py): a directory here, and
on Docker MinIO (S3), Consul, Vault and a directory over SSH on a Debian
container. Each test class of a storage starts its own container and
removes it when done; without Docker they are skipped.
"""

import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request

import test_host
import test_users

ROOT = test_host.ROOT


def load_storage():
    """module_utils/storage.py, loaded from its file: Python's standard library only."""
    spec = importlib.util.spec_from_file_location('ofzhur_storage', os.path.join(ROOT, 'plugins', 'module_utils', 'storage.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


storage = load_storage()


def ansible_core():
    """The version of ansible-core on PATH and its python."""
    r = subprocess.run(['ansible', '--version'], capture_output=True, text=True, check=True)
    version = tuple(int(x) for x in re.search(r'core (\d+)\.(\d+)', r.stdout).groups())
    python = re.search(r'python version = .*\((/[^()]*)\)\s*$', r.stdout, re.M).group(1)
    return version, python


VERSION, PYTHON = ansible_core()


def environment(extra):
    """A small environment: nothing of this machine's settings or credentials reaches Ansible."""
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'LC_CTYPE') if k in os.environ}
    env.update(extra)
    return env


def open_store(url, env):
    """The storage of url with the options that env sets (ANSIBLE_OFZHUR_STORAGE_*)."""
    options = {k[len(storage.ENV):].lower(): v for k, v in env.items() if k.startswith(storage.ENV)}
    return storage.open_store(url, options.get)


def http(method, url, body=None, headers=None):
    req = urllib.request.Request(url, method=method, headers=headers or {},
                                 data=json.dumps(body).encode() if body is not None else None)
    with urllib.request.urlopen(req, timeout=10) as r:
        out = r.read()
        return json.loads(out) if out.strip() else None


def wait(what, check, seconds=60):
    for _ in range(seconds):
        try:
            if check():
                return
        except (OSError, urllib.error.URLError, subprocess.SubprocessError):
            pass
        time.sleep(1)
    raise AssertionError(f'{what} does not answer')


class Directory:
    """A directory on this machine, a new one for each test."""

    ENV = {}

    def url(self, prefix):
        self.dir = tempfile.mkdtemp(prefix='ofzhur-storage-test-')
        self.addCleanup(shutil.rmtree, self.dir)
        return f'file://{self.dir}/{prefix}'

    def broken(self):
        """The environment of a run that the storage refuses, a secret that must not show, and the reason."""
        d = os.path.join(self.dir, self._testMethodName)
        os.makedirs(d, exist_ok=True)
        os.chmod(d, 0o300)  # not readable
        self.addCleanup(os.chmod, d, 0o700)
        return {}, None, 'Permission denied'


class Container:
    """A storage in a container of its own, for the tests of the class. SUITE (of the test file) and KIND
    name the container."""

    IMAGE = KIND = PORT = None
    RUN = ()
    COMMAND = ()
    ENV = {}

    @classmethod
    def setUpClass(cls):
        if not test_users.have_docker():
            raise unittest.SkipTest('Docker is not available')
        if test_users.docker('image', 'inspect', cls.IMAGE, check=False).returncode \
                and test_users.docker('pull', '-q', cls.IMAGE, check=False).returncode:
            raise unittest.SkipTest(f'{cls.IMAGE} is not available')
        cls.container = f'ofzhur-test-{cls.SUITE}-{cls.KIND}'
        test_users.docker('rm', '-f', cls.container, check=False)
        cls.addClassCleanup(test_users.docker, 'rm', '-f', cls.container, check=False)
        test_users.docker('run', '-d', '--name', cls.container, '-p', f'127.0.0.1::{cls.PORT}', *cls.RUN, cls.IMAGE, *cls.COMMAND)
        cls.address = test_users.docker('port', cls.container, f'{cls.PORT}/tcp').stdout.split()[0]
        cls.start()

    @classmethod
    def start(cls):
        pass


class MinIO(Container):

    IMAGE, KIND, PORT = 'quay.io/minio/minio', 'minio', 9000
    RUN = ('-e', 'MINIO_ROOT_USER=ofzhur-test', '-e', 'MINIO_ROOT_PASSWORD=ofzhur-test-secret')
    COMMAND = ('server', '/data')

    @classmethod
    def start(cls):
        def bucket():
            return test_users.docker('exec', cls.container, 'sh', '-c',
                                     'mc alias set t http://127.0.0.1:9000 ofzhur-test ofzhur-test-secret >/dev/null'
                                     ' && mc mb -p t/fleet >/dev/null', check=False).returncode == 0
        wait('MinIO', bucket)
        cls.ENV = {'ANSIBLE_OFZHUR_STORAGE_ENDPOINT': f'http://{cls.address}',
                   'ANSIBLE_OFZHUR_STORAGE_ACCESS_KEY': 'ofzhur-test',
                   'ANSIBLE_OFZHUR_STORAGE_SECRET_KEY': 'ofzhur-test-secret'}

    def url(self, prefix):
        return f's3://fleet/{prefix}'

    def broken(self):
        return {'ANSIBLE_OFZHUR_STORAGE_SECRET_KEY': 'Wr0ngS3cret'}, 'Wr0ngS3cret', 'SignatureDoesNotMatch'


class Consul(Container):

    IMAGE, KIND, PORT = 'hashicorp/consul', 'consul', 8500
    RUN = ('-e', 'CONSUL_LOCAL_CONFIG={"acl": {"enabled": true, "default_policy": "deny",'
                 ' "tokens": {"initial_management": "ofzhur-test-management"}}}')
    COMMAND = ('agent', '-dev', '-client', '0.0.0.0')

    @classmethod
    def start(cls):
        base, management = f'http://{cls.address}/v1', {'X-Consul-Token': 'ofzhur-test-management'}

        def policy():
            http('PUT', f'{base}/acl/policy', {'Name': 'fleet', 'Rules': 'key_prefix "fleet/" { policy = "write" }'}, management)
            return True
        wait('Consul', policy)
        token = http('PUT', f'{base}/acl/token', {'Policies': [{'Name': 'fleet'}]}, management)['SecretID']
        cls.ENV = {'ANSIBLE_OFZHUR_STORAGE_CONSUL_TOKEN': token}

    def url(self, prefix):
        return f'http+consul://{self.address}/fleet/{prefix}'

    def broken(self):
        return {'ANSIBLE_OFZHUR_STORAGE_CONSUL_TOKEN': '00000000-0000-0000-0000-000000000000'}, None, 'ACL not found'


class Vault(Container):

    IMAGE, KIND, PORT = 'hashicorp/vault', 'vault', 8200
    RUN = ('--cap-add', 'IPC_LOCK', '-e', 'VAULT_DEV_ROOT_TOKEN_ID=ofzhur-test-root',
           '-e', 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200')
    ROOT_TOKEN = 'ofzhur-test-root'

    POLICY = """
path "secret/data/fleet/*" { capabilities = ["create", "read", "update"] }
path "secret/metadata/fleet/*" { capabilities = ["list", "delete"] }
"""

    @classmethod
    def start(cls):
        base, root = f'http://{cls.address}/v1', {'X-Vault-Token': cls.ROOT_TOKEN}
        wait('Vault', lambda: http('GET', f'{base}/sys/health') is not None)
        http('PUT', f'{base}/sys/policies/acl/fleet', {'policy': cls.POLICY}, root)
        token = http('POST', f'{base}/auth/token/create', {'policies': ['fleet']}, root)['auth']['client_token']
        cls.ENV = {'ANSIBLE_OFZHUR_STORAGE_VAULT_TOKEN': token}

    def url(self, prefix):
        return f'http+vault://{self.address}/secret/fleet/{prefix}'

    def broken(self):
        return {'ANSIBLE_OFZHUR_STORAGE_VAULT_TOKEN': 'hvs.Wr0ngT0ken'}, 'hvs.Wr0ngT0ken', 'permission denied'

    def secret(self, path, data):
        """Writes a secret of KV version 2 by hand, as root."""
        http('POST', f'http://{self.address}/v1/secret/data/{path}', {'data': data}, {'X-Vault-Token': self.ROOT_TOKEN})


class SSH(Container):

    IMAGE, KIND, PORT = 'ofzhur-test-users:debian-trixie', 'ssh', 22

    @classmethod
    def setUpClass(cls):
        if test_users.have_docker():
            test_users.docker('build', '-q', '-t', cls.IMAGE, '-', input=test_users.DOCKERFILE.format(base='debian:trixie'))
        super().setUpClass()

    @classmethod
    def start(cls):
        cls.keys = tempfile.mkdtemp(prefix='ofzhur-storage-test-')
        cls.addClassCleanup(shutil.rmtree, cls.keys)
        for name in ('ump', 'other'):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', f'{cls.keys}/{name}'], check=True)
        with open(f'{cls.keys}/ump.pub') as f:
            test_users.docker('exec', '-i', cls.container, 'sh', '-c',
                              'install -d -m 700 -o ump -g ump /home/ump/.ssh && cat > /home/ump/.ssh/authorized_keys'
                              ' && chown ump:ump /home/ump/.ssh/authorized_keys', input=f.read())
        host, port = cls.address.rsplit(':', 1)
        cls.target = f'ump@{host}:{port}'
        cls.ENV = {'ANSIBLE_OFZHUR_STORAGE_SSH_ARGS': cls.ssh_args('ump')}
        wait('sshd', lambda: subprocess.run(['ssh', *shlex.split(cls.ssh_args('ump')), '-p', port, f'ump@{host}', 'true'],
                                            capture_output=True, timeout=20).returncode == 0)

    @classmethod
    def ssh_args(cls, key):
        return (f'-F /dev/null -i {cls.keys}/{key} -o IdentitiesOnly=yes'
                f' -o UserKnownHostsFile={cls.keys}/known_hosts -o StrictHostKeyChecking=accept-new')

    def url(self, prefix):
        return f'ssh://{self.target}/home/ump/fleet/{prefix}'

    def broken(self):
        return {'ANSIBLE_OFZHUR_STORAGE_SSH_ARGS': self.ssh_args('other')}, None, 'ssh: ump@127.0.0.1: Permission denied'
