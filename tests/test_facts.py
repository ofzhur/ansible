# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""Tests of the cache plugin ofzhur.ansible.facts.

They run the ansible CLI found on PATH against a repository laid out the
way the template expects, with the facts of two hosts of this machine
(connection local; the setup module gathers the facts of python alone)
in each storage of storages.py: a directory here, and on Docker MinIO
(S3), Consul, Vault and a directory over SSH on a Debian container.
Without Docker only the directory is tested. For another ansible-core,
put it first on PATH:

    python3 tests/test_facts.py
    PATH=/path/to/venv/bin:$PATH python3 tests/test_facts.py
"""

import json
import os
import re
import subprocess
import tempfile
import time
import unittest

import storages
import test_host
from storages import PYTHON, VERSION, environment

NAME = 'ofzhur.ansible.facts'
# the object of a host
SCHEMA = 's1_' if VERSION >= (2, 19) else ''

HOST = """\
plugin: ofzhur.ansible.host
groups: [common]
vars:
  ansible_connection: local
"""

# The password of the vault value below is ofzhur-test, its plain text "plain secret".
GATHER = """\
- hosts: all
  gather_facts: true
  gather_subset: ['!all', '!min', python]
  tasks:
    - ansible.builtin.set_fact:
        marker: "{{ inventory_hostname }} one"
        secret: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          64333832616430396536643937393265326235366337346137343336333463336634393865303266
          3136346261393039626438346663636233613064623863360a386333343061383538333433386333
          39623934313365383064653138363131353265323232356534636138356531663734643163656335
          3334353763313461360a666461306533373833336138323332396366643032386137646134313438
          3733
        template: !unsafe '{{ nothing }}'
        cacheable: true
"""

READ = """\
- hosts: all
  gather_facts: false
  tasks:
    - ansible.builtin.debug:
        msg:
          marker: "{{ hostvars[peer].ansible_facts.marker | default('') }}"
          python: "{{ hostvars[peer].ansible_facts.python.executable | default('') }}"
          secret: "{{ hostvars[peer].ansible_facts.secret | default('') }}"
          template: "{{ hostvars[peer].ansible_facts.template | default('') }}"
"""

# Run with the python of ansible-core, in the repository: the plugin as Ansible loads it.
HELPER = r"""
import json, sys
from ansible import constants as C
from ansible.plugins.loader import cache_loader, init_plugin_loader
init_plugin_loader()
cache = cache_loader.get('ofzhur.ansible.facts')
plugin = getattr(cache, '__wrapped__', cache)  # ansible-core >= 2.19: behind its interposer
module = sys.modules[type(plugin).__module__]
storage = sys.modules['ansible_collections.ofzhur.ansible.plugins.module_utils.storage']

def name(key):
    return module.object_name(plugin._prefix, cache._get_key(key) if hasattr(cache, '_get_key') else key)

out = []
for op, *args in json.loads(sys.argv[1]):
    if op == 'get':
        try:
            out.append(cache.get(args[0]))
        except KeyError:
            out.append('KeyError')
        continue
    if op == 'keys':
        r = sorted(cache.keys())
    elif op == 'set':
        r = cache.set(*args)
    elif op == 'contains':
        r = cache.contains(args[0])
    elif op == 'delete':
        r = cache.delete(args[0])
    elif op == 'flush':
        r = cache.flush()
    elif op == 'names':
        r = sorted(plugin._store.list(''))
    elif op == 'raw':
        r = plugin._store.read(name(args[0])).decode()
    elif op == 'age':
        doc = json.loads(plugin._store.read(name(args[0])))
        doc['time'] -= args[1]
        r = plugin._store.write(name(args[0]), json.dumps(doc).encode())
    elif op == 'page':
        storage.S3.PAGE = args[0]
        r = None
    out.append(r)
print(json.dumps(out))
"""

SIGV4_KEYS = ('AKIAIOSFODNN7EXAMPLE', 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY')
EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


def trusted(value):
    """value as ansible-core >= 2.19 keeps a string trusted as a template in its cache."""
    return {'value': value, 'tags': [{'__ansible_type': 'TrustedAsTemplate'}], '__ansible_type': '_AnsibleTaggedStr'}


class Storage:
    """The tests of one storage. A subclass of storages.py gives its URL (with a prefix of its own for each
    test) and environment."""

    SUITE = 'facts'

    def check_object(self, key):
        pass

    def setUp(self):
        self.infra = test_host.Infra({
            'inventory/hosts/web-01.yml': HOST,
            'inventory/hosts/db-01.yml': HOST,
            'inventory/group_vars/all.yml': 'ansible_python_interpreter: "{{ ansible_playbook_python }}"\n',
            'gather.yml': GATHER,
            'read.yml': READ,
            'vault-password': 'ofzhur-test\n',
        })
        self.addCleanup(self.infra.close)
        self.uri = self.url(self._testMethodName)
        self.env = dict(self.ENV, ANSIBLE_CACHE_PLUGIN=NAME, ANSIBLE_CACHE_PLUGIN_CONNECTION=self.uri,
                        ANSIBLE_VAULT_PASSWORD_FILE=os.path.join(self.infra.dir, 'vault-password'),
                        ANSIBLE_CALLBACK_RESULT_FORMAT='json')

    def call(self, *argv, env=None):
        return subprocess.run(argv, cwd=self.infra.dir, env=environment(dict(self.env, **(env or {}))),
                              capture_output=True, text=True)

    def ok(self, *argv, env=None):
        r = self.call(*argv, env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def helper(self, *ops, timeout=None):
        env = {'ANSIBLE_CACHE_PLUGIN_TIMEOUT': str(timeout)} if timeout is not None else None
        return json.loads(self.ok(PYTHON, '-c', HELPER, json.dumps(ops), env=env).stdout)

    def gather(self):
        r = self.ok('ansible-playbook', 'gather.yml')
        self.assertIn('ok=2', r.stdout)
        return r

    def peer(self, timeout=None):
        """What web-01 sees of db-01, with the facts of db-01 from the storage alone."""
        env = {'ANSIBLE_CACHE_PLUGIN_TIMEOUT': str(timeout)} if timeout is not None else None
        r = self.ok('ansible-playbook', 'read.yml', '--limit', 'web-01', '-e', 'peer=db-01', env=env)
        return json.loads(re.search(r'^ok: \[web-01\] => (\{.*?^\})', r.stdout, re.M | re.S).group(1))['msg']

    def plant(self, key, value):
        """An object written by someone else, with the facts value of a host."""
        storages.open_store(self.uri, self.env).write(SCHEMA + key, json.dumps({'time': time.time(), 'value': value}).encode())

    def test_share(self):
        self.gather()
        self.assertEqual(self.peer(), {
            'marker': 'db-01 one',
            'python': PYTHON,
            'secret': 'plain secret',
            'template': '{{ nothing }}',
        })
        self.assertEqual(self.helper(['keys']), [['db-01', 'web-01']])
        raw = self.helper(['raw', 'db-01'])[0]
        self.assertIn('$ANSIBLE_VAULT', raw)
        if VERSION < (2, 19):
            # ansible-core 2.19 and later store the plain text with the ciphertext
            self.assertNotIn('plain secret', raw)
        self.check_object('db-01')

    def test_planted_template(self):
        # facts are data: a template planted in the storage never runs on the control machine
        marker = os.path.join(self.infra.dir, 'planted')
        facts = {'marker': '{{ 6 * 7 }}', 'template': "{{ lookup('ansible.builtin.pipe', 'touch %s') }}" % marker}
        if VERSION >= (2, 19):
            facts = {'__payload__': json.dumps({k: trusted(v) for k, v in facts.items()})}
        self.plant('db-01', facts)
        self.assertEqual(self.peer(), {
            'marker': '{{ 6 * 7 }}',
            'python': '',
            'secret': '',
            'template': "{{ lookup('ansible.builtin.pipe', 'touch %s') }}" % marker,
        })
        self.assertFalse(os.path.exists(marker))

    def test_timeout(self):
        self.gather()
        self.helper(['age', 'db-01', 100])
        self.assertEqual(self.peer(timeout=50)['marker'], '')
        self.assertEqual(self.helper(['keys'], ['contains', 'db-01'], ['get', 'db-01'], timeout=50),
                         [['web-01'], False, 'KeyError'])
        self.assertEqual(self.peer(timeout=0)['marker'], 'db-01 one')
        self.assertEqual(self.helper(['keys'], timeout=0), [['db-01', 'web-01']])

    def test_flush(self):
        self.gather()
        self.helper(['set', 'gone-01', {'n': 1}])
        # --flush-cache: the facts of the hosts of the inventory (ansible-core >= 2.19), of the limit (earlier)
        self.ok('ansible-playbook', 'read.yml', '--flush-cache', '--limit', 'web-01', '-e', 'peer=db-01')
        self.assertEqual(self.helper(['keys']), [['gone-01'] if VERSION >= (2, 19) else ['db-01', 'gone-01']])
        # the plugin's flush: every object
        self.assertEqual(self.helper(['flush'], ['keys'], ['names']), [None, [], []])

    def test_names(self):
        keys = ['web-01', '10.0.0.1', 'fe80::1%eth0', 'a/b c', ' ~x~ ', 'ü']
        out = self.helper(*[['set', k, {'n': i}] for i, k in enumerate(keys)], ['keys'], *[['get', k] for k in keys],
                          ['delete', 'a/b c'], ['contains', 'a/b c'], ['get', 'a/b c'], ['keys'])
        n = len(keys)
        self.assertEqual(out[n], sorted(keys))
        self.assertEqual(out[n + 1:2 * n + 1], [{'n': i} for i in range(n)])
        self.assertEqual(out[2 * n + 2:], [False, 'KeyError', sorted(set(keys) - {'a/b c'})])

    def folder_marker(self):
        """PREFIX/, the folder a console makes, is no object: no warning, never deleted."""
        store = storages.open_store(self.uri, self.env)
        store.write('', b'')
        r = self.gather()
        self.assertNotIn('is not a cache object', r.stdout + r.stderr)
        self.assertEqual(self.helper(['names'], ['flush'], ['names']),
                         [sorted(SCHEMA + h for h in ('db-01', 'web-01')), None, []])
        self.assertEqual(store.read(''), b'')

    def test_refused(self):
        env, secret, reason = self.broken()
        r = self.call('ansible-playbook', 'gather.yml', env=env)
        out = r.stdout + r.stderr
        self.assertNotEqual(r.returncode, 0, out)
        self.assertIn(f'{NAME}: {self.uri}: ', out)
        self.assertIn(reason, out)
        self.assertNotIn('ssh: ssh:', out)
        if secret:
            self.assertNotIn(secret, out)


class Directory(storages.Directory, Storage, unittest.TestCase):

    def check_object(self, key):
        self.assertEqual(os.stat(os.path.join(self.dir, self._testMethodName, SCHEMA + key)).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.join(self.dir, self._testMethodName)).st_mode & 0o777, 0o700)

    def test_relative_path(self):
        # a plain path in ansible.cfg is relative to it, as the path of ansible.builtin.jsonfile
        cfg = os.path.join(self.infra.dir, 'ansible.cfg')
        with open(cfg) as f:
            text = f.read().replace('fact_caching = jsonfile', f'fact_caching = {NAME}')
        with open(cfg, 'w') as f:
            f.write(text)
        os.makedirs(os.path.join(self.infra.dir, 'sub'))
        env = environment({'ANSIBLE_CONFIG': cfg, 'ANSIBLE_VAULT_PASSWORD_FILE': self.env['ANSIBLE_VAULT_PASSWORD_FILE']})
        r = subprocess.run(['ansible-playbook', '-i', '../inventory', '../gather.yml'], cwd=os.path.join(self.infra.dir, 'sub'),
                           env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(sorted(os.listdir(os.path.join(self.infra.dir, '.cache', 'facts'))),
                         [SCHEMA + h for h in ('db-01', 'web-01')])

    def test_foreign_objects(self):
        # a warning that names the object and its host; the next facts replace it
        store = storages.open_store(self.uri, {})
        store.write(SCHEMA + 'db-01', b'not JSON')
        store.write(SCHEMA + 'web-01', json.dumps({'time': time.time(), 'value': ['a list']}).encode())
        # of the other scheme: no facts of this ansible-core replace it
        other = 's1_gone-01' if not SCHEMA else 'gone-01'
        store.write(other, b'not JSON')
        r = self.gather()
        squeezed = ''.join((r.stdout + r.stderr).split())
        for host in ('db-01', 'web-01'):
            self.assertIn(''.join(f'{self.uri}: {SCHEMA}{host} is not a cache object'.split()), squeezed)
            self.assertIn(''.join(f'the next facts of {host} replace it'.split()), squeezed)
        self.assertIn(''.join(f'{self.uri}: {other} is not a cache object'.split()), squeezed)
        self.assertIn('andisnotread;removeit', squeezed)
        self.assertNotIn(''.join(f'the next facts of {other} replace it'.split()), squeezed)
        self.assertEqual(self.peer()['marker'], 'db-01 one')


class Configuration(unittest.TestCase):
    """A configuration that cannot work fails the run, before any facts are gathered."""

    def setUp(self):
        self.infra = test_host.Infra({
            'inventory/hosts/web-01.yml': HOST,
            'inventory/group_vars/all.yml': 'ansible_python_interpreter: "{{ ansible_playbook_python }}"\n',
            'read.yml': READ,
        })
        self.addCleanup(self.infra.close)

    def assertFails(self, uri, *messages, env=None, secret=None):
        r = subprocess.run(['ansible-playbook', 'read.yml', '-e', 'peer=web-01'], cwd=self.infra.dir, capture_output=True, text=True,
                           env=environment(dict(env or {}, ANSIBLE_CACHE_PLUGIN=NAME, ANSIBLE_CACHE_PLUGIN_CONNECTION=uri)))
        out = r.stdout + r.stderr
        self.assertNotEqual(r.returncode, 0, out)
        self.assertNotIn('ok=', out)
        for m in messages:
            self.assertIn(m, out)
        if secret:
            self.assertNotIn(secret, out)
        return out

    def test_no_url(self):
        self.assertFails('', 'set fact_caching_connection')

    def test_unknown_scheme(self):
        self.assertFails('redis://localhost/facts', 'redis://localhost/facts: unknown scheme redis')

    def test_secrets_in_the_url(self):
        self.assertFails('s3://facts/x?secret_key=Sup3rS3cret', 's3://facts/x: a query string in the URL is not read',
                         secret='Sup3rS3cret')
        self.assertFails('ssh://ump:Sup3rS3cret@203.0.113.1/srv/facts', 'ssh://ump@203.0.113.1/srv/facts: a password',
                         secret='Sup3rS3cret')
        self.assertFails('vault://hvs.Sup3rS3cret@127.0.0.1:8200/secret/facts', 'vault://127.0.0.1:8200/secret/facts: a user',
                         secret='Sup3rS3cret')

    def test_missing_credentials(self):
        # the variables of the storages' own clients are never read: they are ump's
        clients = {'AWS_ACCESS_KEY_ID': 'AKIA', 'AWS_SECRET_ACCESS_KEY': 'secret', 'VAULT_TOKEN': 'hvs.token',
                   'CONSUL_HTTP_TOKEN': 'token'}
        self.assertFails('s3://facts/x', 'the access key and the secret key are missing', '[ofzhur_storage]', env=clients)
        self.assertFails('r2://0123456789abcdef0123456789abcdef/facts', 'the access key and the secret key are missing',
                         env=dict(clients, ANSIBLE_OFZHUR_STORAGE_ACCESS_KEY='AKIA'))
        self.assertFails('vault://127.0.0.1:8200/secret/facts', 'vault://127.0.0.1:8200/secret/facts: the token is missing',
                         'ANSIBLE_OFZHUR_STORAGE_VAULT_TOKEN_FILE', env=clients)
        self.assertFails('s3://facts/x', 'secret_key_file: No such file or directory',
                         env={'ANSIBLE_OFZHUR_STORAGE_ACCESS_KEY': 'AKIA', 'ANSIBLE_OFZHUR_STORAGE_SECRET_KEY': 'secret',
                              'ANSIBLE_OFZHUR_STORAGE_SECRET_KEY_FILE': '/nonexistent/key'})

    def test_incomplete_urls(self):
        env = {'ANSIBLE_OFZHUR_STORAGE_ACCESS_KEY': 'a', 'ANSIBLE_OFZHUR_STORAGE_SECRET_KEY': 'b',
               'ANSIBLE_OFZHUR_STORAGE_VAULT_TOKEN': 't'}
        for uri, message in [('consul://127.0.0.1:8500', 'consul://host:8500/prefix'),
                             ('vault://127.0.0.1:8200/secret', 'vault://host:8200/mount/prefix'),
                             ('r2://0123456789abcdef0123456789abcdef', 'r2://account/bucket/prefix'),
                             ('ssh://203.0.113.1', 'ssh://[user@]host[:port]/path'),
                             ('s3://facts:9000/x', 'a port in the URL is not read')]:
            with self.subTest(uri):
                self.assertFails(uri, message, env=env)

    def test_prefix(self):
        self.assertFails('/nonexistent/facts', 'fact_caching_prefix', env={'ANSIBLE_CACHE_PLUGIN_PREFIX': 'a/b'})

    def test_ca_file(self):
        self.infra.write('ca.pem', 'not a certificate\n')
        for path, message in (('/nonexistent/ca.pem', 'ca_file: No such file or directory: /nonexistent/ca.pem'),
                              (os.path.join(self.infra.dir, 'ca.pem'), f'ca_file: no certificate (PEM) in it: {self.infra.dir}/ca.pem')):
            with self.subTest(path):
                self.assertFails('http+consul://127.0.0.1:1/facts', f'http+consul://127.0.0.1:1/facts: {message}',
                                 env={'ANSIBLE_OFZHUR_STORAGE_CA_FILE': path})

    def test_unreachable(self):
        self.assertFails('http+consul://127.0.0.1:1/facts', 'http+consul://127.0.0.1:1/facts: reading')

    def test_ssh_unreachable(self):
        # the message of ssh, once
        known = tempfile.NamedTemporaryFile(prefix='ofzhur-facts-test-')
        self.addCleanup(known.close)
        out = self.assertFails('ssh://127.0.0.1:1/srv/facts', 'ssh://127.0.0.1:1/srv/facts: reading: ssh: connect to host 127.0.0.1 port 1',
                               env={'ANSIBLE_OFZHUR_STORAGE_SSH_ARGS': f'-F /dev/null -o UserKnownHostsFile={known.name}'})
        self.assertNotIn('ssh: ssh:', out)

    def test_documentation(self):
        r = subprocess.run(['ansible-doc', '-t', 'cache', NAME], cwd=self.infra.dir, capture_output=True, text=True,
                           env=environment({}))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('ofzhur_storage', r.stdout)
        self.assertIn('ANSIBLE_OFZHUR_STORAGE_SECRET_KEY_FILE', r.stdout)
        self.assertNotIn('AWS_ACCESS_KEY_ID', r.stdout)


class Signing(unittest.TestCase):
    """AWS Signature Version 4 and the addresses of the buckets, without a store."""

    def test_aws_examples(self):
        # https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
        sigv4 = storages.storage.sigv4
        h = {'host': 'examplebucket.s3.amazonaws.com', 'x-amz-content-sha256': EMPTY_SHA256, 'x-amz-date': '20130524T000000Z'}
        out = [
            sigv4('GET', '/', 'max-keys=2&prefix=J', h, EMPTY_SHA256, *SIGV4_KEYS, 'us-east-1', '20130524T000000Z'),
            sigv4('GET', '/test.txt', '', dict(h, range='bytes=0-9'), EMPTY_SHA256, *SIGV4_KEYS, 'us-east-1', '20130524T000000Z'),
        ]
        self.assertTrue(out[0].endswith('SignedHeaders=host;x-amz-content-sha256;x-amz-date, '
                                        'Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7'), out[0])
        self.assertTrue(out[1].endswith('Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41'), out[1])

    def test_addresses(self):
        s = storages.storage
        opts = {'access_key': 'a', 'secret_key': 'b', 'region': 'eu-central-1'}

        def where(uri, **o):
            store = s.open_store(uri, dict(opts, **o).get)
            return [store.base, store.root, store.prefix, store.region]
        self.assertEqual([
            where('r2://0123456789abcdef0123456789abcdef/fleet/facts'),
            where('s3://fleet/facts/'),
            where('s3://fleet.example/facts'),
            where('s3://fleet', endpoint='http://127.0.0.1:9000/'),
            s.label_of('ssh://ump:pw@host:2222/srv/facts?a=b#c'),
        ], [
            ['https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com', '/fleet/', 'facts/', 'auto'],
            ['https://fleet.s3.eu-central-1.amazonaws.com', '/', 'facts/', 'eu-central-1'],
            ['https://s3.eu-central-1.amazonaws.com', '/fleet.example/', 'facts/', 'eu-central-1'],
            ['http://127.0.0.1:9000', '/fleet/', '', 'eu-central-1'],
            'ssh://ump@host:2222/srv/facts',
        ])

    def test_file_wins(self):
        with tempfile.NamedTemporaryFile('w', prefix='ofzhur-facts-test-') as f:
            f.write('from-file\n')
            f.flush()
            store = storages.storage.open_store('s3://fleet/facts', {'access_key': 'a', 'secret_key': 'value',
                                                                    'secret_key_file': f.name}.get)
        self.assertEqual(store.secret_key, 'from-file')


# --- Docker -------------------------------------------------------------------

class S3(storages.MinIO, Storage, unittest.TestCase):

    def test_folder_marker(self):
        self.folder_marker()

    def test_pages(self):
        keys = [f'web-{i:02}' for i in range(7)]
        out = self.helper(['page', 2], *[['set', k, {}] for k in keys], ['keys'], ['flush'], ['names'], timeout=0)
        self.assertEqual(out[-3:], [keys, None, []])

    def test_files(self):
        # the credentials from files of [ofzhur_storage] in ansible.cfg; a file wins over a value
        for name, value in (('access', 'ofzhur-test'), ('secret', 'ofzhur-test-secret')):
            self.infra.write(f'secrets/{name}', value + '\n')
        with open(os.path.join(self.infra.dir, 'ansible.cfg'), 'a') as f:
            f.write('\n[ofzhur_storage]\naccess_key_file = secrets/access\nsecret_key_file = secrets/secret\n')
        del self.env['ANSIBLE_OFZHUR_STORAGE_ACCESS_KEY']
        self.env['ANSIBLE_OFZHUR_STORAGE_SECRET_KEY'] = 'Wr0ngS3cret'
        self.gather()
        self.assertEqual(self.peer()['marker'], 'db-01 one')


class Consul(storages.Consul, Storage, unittest.TestCase):

    def test_folder_marker(self):
        self.folder_marker()

    def test_outside_the_policy(self):
        self.env['ANSIBLE_CACHE_PLUGIN_CONNECTION'] = self.uri = f'http+consul://{self.address}/other'
        r = self.call('ansible-playbook', 'gather.yml')
        self.assertNotEqual(r.returncode, 0)
        # Consul leaves out the keys a token cannot read; the write fails
        self.assertIn(f'{NAME}: {self.uri}: writing', r.stdout + r.stderr)
        self.assertIn("lacks permission 'key:write'", r.stdout + r.stderr)


class Vault(storages.Vault, Storage, unittest.TestCase):

    def test_token_file(self):
        self.infra.write('secrets/vault-token', self.ENV['ANSIBLE_OFZHUR_STORAGE_VAULT_TOKEN'] + '\n')
        del self.env['ANSIBLE_OFZHUR_STORAGE_VAULT_TOKEN']
        self.env['ANSIBLE_OFZHUR_STORAGE_VAULT_TOKEN_FILE'] = os.path.join(self.infra.dir, 'secrets/vault-token')
        self.gather()
        self.assertEqual(self.peer()['marker'], 'db-01 one')

    def test_foreign_secret(self):
        # a secret without the field json is an object like any other that is none of the plugin's
        self.secret(f'fleet/{self._testMethodName}/{SCHEMA}db-01', {'password': 'Sup3rS3cret'})
        r = self.gather()
        out = r.stdout + r.stderr
        self.assertIn(''.join(f'{SCHEMA}db-01 is not a cache object'.split()), ''.join(out.split()))
        self.assertNotIn('Sup3rS3cret', out)
        self.assertEqual(self.peer()['marker'], 'db-01 one')


class SSH(storages.SSH, Storage, unittest.TestCase):

    def check_object(self, key):
        d = f'/home/ump/fleet/{self._testMethodName}'
        r = storages.test_users.docker('exec', self.container, 'stat', '-c', '%a %U', d, f'{d}/{SCHEMA}{key}')
        self.assertEqual(r.stdout.split('\n'), ['700 ump', '600 ump', ''])
        r = storages.test_users.docker('exec', self.container, 'sh', '-c', f'ls -A {d}')
        self.assertEqual(sorted(r.stdout.split()), sorted(SCHEMA + h for h in ('db-01', 'web-01')))


if __name__ == '__main__':
    unittest.main()
