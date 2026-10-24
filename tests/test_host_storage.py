# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""Tests of host files in a storage: ofzhur.ansible.host with url, such
as inventory/hosts.yml.

The host files are written with module_utils/storage.py into each
storage of storages.py: a directory here, and on Docker MinIO (S3),
Consul, Vault and a directory over SSH on a Debian container. The ansible
CLI found on PATH reads them in a repository laid out as in test_host.py.
Without Docker only the directory is tested.

    python3 tests/test_host_storage.py
"""

import json
import os
import subprocess
import unittest

import storages
import test_host
from storages import environment
from test_host import plain

WEB = """\
plugin: ofzhur.ansible.host
groups: [common, web]
vars:
  ansible_host: 203.0.113.10
  ump_admin: ump
  ump_ref: fake/2
  template: "{{ 1 + 1 }}"
"""

DB = """\
plugin: ofzhur.ansible.host
groups: [common, db]
vars:
  ansible_host: 2001:db8::20
  ump_ref: fake/1
"""

GROUPS = """\
all:
  children:
    prod:
      children:
        web:
        db:
"""


class Remote:
    """The tests of one storage. A subclass of storages.py gives its URL (with a prefix of its own for each
    test) and environment."""

    SUITE = 'hosts'

    def setUp(self):
        self.uri = self.url(self._testMethodName)
        self.store = storages.open_store(self.uri, self.ENV)
        self.infra = test_host.Infra({
            'inventory/hosts.yml': f'plugin: ofzhur.ansible.host\nurl: {self.uri}\n',
            'inventory/groups.yml': GROUPS,
        })
        self.addCleanup(self.infra.close)
        self.env = dict(self.ENV)

    def put(self, name, content):
        self.store.write(name, content.encode())

    def call(self, *argv, env=None):
        return subprocess.run(argv, cwd=self.infra.dir, env=environment(dict(self.env, **(env or {}))),
                              capture_output=True, text=True)

    def inventory(self, *args, env=None):
        r = self.call('ansible-inventory', '--list', *args, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)
        return plain(json.loads(r.stdout))

    def assertFails(self, *messages, env=None):
        r = self.call('ansible-inventory', '--list', env=env)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        # ansible-core < 2.19 wraps warnings at 80 columns
        squeezed = ''.join(r.stderr.split())
        for m in messages:
            self.assertIn(''.join(m.split()), squeezed, r.stderr)
        return r.stderr

    def test_hosts(self):
        self.put('web-01.yml', WEB)
        self.put('db-01.yaml', DB)
        # neither host files nor read: other names, dot names (ump's files on their way)
        self.put('README', 'not a host file\n')
        self.put('.web-02.yml.tmp', 'plugin: ofzhur.ansible.host\n')
        inv = self.inventory()
        hostvars = inv['_meta']['hostvars']
        self.assertEqual(sorted(hostvars), ['db-01', 'web-01'])
        self.assertEqual(hostvars['web-01'], {'ansible_host': '203.0.113.10', 'ump_admin': 'ump', 'ump_ref': 'fake/2',
                                              'template': '{{ 1 + 1 }}'})
        self.assertEqual(hostvars['db-01']['ansible_host'], '2001:db8::20')
        self.assertEqual(sorted(inv['common']['hosts']), ['db-01', 'web-01'])
        self.assertEqual(sorted(inv['prod']['children']), ['db', 'web'])
        # values are data
        r = self.call('ansible', 'web-01', '-m', 'ansible.builtin.debug', '-a', 'var=template')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('{{ 1 + 1 }}', r.stdout)

    def test_empty(self):
        # no server yet: a valid inventory, unlike an empty directory of host files
        inv = self.inventory()
        self.assertEqual(inv['_meta']['hostvars'], {})

    def test_invalid_host_file(self):
        self.put('web-01.yml', WEB)
        self.put('db-01.yml', 'plugin: ofzhur.ansible.host\nvar: {a: 1}\n')
        self.assertFails(f'{self.uri}/db-01.yml: unknown key(s) var')

    def test_second_file_for_a_host(self):
        self.put('web-01.yml', WEB)
        self.put('web-01.yaml', WEB)
        self.assertFails(f'{self.uri}/web-01.yml: host web-01 is already defined by {self.uri}/web-01.yaml')

    def test_refused(self):
        self.put('web-01.yml', WEB)
        env, secret, reason = self.broken()
        stderr = self.assertFails(f'inventory/hosts.yml: {self.uri}: ', reason, env=env)
        self.assertNotIn('ssh: ssh:', stderr)
        if secret:
            self.assertNotIn(secret, stderr)


class Directory(storages.Directory, Remote, unittest.TestCase):

    def test_host_in_both(self):
        # a host of a local host file and of the storage; one server under two names, in either order
        self.put('web-01.yml', WEB)
        self.infra.write('inventory/hosts/web-01.yml', DB)
        self.assertFails('host web-01 is already defined by')
        os.remove(os.path.join(self.infra.dir, 'inventory', 'hosts', 'web-01.yml'))
        self.infra.write('inventory/hosts/old-01.yml', WEB)
        self.assertFails(f'{self.uri}/web-01.yml: host web-01 has ump_ref fake/2, as has host old-01 of', 'one server, two hosts')
        os.rename(os.path.join(self.infra.dir, 'inventory', 'hosts.yml'), os.path.join(self.infra.dir, 'inventory', 'a-hosts.yml'))
        self.assertFails('old-01.yml: host old-01 has ump_ref fake/2, as has host web-01 of', 'one server, two hosts')

    def test_pointer(self):
        cases = {
            'credentials': (f'url: {self.uri}\nsecret_key: Sup3rS3cret\n', 'unknown key(s) secret_key', '[ofzhur_storage]'),
            'host file': (f'url: {self.uri}\ngroups: [web]\n', 'unknown key(s) groups'),
            'path': ('url: inventory/remote\n', 'url must be the URL of a storage'),
            'scheme': ('url: redis://127.0.0.1/inventory\n', 'redis://127.0.0.1/inventory: unknown scheme redis'),
            'query': ('url: s3://fleet/inventory?secret_key=Sup3rS3cret\n', 's3://fleet/inventory: a query string'),
            'ca_file': ('url: http+consul://127.0.0.1:1/inventory\nca_file: ca.pem\n',
                        f'http+consul://127.0.0.1:1/inventory: ca_file: No such file or directory: {self.infra.dir}/inventory/ca.pem'),
        }
        for name, (pointer, *messages) in cases.items():
            with self.subTest(name):
                self.infra.write('inventory/hosts.yml', 'plugin: ofzhur.ansible.host\n' + pointer)
                self.assertNotIn('Sup3rS3cret', self.assertFails(*messages))

    def test_connection_variables(self):
        # whoever writes the storage would run commands on every machine that reads it: of the ansible_*
        # variables a host file there sets ansible_host alone, an address
        marker = os.path.join(self.infra.dir, 'ran')
        proxy = json.dumps(f'-o ProxyCommand="touch {marker}"')
        ssh = {'ANSIBLE_SSH_ARGS': '-F /dev/null -o ControlMaster=no'}
        refused = 'a host file in a storage sets no ansible_* variable but ansible_host; the others go into host_vars/'
        cases = {
            'ssh args': (f'ansible_ssh_common_args: {proxy}', f'ansible_ssh_common_args: {refused}'),
            'proxy': (f'ansible_ssh_extra_args: {proxy}\n  ansible_port: 2222', f'ansible_port, ansible_ssh_extra_args: {refused}'),
            'local': (f'ansible_connection: local\n  ansible_python_interpreter: "touch {marker}; python3"',
                      f'ansible_connection, ansible_python_interpreter: {refused}'),
            'address': (f'ansible_host: "-oProxyCommand=touch {marker}"', "ansible_host '-oProxyCommand=touch",
                        'is not a host name or an address'),
            'not a string': ('ansible_host: [203.0.113.10]', 'is not a host name or an address'),
        }
        for name, (variables, *messages) in cases.items():
            with self.subTest(name):
                self.put('web-01.yml', f'plugin: ofzhur.ansible.host\nvars:\n  {variables}\n')
                self.assertFails(f'{self.uri}/web-01.yml: ', *messages)
                r = self.call('ansible', 'web-01', '-m', 'ansible.builtin.ping', env=ssh)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertFalse(os.path.exists(marker))
        # in host_vars/, reviewed with the repository, they apply
        self.put('web-01.yml', 'plugin: ofzhur.ansible.host\nvars:\n  ansible_host: 2001:db8::10\n')
        self.infra.write('inventory/host_vars/web-01.yml', 'ansible_port: 2222\n')
        self.assertEqual(self.inventory()['_meta']['hostvars']['web-01'], {'ansible_host': '2001:db8::10', 'ansible_port': 2222})
        # as in a host file of the repository: the command of the first case runs
        os.remove(os.path.join(self.infra.dir, 'inventory', 'host_vars', 'web-01.yml'))
        self.store.delete(['web-01.yml'])
        self.infra.write('inventory/hosts/web-01.yml', f'plugin: ofzhur.ansible.host\nvars:\n  ansible_ssh_common_args: {proxy}\n')
        self.call('ansible', 'web-01', '-m', 'ansible.builtin.ping', env=ssh)
        self.assertTrue(os.path.exists(marker))

    def test_unreachable(self):
        self.infra.write('inventory/hosts.yml', 'plugin: ofzhur.ansible.host\nurl: http+consul://127.0.0.1:1/inventory\n')
        self.assertFails('inventory/hosts.yml: http+consul://127.0.0.1:1/inventory: reading')

    def test_auto_without_enable_plugins(self):
        self.put('web-01.yml', WEB)
        inv = self.inventory(env={'ANSIBLE_INVENTORY_ENABLED': 'auto,yaml'})
        self.assertEqual(inv['web']['hosts'], ['web-01'])

    def test_documentation(self):
        r = self.call('ansible-doc', '-t', 'inventory', 'ofzhur.ansible.host')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('ofzhur_storage', r.stdout)
        self.assertIn('ANSIBLE_OFZHUR_STORAGE_VAULT_TOKEN_FILE', r.stdout)


# --- Docker -------------------------------------------------------------------

class S3(storages.MinIO, Remote, unittest.TestCase):

    def test_options(self):
        # the endpoint in the pointer, the credentials from files of [ofzhur_storage] in ansible.cfg
        self.put('web-01.yml', WEB)
        self.infra.write('inventory/hosts.yml', f'plugin: ofzhur.ansible.host\nurl: {self.uri}\n'
                                                f'endpoint: {self.ENV["ANSIBLE_OFZHUR_STORAGE_ENDPOINT"]}\n')
        for name, value in (('access', 'ofzhur-test'), ('secret', 'ofzhur-test-secret')):
            self.infra.write(f'secrets/{name}', value + '\n')
        with open(os.path.join(self.infra.dir, 'ansible.cfg'), 'a') as f:
            f.write('\n[ofzhur_storage]\naccess_key_file = secrets/access\nsecret_key_file = secrets/secret\n')
        self.env = {'AWS_ACCESS_KEY_ID': 'ofzhur-test', 'AWS_SECRET_ACCESS_KEY': 'Wr0ngS3cret'}
        self.assertEqual(self.inventory()['web']['hosts'], ['web-01'])

    def test_pages(self):
        storages.storage.S3.PAGE = 2
        self.addCleanup(setattr, storages.storage.S3, 'PAGE', 1000)
        names = [f'web-{i:02}' for i in range(5)]
        for name in names:
            self.put(f'{name}.yml', 'plugin: ofzhur.ansible.host\n')
        self.assertEqual(sorted(self.store.list('', ('.yml',))), [f'{n}.yml' for n in names])


class Consul(storages.Consul, Remote, unittest.TestCase):
    pass


class Vault(storages.Vault, Remote, unittest.TestCase):

    def test_foreign_secret(self):
        # a secret without the field json is no host file: the inventory fails, as on any other
        self.put('web-01.yml', WEB)
        self.secret(f'fleet/{self._testMethodName}/db-01.yml', {'password': 'Sup3rS3cret'})
        stderr = self.assertFails(f'{self.uri}/db-01.yml: not a host file')
        self.assertNotIn('Sup3rS3cret', stderr)


class SSH(storages.SSH, Remote, unittest.TestCase):
    pass


if __name__ == '__main__':
    unittest.main()
