# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""Tests of the ofzhur.ansible.host inventory plugin (host files in a directory;
test_host_storage.py has those in a storage) and config/push/ansible.cfg.

They run the ansible CLI found on PATH against an infrastructure repository
laid out in a temporary directory, the way the template expects it:

    python3 tests/test_host.py
"""

import json
import os
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

WEB = """\
plugin: ofzhur.ansible.host
groups: [role_web, role_base, account_main]
vars:
  ansible_host: 203.0.113.10
  ump_admin: ump
  ump_roles: [web, base]
  ump_attributes: {owner: ops}
  template: "{{ 1 + 1 }}"
"""

DB = """\
plugin: ofzhur.ansible.host
groups: [role_db]
vars:
  ansible_host: 203.0.113.20
"""

GROUPS = """\
all:
  children:
    prod:
      children:
        role_web:
        role_db:
"""


def plain(value):
    """The value without the markers of untrusted data that ansible-inventory prints."""
    if isinstance(value, dict):
        if list(value) == ['__ansible_unsafe']:
            return value['__ansible_unsafe']
        return {k: plain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [plain(v) for v in value]
    return value


class Infra:
    """A temporary infrastructure repository with the push template as ansible.cfg."""

    def __init__(self, files):
        self.dir = tempfile.mkdtemp(prefix='ofzhur-ansible-test-')
        collection = os.path.join(self.dir, 'collections', 'ansible_collections', 'ofzhur')
        os.makedirs(collection)
        os.symlink(ROOT, os.path.join(collection, 'ansible'))
        shutil.copy(os.path.join(ROOT, 'config', 'push', 'ansible.cfg'), self.dir)
        for path, content in files.items():
            self.write(path, content)

    def write(self, path, content):
        full = os.path.join(self.dir, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, 'w') as f:
            f.write(textwrap.dedent(content))

    def run(self, *argv, env=None):
        e = {k: v for k, v in os.environ.items() if not k.startswith('ANSIBLE_')}
        e.update(env or {})
        return subprocess.run(argv, cwd=self.dir, env=e, capture_output=True, text=True)

    def inventory(self, *args, env=None):
        r = self.run('ansible-inventory', '--list', *args, env=env)
        if r.returncode:
            raise AssertionError(f'ansible-inventory failed:\n{r.stderr}')
        return plain(json.loads(r.stdout))

    def close(self):
        shutil.rmtree(self.dir)


class HostFiles(unittest.TestCase):

    def infra(self, files):
        i = Infra(files)
        self.addCleanup(i.close)
        return i

    def assertFails(self, infra, *messages):
        r = infra.run('ansible-inventory', '--list')
        self.assertNotEqual(r.returncode, 0, r.stdout)
        # ansible-core < 2.19 wraps messages at 80 columns
        squeezed = ''.join(r.stderr.split())
        for m in messages:
            self.assertIn(''.join(m.split()), squeezed, r.stderr)

    def test_hosts_groups_vars(self):
        i = self.infra({
            'inventory/groups.yml': GROUPS,
            'inventory/hosts/web-01.yml': WEB,
            'inventory/hosts/db-01.yaml': DB,
            'inventory/group_vars/role_web.yml': 'http_port: 8080\n',
            'inventory/host_vars/web-01.yml': 'ump_admin: admin\n',
        })
        inv = i.inventory()
        hostvars = inv['_meta']['hostvars']
        self.assertEqual(sorted(hostvars), ['db-01', 'web-01'])
        self.assertEqual(inv['role_web']['hosts'], ['web-01'])
        self.assertEqual(inv['role_base']['hosts'], ['web-01'])
        self.assertEqual(inv['role_db']['hosts'], ['db-01'])
        self.assertEqual(sorted(inv['prod']['children']), ['role_db', 'role_web'])
        web = hostvars['web-01']
        self.assertEqual(web['ansible_host'], '203.0.113.10')
        self.assertEqual(web['ump_roles'], ['web', 'base'])
        self.assertEqual(web['ump_attributes'], {'owner': 'ops'})
        self.assertEqual(web['http_port'], 8080)
        self.assertEqual(web['ump_admin'], 'admin', 'host_vars/ wins over the host file')
        self.assertNotIn('ansible_user', web)
        self.assertEqual(inv.get('ungrouped', {}).get('hosts', []), [])

    def test_values_are_not_templated(self):
        i = self.infra({'inventory/hosts/web-01.yml': WEB})
        r = i.run('ansible', 'web-01', '-m', 'ansible.builtin.debug', '-a', 'msg={{ template }}')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('{{ 1 + 1 }}', r.stdout)
        r = i.run('ansible-inventory', '--list')
        self.assertIn('"__ansible_unsafe": "{{ 1 + 1 }}"', r.stdout)

    def test_static_groups_only(self):
        # no server yet: the inventory is still valid, with no hosts
        inv = self.infra({'inventory/groups.yml': GROUPS}).inventory()
        self.assertEqual(inv['_meta']['hostvars'], {})

    def test_one_file_as_source(self):
        i = self.infra({'inventory/hosts/web-01.yml': WEB})
        inv = i.inventory('-i', 'inventory/hosts/web-01.yml')
        self.assertEqual(list(inv['_meta']['hostvars']), ['web-01'])

    def test_auto_without_enable_plugins(self):
        i = self.infra({'inventory/hosts/web-01.yml': WEB})
        inv = i.inventory(env={'ANSIBLE_INVENTORY_ENABLED': 'auto,yaml'})
        self.assertEqual(inv['role_web']['hosts'], ['web-01'])

    def test_minimal_file(self):
        i = self.infra({'inventory/hosts/10.0.0.1.yml': 'plugin: ofzhur.ansible.host\n'})
        inv = i.inventory()
        self.assertEqual(inv['ungrouped']['hosts'], ['10.0.0.1'])

    def test_invalid_files_fail_the_run(self):
        cases = {
            'unknown key': ('plugin: ofzhur.ansible.host\nvar: {a: 1}\n', 'unknown key(s) var'),
            'groups': ('plugin: ofzhur.ansible.host\ngroups: role_web\n', 'groups must be a list'),
            'vars': ('plugin: ofzhur.ansible.host\nvars: [a]\n', 'vars must be a mapping'),
            'variable name': ('plugin: ofzhur.ansible.host\nvars: {a-b: 1}\n', 'invalid variable name(s) a-b'),
            'group name': ('plugin: ofzhur.ansible.host\ngroups: [os_ubuntu-26.04]\n', 'invalid group name(s) os_ubuntu-26.04'),
            'yaml': ('plugin: ofzhur.ansible.host\nvars: {a: [\n', 'web-01.yml'),
            'empty': ('', 'web-01.yml'),
            'comment only': ('# nothing\n', 'web-01.yml'),
        }
        for name, (content, message) in cases.items():
            with self.subTest(name):
                self.assertFails(self.infra({'inventory/hosts/web-01.yml': content}), message)

    def test_keyword_group(self):
        # a Python keyword is a valid group name for Ansible
        inv = self.infra({'inventory/hosts/web-01.yml': 'plugin: ofzhur.ansible.host\ngroups: [common, global]\n'}).inventory()
        self.assertEqual(inv['global']['hosts'], ['web-01'])

    def test_second_file_for_a_host_fails(self):
        # also when the static groups list the host first
        groups = 'monitoring:\n  hosts:\n    web-01:\n'
        i = self.infra({
            'inventory/groups.yml': groups,
            'inventory/hosts/web-01.yml': WEB,
            'inventory/hosts/web-01.yaml': DB,
        })
        self.assertFails(i, 'host web-01 is already defined by')
        inv = self.infra({'inventory/groups.yml': groups, 'inventory/hosts/web-01.yml': WEB}).inventory()
        self.assertEqual(inv['monitoring']['hosts'], ['web-01'])

    def test_one_server_two_hosts(self):
        # the same ump_ref: a server under its old name and its new one
        server = 'plugin: ofzhur.ansible.host\nvars: {ump_ref: fake/1}\n'
        i = self.infra({'inventory/hosts/old-01.yml': server, 'inventory/hosts/web-01.yml': server})
        self.assertFails(i, 'web-01.yml: host web-01 has ump_ref fake/1, as has host old-01 of', 'one server, two hosts')

    def test_invalid_host_name(self):
        i = self.infra({'inventory/hosts/web 01.yml': 'plugin: ofzhur.ansible.host\n'})
        self.assertFails(i, "'web 01' is not a host name")

    def test_empty_hosts_directory_fails(self):
        # documented: a provisioner removes hosts/ with its last file
        i = self.infra({'inventory/groups.yml': GROUPS})
        os.makedirs(os.path.join(i.dir, 'inventory', 'hosts'))
        self.assertFails(i, 'inventory/hosts')

    def test_documentation(self):
        i = self.infra({})
        r = i.run('ansible-doc', '-t', 'inventory', 'ofzhur.ansible.host')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('Reads one host from a YAML file', r.stdout)


if __name__ == '__main__':
    unittest.main()
