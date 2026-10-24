# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""Tests of the ofzhur.ansible.ump inventory plugin.

A fake ump on PATH prints what the test gives it and records its
arguments; the ansible CLI found on PATH reads it through
inventory/ump.yml, in a repository laid out as in test_host.py:

    python3 tests/test_ump.py
"""

import json
import os
import stat
import unittest

from test_host import Infra, plain

# ump's host files of two servers ...
WEB = """\
# web-01: written by ump (ump server reinstall, ump provision).
# Edits are overwritten; overrides go to inventory/host_vars/web-01.yml.
plugin: ofzhur.ansible.host
groups: [common, web]
vars:
  ansible_host: 203.0.113.10
  ump_admin: ump
  ump_name: web-01
  ump_ref: fake/2
  ump_provider: fake
  ump_account: main
  ump_location: eu-1
  ump_product: "1024"
  ump_os: ubuntu-26.04
  ump_profile: ubuntu-26.04
  ump_installed_at: "2026-10-12T09:00:00Z"
  ump_attributes:
    owner: alice
    note: "{{ 1 + 1 }}"
"""

DB = """\
# db-01: written by ump (ump server reinstall, ump provision).
# Edits are overwritten; overrides go to inventory/host_vars/db-01.yml.
plugin: ofzhur.ansible.host
groups: [common, db, web]
vars:
  ansible_host: 2001:db8::20
  ump_admin: oleg
  ump_name: db-01
  ump_ref: fake/1
  ump_provider: fake
  ump_account: main
  ump_location: eu-2
  ump_os: debian-13
  ump_profile: debian-13
  ump_installed_at: "2026-10-11T08:00:00Z"
"""

# ... and the same as ump server list -o ansible prints them, in another
# order than the files'
HOSTVARS = {
    'web-01': {
        'ansible_host': '203.0.113.10', 'ump_admin': 'ump',
        'ump_name': 'web-01', 'ump_ref': 'fake/2', 'ump_provider': 'fake', 'ump_account': 'main',
        'ump_location': 'eu-1', 'ump_product': '1024', 'ump_os': 'ubuntu-26.04', 'ump_profile': 'ubuntu-26.04',
        'ump_installed_at': '2026-10-12T09:00:00Z',
        'ump_attributes': {'owner': 'alice', 'note': '{{ 1 + 1 }}'},
    },
    'db-01': {
        'ansible_host': '2001:db8::20', 'ump_admin': 'oleg',
        'ump_name': 'db-01', 'ump_ref': 'fake/1', 'ump_provider': 'fake', 'ump_account': 'main',
        'ump_location': 'eu-2', 'ump_os': 'debian-13', 'ump_profile': 'debian-13',
        'ump_installed_at': '2026-10-11T08:00:00Z',
    },
}
INVENTORY = {
    '_meta': {'hostvars': HOSTVARS},
    'all': {'children': ['ungrouped', 'common', 'db', 'web']},
    'common': {'hosts': ['web-01', 'db-01']},
    'db': {'hosts': ['db-01']},
    'web': {'hosts': ['web-01', 'db-01']},
}

GROUPS = """\
all:
  children:
    prod:
      children:
        web:
        db:
"""

# prints the file stdout, the file stderr to stderr, and exits with the
# status in the file status; records its arguments, one per line
FAKE_UMP = """\
#!/bin/sh
dir=$(dirname "$0")
printf '%s\\n' "$@" > "$dir/args"
[ -f "$dir/sleep" ] && sleep "$(cat "$dir/sleep")"
cat "$dir/stdout"
[ -f "$dir/stderr" ] && cat "$dir/stderr" >&2
exit "$(cat "$dir/status" 2>/dev/null || echo 0)"
"""

LIST = ['server', 'list', '-o', 'ansible']


class Ump:
    """The fake ump of a repository, in its bin/."""

    def __init__(self, infra, stdout, stderr=None, status=0, sleep=None):
        self.dir = os.path.join(infra.dir, 'bin')
        self.path = os.path.join(self.dir, 'ump')
        infra.write('bin/ump', FAKE_UMP)
        os.chmod(self.path, os.stat(self.path).st_mode | stat.S_IXUSR)
        infra.write('bin/stdout', stdout if isinstance(stdout, str) else json.dumps(stdout))
        infra.write('bin/status', f'{status}\n')
        if stderr is not None:
            infra.write('bin/stderr', stderr)
        if sleep is not None:
            infra.write('bin/sleep', f'{sleep}\n')
        self.env = {'PATH': self.dir + os.pathsep + os.environ['PATH']}

    def args(self):
        with open(os.path.join(self.dir, 'args')) as f:
            return f.read().splitlines()


class UmpInventory(unittest.TestCase):

    def infra(self, files, stdout=None, **fake):
        i = Infra(files)
        self.addCleanup(i.close)
        ump = Ump(i, INVENTORY if stdout is None else stdout, **fake)
        return i, ump

    def assertFails(self, infra, ump, *messages, args=()):
        r = infra.run('ansible-inventory', '--list', *args, env=ump.env)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertMessages(r.stderr, messages)

    def assertMessages(self, stderr, messages):
        # ansible-core < 2.19 wraps warnings at 80 columns
        squeezed = ''.join(stderr.split())
        for m in messages:
            self.assertIn(''.join(m.split()), squeezed, stderr)

    def raw(self, infra, ump, *args, env=None):
        r = infra.run('ansible-inventory', '--list', *args, env={**ump.env, **(env or {})})
        if r.returncode:
            raise AssertionError(f'ansible-inventory failed:\n{r.stderr}')
        return json.loads(r.stdout)

    def test_same_as_host_files(self):
        files, _ = self.infra({
            'inventory/groups.yml': GROUPS,
            'inventory/hosts/web-01.yml': WEB,
            'inventory/hosts/db-01.yml': DB,
            'inventory/group_vars/web.yml': 'http_port: 8080\n',
            'inventory/host_vars/web-01.yml': 'ump_admin: admin\n',
        }, stdout={})
        ump, fake = self.infra({
            'inventory/groups.yml': GROUPS,
            'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n',
            'inventory/group_vars/web.yml': 'http_port: 8080\n',
            'inventory/host_vars/web-01.yml': 'ump_admin: admin\n',
        })
        # the output itself, markers of untrusted data and order included
        expected = self.raw(files, fake)
        self.assertEqual(self.raw(ump, fake), expected)
        self.assertEqual(fake.args(), LIST)
        inv = plain(expected)
        self.assertEqual(inv['web']['hosts'], ['db-01', 'web-01'])
        self.assertEqual(inv['_meta']['hostvars']['web-01']['ump_admin'], 'admin')
        self.assertEqual(inv['_meta']['hostvars']['web-01']['http_port'], 8080)
        self.assertEqual(sorted(inv['prod']['children']), ['db', 'web'])
        for name in ('ansible_host', 'ump_product', 'ump_installed_at'):
            self.assertEqual(type(inv['_meta']['hostvars']['web-01'][name]), str)
        graphs = [i.run('ansible-inventory', '--graph', env=fake.env) for i in (files, ump)]
        self.assertEqual(graphs[1].stdout, graphs[0].stdout, graphs[1].stderr)

    def test_arguments_and_cached(self):
        i, ump = self.infra({'inventory/ump.yml': """\
            plugin: ofzhur.ansible.ump
            arguments: [--account, main, web-01]
            cached: true
            """})
        self.assertEqual(sorted(plain(self.raw(i, ump))['_meta']['hostvars']), ['db-01', 'web-01'])
        self.assertEqual(ump.args(), LIST + ['--cached', '--account', 'main', 'web-01'])

    def test_command(self):
        i, ump = self.infra({})
        i.write('inventory/ump.yml', f'plugin: ofzhur.ansible.ump\ncommand: {ump.path}\n')
        inv = plain(self.raw(i, ump, env={'PATH': os.environ['PATH']}))
        self.assertEqual(inv['db']['hosts'], ['db-01'])

    def test_one_source_as_argument(self):
        i, ump = self.infra({'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n'})
        inv = plain(self.raw(i, ump, '-i', 'inventory/ump.yml'))
        self.assertEqual(inv['common']['hosts'], ['db-01', 'web-01'])

    def test_plugin_enabled_before_host_files(self):
        # verify_file takes ump's configuration, never a host file
        i, ump = self.infra({
            'inventory/groups.yml': GROUPS,
            'inventory/hosts/app-01.yml': 'plugin: ofzhur.ansible.host\ngroups: [common, app]\n',
            'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n',
        })
        enabled = {'ANSIBLE_INVENTORY_ENABLED': 'ofzhur.ansible.ump,ofzhur.ansible.host,yaml'}
        inv = plain(self.raw(i, ump, env=enabled))
        self.assertEqual(inv['common']['hosts'], ['app-01', 'db-01', 'web-01'])
        only = {'ANSIBLE_INVENTORY_ENABLED': 'ofzhur.ansible.ump'}
        r = i.run('ansible-inventory', '--list', '-i', 'inventory/hosts/app-01.yml', env={**ump.env, **only})
        self.assertNotEqual(r.returncode, 0, r.stdout)
        inv = plain(self.raw(i, ump, '-i', 'inventory/ump.yml', env=only))
        self.assertEqual(inv['db']['hosts'], ['db-01'])

    def test_values_are_not_templated(self):
        i, ump = self.infra({'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n'}, stdout={
            '_meta': {'hostvars': {'web-01': {'template': '{{ 1 + 1 }}', 'nested': {'a': ['{{ 2 + 2 }}']}}}},
            'web': {'hosts': ['web-01'], 'vars': {'group_template': '{{ 3 + 3 }}'}},
        })
        for var, literal in (('template', '{{ 1 + 1 }}'), ('nested', '{{ 2 + 2 }}'), ('group_template', '{{ 3 + 3 }}')):
            with self.subTest(var):
                r = i.run('ansible', 'web-01', '-m', 'ansible.builtin.debug', '-a', f'var={var}', env=ump.env)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertIn(literal, r.stdout)

    def test_no_servers(self):
        i, ump = self.infra({'inventory/groups.yml': GROUPS, 'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n'},
                            stdout={'_meta': {'hostvars': {}}, 'all': {'children': ['ungrouped']}})
        self.assertEqual(plain(self.raw(i, ump))['_meta']['hostvars'], {})

    def test_ump_fails(self):
        cmd = 'ump server list -o ansible failed (exit status 3)'
        cases = {
            'no accounts': ('', 'no accounts configured in ~/.config/ump/config.yaml\n'),
            # one account could not be listed: the others are printed, and not taken
            'partial': (json.dumps(INVENTORY), 'ump: fake/other: 503 Service Unavailable\n'),
        }
        for name, (stdout, stderr) in cases.items():
            with self.subTest(name):
                i, ump = self.infra({'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n'}, stdout=stdout, stderr=stderr, status=3)
                self.assertFails(i, ump, 'inventory/ump.yml', cmd, stderr.strip())

    def test_notes_are_warnings(self):
        note = 'ump: fake/3 is left out of the inventory: it has no public address'
        cache = 'From cache: main (2 hours old)'
        i, ump = self.infra({'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n'}, stderr=f'{cache}\n{note}\n')
        r = i.run('ansible-inventory', '--list', env=ump.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertMessages(r.stderr, ['[WARNING]', note])
        self.assertEqual(sorted(plain(json.loads(r.stdout))['_meta']['hostvars']), ['db-01', 'web-01'])
        # what ump took from its cache is no warning; -v shows it
        self.assertNotIn('From cache', r.stderr)
        i, ump = self.infra({'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n'}, stderr=cache + '\n')
        r = i.run('ansible-inventory', '--list', env=ump.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn('WARNING', r.stderr)
        r = i.run('ansible-inventory', '--list', '-v', env=ump.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertMessages(r.stdout + r.stderr, [cache])

    def test_not_an_inventory(self):
        cases = {
            'table': ('NAME    IP\nweb-01  203.0.113.10\n', 'printed no inventory: not JSON'),
            'empty': ('', 'printed no inventory: not JSON'),
            'list': ([], 'not a JSON object'),
            'meta': ({'_meta': {'hostvars': {}, 'extra': 1}}, '_meta must have hostvars only'),
            'hostvars': ({'_meta': {'hostvars': []}}, '_meta.hostvars must be a mapping'),
            'host vars': ({'_meta': {'hostvars': {'web-01': ['a']}}}, 'the variables of web-01 must be a mapping'),
            'variable name': ({'_meta': {'hostvars': {'web-01': {'a-b': 1}}}}, 'the variables of web-01: invalid variable name(s) a-b'),
            'host name': ({'web': {'hosts': ['web 01']}}, "invalid host name(s) web 01"),
            'meta host name': ({'_meta': {'hostvars': {'web/01': {}}}}, "invalid host name(s) web/01"),
            'group name': ({'os_ubuntu-26.04': {'hosts': ['web-01']}}, 'invalid group name(s) os_ubuntu-26.04'),
            'group': ({'web': ['web-01']}, 'group web must be a mapping'),
            'group key': ({'web': {'host': ['web-01']}}, 'group web: unknown key(s) host'),
            'hosts': ({'web': {'hosts': 'web-01'}}, 'group web: hosts must be a list'),
            'children': ({'all': {'children': 'web'}}, 'group all: children must be a list'),
            'child name': ({'all': {'children': ['a.b']}}, 'group all: invalid group name(s) a.b'),
            'group vars': ({'web': {'vars': {'1a': 1}}}, 'the variables of group web: invalid variable name(s) 1a'),
        }
        for name, (stdout, message) in cases.items():
            with self.subTest(name):
                i, ump = self.infra({'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n'}, stdout=stdout)
                self.assertFails(i, ump, 'ump server list -o ansible printed no inventory', message)

    def test_nothing_added_from_a_bad_inventory(self):
        # checked whole before the first host is added
        bad = {'_meta': {'hostvars': {'web-01': {'a': 1}}}, 'web': {'hosts': ['web-01']}, 'db': {'hosts': ['db 01']}}
        i, ump = self.infra({
            'inventory/groups.yml': GROUPS,
            'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n',
        }, stdout=bad)
        r = i.run('ansible-inventory', '--list', env={**ump.env, 'ANSIBLE_INVENTORY_ANY_UNPARSED_IS_FAILED': 'false'})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertMessages(r.stderr, ['invalid host name(s) db 01'])
        self.assertEqual(plain(json.loads(r.stdout))['_meta']['hostvars'], {})

    def test_command_not_found(self):
        i, ump = self.infra({'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\ncommand: no-such-ump\n'})
        self.assertFails(i, ump, 'no-such-ump not found; install ump or set command')

    def test_timeout(self):
        i, ump = self.infra({'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\ntimeout: 1\n'}, sleep=10)
        self.assertFails(i, ump, 'ump server list -o ansible did not finish in 1 seconds')

    def test_configuration(self):
        cases = {
            'unknown key': ('plugin: ofzhur.ansible.ump\ncache: true\n', 'unknown key(s) cache'),
            'cached': ('plugin: ofzhur.ansible.ump\ncached: maybe\n', 'cached must be true or false'),
        }
        for name, (content, message) in cases.items():
            with self.subTest(name):
                i, ump = self.infra({'inventory/ump.yml': content})
                self.assertFails(i, ump, message)

    def test_host_also_in_a_host_file(self):
        # in either order: hosts/ before ump.yml, a-ump.yml before hosts/
        for config in ('ump.yml', 'a-ump.yml'):
            with self.subTest(config):
                i, ump = self.infra({
                    f'inventory/{config}': 'plugin: ofzhur.ansible.ump\n',
                    'inventory/hosts/web-01.yml': WEB,
                })
                self.assertFails(i, ump, 'host web-01 is already defined by')
        # a host only listed by static groups is no host file
        i, ump = self.infra({
            'inventory/groups.yml': 'monitoring:\n  hosts:\n    web-01:\n',
            'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n',
        })
        inv = plain(self.raw(i, ump))
        self.assertEqual(inv['monitoring']['hosts'], ['web-01'])
        self.assertEqual(inv['_meta']['hostvars']['web-01']['ump_ref'], 'fake/2')

    def test_one_server_two_hosts(self):
        # a host file of the server under its old name, read before ump or after it
        old = WEB.replace('web-01', 'old-01')
        for config, first in (('ump.yml', 'old-01'), ('a-ump.yml', 'web-01')):
            with self.subTest(config):
                i, ump = self.infra({f'inventory/{config}': 'plugin: ofzhur.ansible.ump\n', 'inventory/hosts/old-01.yml': old})
                second = 'web-01' if first == 'old-01' else 'old-01'
                self.assertFails(i, ump, f'host {second} has ump_ref fake/2, as has host {first} of', 'one server, two hosts')
        # two hosts of ump
        hostvars = dict(HOSTVARS, **{'old-01': dict(HOSTVARS['web-01'], ump_name='old-01')})
        i, ump = self.infra({'inventory/ump.yml': 'plugin: ofzhur.ansible.ump\n'}, stdout=dict(INVENTORY, _meta={'hostvars': hostvars}))
        self.assertFails(i, ump, 'inventory/ump.yml: host web-01 has ump_ref fake/2, as has host old-01: one server, two hosts')

    def test_documentation(self):
        i, ump = self.infra({})
        r = i.run('ansible-doc', '-t', 'inventory', 'ofzhur.ansible.ump', env=ump.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('ump server list -o ansible', r.stdout)
        r = i.run('ansible-doc', '-t', 'inventory', '-l', 'ofzhur.ansible', env=ump.env)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('ofzhur.ansible.ump', r.stdout)


if __name__ == '__main__':
    unittest.main()
