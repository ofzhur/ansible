# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""Tests of the role ofzhur.ansible.users and the playbook base.

The checks run the ansible CLI found on PATH only. The scenarios also run
Docker: two containers per image (web-01, db-01) reached over SSH as the
user ump, the way ump leaves a server and runs Ansible on it (as its
administrator, with ump's extra variable AS_UMP). Without Docker they are
skipped.

    python3 tests/test_users.py
"""

import re
import subprocess
import time
import unittest

import test_host

Infra = test_host.Infra

# One host on this machine for the checks. Modules cannot run on it (the
# interpreter does not exist), so nothing here can change, whatever the role
# does: only the checks of the control machine run.
LOCAL = """\
plugin: ofzhur.ansible.host
groups: [common]
vars:
  ansible_connection: local
  ansible_python_interpreter: /nonexistent/python
  ump_admin: ump
"""

# ump's own runs log in as each server's administrator, with this extra variable of ump's; a person as themselves
AS_UMP = ('-e', '{"ansible_ssh_user": "{{ ump_admin | default(ansible_user) | default(none) }}"}')

CHECK_ENV = {
    'ANSIBLE_GATHERING': 'explicit',
    'ANSIBLE_CALLBACK_RESULT_FORMAT': 'json',
}


def recap(stdout):
    """{host: {'ok': n, 'changed': n, ...}} from the PLAY RECAP."""
    return {
        host: {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', counts)}
        for host, counts in re.findall(r'^(\S+)\s+: (ok=.*)$', stdout, re.M)
    }


class Checks(unittest.TestCase):
    """The playbooks resolve; a bad entry fails before the first change."""

    def infra(self, files):
        i = Infra(files)
        self.addCleanup(i.close)
        return i

    def base(self, users_yml, *args):
        i = self.infra({
            'inventory/hosts/web-01.yml': LOCAL,
            'inventory/group_vars/common/users.yml': users_yml,
        })
        return i.run('ansible-playbook', 'ofzhur.ansible.base', '--check', '-e', 'ansible_become=false', *args, env=CHECK_ENV)

    def assertRefused(self, users_yml, *messages, ok=0):
        r = self.base(users_yml, *AS_UMP)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        for m in messages:
            self.assertIn(m, r.stdout)
        self.assertEqual(recap(r.stdout)['web-01'], {
            'ok': ok, 'changed': 0, 'unreachable': 0, 'failed': 1,
            'skipped': 0, 'rescued': 0, 'ignored': 0,
        })

    def test_syntax(self):
        i = self.infra({'inventory/hosts/web-01.yml': LOCAL})
        r = i.run('ansible-playbook', '--syntax-check', 'ofzhur.ansible.base')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_list_tasks(self):
        # the play matches the servers of the group common
        i = self.infra({'inventory/hosts/web-01.yml': LOCAL,
                        'inventory/hosts/other-01.yml': 'plugin: ofzhur.ansible.host\ngroups: [other]\n'})
        r = i.run('ansible-playbook', '--list-tasks', '--list-hosts', 'ofzhur.ansible.base')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('ofzhur.ansible.users : Users', r.stdout)
        self.assertIn('web-01', r.stdout)
        self.assertNotIn('other-01', r.stdout)

    def test_documentation(self):
        r = self.infra({}).run('ansible-doc', '-t', 'role', 'ofzhur.ansible.users')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('users_protected', r.stdout)

    def test_unknown_key(self):
        self.assertRefused(
            'users:\n  - name: oleg\n    key: [ssh-ed25519 AAAA]\n',
            'users.key. Supported parameters include')

    def test_wrong_type(self):
        cases = {
            'uid': 'users:\n  - name: oleg\n    uid: one\n',
            'hosts': 'users:\n  - name: oleg\n    hosts: {web: 1}\n',
            'users': 'users:\n  - oleg\n',
            'users_groups': 'users_groups:\n  - name: ops\n    sudo: true\n',
        }
        for name, users_yml in cases.items():
            with self.subTest(name):
                self.assertRefused(users_yml, 'Validation of arguments failed')

    def test_protected_users(self):
        cases = {
            'keys': 'users:\n  - name: ump\n    sudo: true\n    keys: [ssh-ed25519 AAAA]\n',
            'absent': 'users:\n  - name: root\n    state: absent\n    sudo: true\n',
            'no sudo': 'users:\n  - name: ump\n',
            'sudo false': 'users:\n  - name: ump\n    sudo: false\n',
            'home': 'users:\n  - name: ump\n    sudo: true\n    home: /srv/ump\n',
            'sudo only': 'users:\n  - name: ump\n    sudo: true\n',
        }
        for name, users_yml in cases.items():
            with self.subTest(name):
                self.assertRefused(users_yml, 'ump in users_protected' if 'ump' in users_yml else 'root in users_protected', ok=3)

    def test_protected_users_targeted(self):
        # an entry for another host is not refused here
        r = self.base('users:\n  - name: ump\n    hosts: db-*\n', *AS_UMP)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(recap(r.stdout)['web-01']['failed'], 0)

    def test_protected_users_by_hand(self):
        # a person logs in as themselves: the administrator stays protected, their own entry passes the
        # checks (and the task Users fails, with no interpreter on this host)
        for args in ((), ('-u', 'oleg'), ('-e', 'ansible_user=oleg')):
            with self.subTest(args):
                r = self.base('users:\n  - name: ump\n    sudo: true\n', *args)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn('ump in users_protected', r.stdout)
                r = self.base('users:\n  - name: oleg\n    sudo: true\n    keys: [ssh-ed25519 AAAA oleg]\n', *args)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertNotIn('users_protected', r.stdout)
                self.assertIn('failed: [web-01] (item=oleg)', r.stdout)
                self.assertEqual(recap(r.stdout)['web-01']['ok'], 4)

    def test_protected_users_without_administrator(self):
        # a host without ump_admin (ump did not install it): root alone, whoever logs in
        i = self.infra({
            'inventory/hosts/web-01.yml': LOCAL.replace('  ump_admin: ump\n', ''),
            'inventory/group_vars/common/users.yml': 'users:\n  - name: ump\n    sudo: true\n',
        })
        for args in (AS_UMP, ('-e', 'ansible_user=ump')):
            with self.subTest(args):
                r = i.run('ansible-playbook', 'ofzhur.ansible.base', '--check', '-e', 'ansible_become=false', *args,
                          env=CHECK_ENV)
                self.assertNotIn('users_protected', r.stdout)
                self.assertIn('failed: [web-01] (item=ump)', r.stdout)

    def test_selected_twice(self):
        self.assertRefused(
            'users:\n  - name: oleg\n  - name: oleg\n    hosts: web-*\n  - name: deploy\n    hosts: db-*\n'
            '  - name: deploy\n',
            'selected twice for web-01: oleg', ok=2)


# --- Docker -------------------------------------------------------------------

DOCKERFILE = """\
FROM {base}
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server python3 sudo \\
 && rm -rf /var/lib/apt/lists/* \\
 && mkdir -p /run/sshd && ssh-keygen -A \\
 && useradd -m -s /bin/bash ump \\
 && echo 'ump ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-ump-ump && chmod 440 /etc/sudoers.d/90-ump-ump
CMD ["/usr/sbin/sshd", "-D", "-e"]
"""

HOST = """\
plugin: ofzhur.ansible.host
groups: [common, {group}]
vars:
  ansible_host: 127.0.0.1
  ansible_port: {port}
  ump_admin: ump
  ansible_ssh_private_key_file: {dir}/ump
  ansible_ssh_common_args: -o UserKnownHostsFile={dir}/known_hosts -o IdentitiesOnly=yes
"""

USERS = """\
users_groups:
  - name: webops
    hosts: web
    state: {webops}
users:
  - name: admin
    sudo: {admin_sudo}
    keys: ['{admin_key}']
  - name: deploy
    hosts: web*
    groups: [webops]
    keys: ['{deploy_key}']
    state: {deploy}
    remove: true
  - name: dba
    hosts: '~^db-\\d+$'
  - name: nodb
    hosts: all:!db-01
  # common[0] is db-01 in the whole inventory, but web-01 within --limit web-01
  - name: first
    hosts: common[0]
"""

HOSTS = {'web-01': 'web', 'db-01': 'db'}


def docker(*argv, check=True, input=None):
    r = subprocess.run(['docker', *argv], capture_output=True, text=True, input=input)
    if check and r.returncode:
        raise AssertionError(f'docker {" ".join(argv[:2])} failed:\n{r.stdout}{r.stderr}')
    return r


def have_docker():
    try:
        return subprocess.run(['docker', 'info'], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


class Scenario:
    """Servers as ump leaves them; the playbook base run on them as ump runs it, step by step."""

    BASE = None

    @classmethod
    def setUpClass(cls):
        if not have_docker():
            raise unittest.SkipTest('Docker is not available')
        tag = cls.BASE.replace(':', '-')
        image = f'ofzhur-test-users:{tag}'
        docker('build', '-q', '-t', image, '-', input=DOCKERFILE.format(base=cls.BASE))

        cls.infra = Infra({})
        cls.addClassCleanup(cls.infra.close)
        d = cls.infra.dir
        cls.keys = {}
        for name in ('ump', 'admin', 'deploy', 'admin2'):
            subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', f'{name}@test', '-f', f'{d}/{name}'], check=True)
            with open(f'{d}/{name}.pub') as f:
                cls.keys[name] = f.read().strip()

        cls.names = {}
        for host, group in HOSTS.items():
            name = cls.names[host] = f'ofzhur-test-users-{tag}-{host}'
            docker('rm', '-f', name, check=False)
            cls.addClassCleanup(docker, 'rm', '-f', name, check=False)
            docker('run', '-d', '--name', name, '--hostname', host, '-p', '127.0.0.1::22', image)
            docker('exec', '-i', name, 'sh', '-c',
                   'install -d -m 700 -o ump -g ump /home/ump/.ssh'
                   ' && cat > /home/ump/.ssh/authorized_keys'
                   ' && chown ump:ump /home/ump/.ssh/authorized_keys'
                   ' && chmod 600 /home/ump/.ssh/authorized_keys',
                   input=cls.keys['ump'] + '\n')
            port = docker('port', name, '22/tcp').stdout.split()[0].rsplit(':', 1)[1]
            cls.infra.write(f'inventory/hosts/{host}.yml', HOST.format(group=group, port=port, dir=d))

        for _ in range(30):
            r = cls.infra.run('ansible', 'all', '-m', 'ansible.builtin.ping', *AS_UMP)
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            raise AssertionError(f'the containers are not reachable over SSH:\n{r.stdout}{r.stderr}')

    def users(self, admin_sudo='true', admin_key='admin', deploy='present', webops='present'):
        self.infra.write('inventory/group_vars/common/users.yml', USERS.format(
            admin_sudo=admin_sudo, admin_key=self.keys[admin_key], deploy_key=self.keys['deploy'],
            deploy=deploy, webops=webops))

    def play(self, *args):
        r = self.infra.run('ansible-playbook', 'ofzhur.ansible.base', *AS_UMP, *args)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return recap(r.stdout)

    def sh(self, host, command, user='root'):
        return docker('exec', '-u', user, self.names[host], 'sh', '-c', command, check=False)

    def out(self, host, command):
        r = self.sh(host, command)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def assertUsers(self, host, present, absent):
        for user in present:
            self.assertEqual(self.sh(host, f'getent passwd {user}').returncode, 0, f'{user} on {host}')
        for user in absent:
            self.assertNotEqual(self.sh(host, f'getent passwd {user}').returncode, 0, f'{user} on {host}')

    def assertKeys(self, host, user, *keys):
        home = f'/home/{user}'
        self.assertEqual(self.out(host, f'stat -c "%a %U %G" {home}/.ssh {home}/.ssh/authorized_keys').split('\n'),
                         [f'700 {user} {user}', f'600 {user} {user}', ''])
        self.assertEqual(self.out(host, f'cat {home}/.ssh/authorized_keys'), ''.join(k + '\n' for k in keys))

    def test_0_check(self):
        # check mode on new servers: users to create have no home yet
        self.users()
        counts = self.play('--check')
        self.assertEqual(sorted(counts), ['db-01', 'web-01'])
        self.assertUsers('web-01', ['ump'], ['admin', 'deploy', 'nodb'])
        self.assertNotEqual(self.sh('web-01', 'getent group webops').returncode, 0)

    def test_1_run(self):
        self.users()
        counts = self.play()
        self.assertEqual(sorted(counts), ['db-01', 'web-01'])
        self.assertUsers('web-01', ['admin', 'deploy', 'nodb', 'ump'], ['dba', 'first'])
        self.assertUsers('db-01', ['admin', 'dba', 'first', 'ump'], ['deploy', 'nodb'])
        self.assertIn('webops', self.out('web-01', 'id -nG deploy').split())
        self.assertNotEqual(self.sh('db-01', 'getent group webops').returncode, 0)

        for host in HOSTS:
            self.assertKeys(host, 'admin', self.keys['admin'])
            self.assertEqual(self.out(host, 'stat -c "%a %U %G" /etc/sudoers.d/admin'), '440 root root\n')
            self.assertEqual(self.out(host, 'cat /etc/sudoers.d/admin'), 'admin ALL=(ALL:ALL) NOPASSWD: ALL\n')
            self.assertEqual(self.sh(host, 'sudo -n true', user='admin').returncode, 0)
            self.assertEqual(self.out(host, 'getent passwd admin').strip().rsplit(':', 1)[1], '/bin/bash')
            # a new user has no usable password
            self.assertRegex(self.out(host, 'getent shadow admin').split(':')[1], r'^[!*]')
        self.assertKeys('web-01', 'deploy', self.keys['deploy'])
        self.assertNotEqual(self.sh('web-01', 'sudo -n true', user='deploy').returncode, 0)
        self.assertNotEqual(self.sh('web-01', 'test -e /etc/sudoers.d/deploy').returncode, 0)
        # without keys, no ~/.ssh
        self.assertNotEqual(self.sh('db-01', 'test -e /home/dba/.ssh').returncode, 0)

    def test_2_again(self):
        counts = self.play()
        for host in HOSTS:
            self.assertEqual(counts[host]['changed'], 0, host)
        # a person logs in as themselves, a user of the list
        r = self.infra.run('ansible-playbook', 'ofzhur.ansible.base', '-u', 'admin',
                           '-e', f'ansible_ssh_private_key_file={self.infra.dir}/admin')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for host in HOSTS:
            self.assertEqual(recap(r.stdout)[host]['changed'], 0, host)

    def test_3_limit(self):
        # patterns see the whole inventory: first stays on db-01
        counts = self.play('--limit', 'web-01')
        self.assertEqual(list(counts), ['web-01'])
        self.assertEqual(counts['web-01']['changed'], 0)
        self.assertUsers('web-01', [], ['first'])

    def test_4_keys_and_sudo(self):
        self.users(admin_sudo='false', admin_key='admin2')
        self.play()
        for host in HOSTS:
            self.assertKeys(host, 'admin', self.keys['admin2'])
            self.assertNotEqual(self.sh(host, 'test -e /etc/sudoers.d/admin').returncode, 0)
            self.assertNotEqual(self.sh(host, 'sudo -n true', user='admin').returncode, 0)

    def test_5_login(self):
        # ump's runs log in as the administrator, also with -u; a person as -u says
        person = ('-u', 'admin', '-e', f'ansible_ssh_private_key_file={self.infra.dir}/admin2')
        for args, user in ((AS_UMP, 'ump'), ((*AS_UMP, '-u', 'admin'), 'ump'), (person, 'admin')):
            with self.subTest(args):
                r = self.infra.run('ansible', 'web-01', '-m', 'ansible.builtin.command', '-a', 'id -un', *args)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(r.stdout.split()[-1], user)

    def test_6_string_key(self):
        # a string is one key, not one character per line
        self.infra.write('inventory/group_vars/common/users.yml',
                         f"users:\n  - name: solo\n    hosts: web-01\n    keys: '{self.keys['admin']}'\n")
        self.play()
        self.assertKeys('web-01', 'solo', self.keys['admin'])

    def test_7_ssh_link(self):
        # root never follows a ~/.ssh the user made a link: the run fails, the target stays
        self.out('web-01', 'install -d -m 755 /opt/rootdir'
                           ' && mv /home/solo/.ssh /home/solo/ssh.old && ln -s /opt/rootdir /home/solo/.ssh')
        r = self.infra.run('ansible-playbook', 'ofzhur.ansible.base', *AS_UMP, '--limit', 'web-01')
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertEqual(self.out('web-01', 'stat -c "%a %U %G" /opt/rootdir'), '755 root root\n')
        self.assertNotEqual(self.sh('web-01', 'test -e /opt/rootdir/authorized_keys').returncode, 0)
        self.out('web-01', 'rm /home/solo/.ssh && mv /home/solo/ssh.old /home/solo/.ssh')

    def test_8_absent(self):
        self.users(admin_sudo='false', admin_key='admin2', deploy='absent', webops='absent')
        self.play()
        self.assertUsers('web-01', ['admin', 'nodb'], ['deploy'])
        self.assertNotEqual(self.sh('web-01', 'test -e /home/deploy').returncode, 0)
        self.assertNotEqual(self.sh('web-01', 'getent group webops').returncode, 0)
        counts = self.play()
        for host in HOSTS:
            self.assertEqual(counts[host]['changed'], 0, host)


class Ubuntu(Scenario, unittest.TestCase):
    BASE = 'ubuntu:24.04'


class Debian(Scenario, unittest.TestCase):
    BASE = 'debian:trixie'


if __name__ == '__main__':
    unittest.main()
