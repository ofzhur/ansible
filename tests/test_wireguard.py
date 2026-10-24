# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""Tests of the role ofzhur.ansible.wireguard.

The checks run the ansible CLI found on PATH only. The scenario also runs
Docker: six containers with systemd on one Docker network (a, c and e on
Debian 13, b, d and f on Ubuntu 24.04), each reached over SSH as the user
ump through `docker exec` and nc, so that ansible_host is the container's
address on the network, the endpoint its peers reach, as a server's public
address is. Without Docker it is skipped.

    python3 tests/test_wireguard.py

With the role ofzhur.ansible.firewall in the collection the scenario runs it
too and checks the ports it opens and the connections it lets in; without,
wireguard_firewall is false and the peers connect both ways.
"""

import json
import os
import shutil
import subprocess
import time
import unittest

import test_host
from test_users import AS_UMP, CHECK_ENV, docker, have_docker, recap

Infra = test_host.Infra

FIREWALL = os.path.exists(os.path.join(test_host.ROOT, 'roles', 'firewall', 'tasks', 'announce.yml'))

PLAYBOOK = """\
- name: WireGuard
  hosts: common
  become: true
  roles:
    - ofzhur.ansible.wireguard
"""

PLAYBOOK_FIREWALL = """\
- name: WireGuard
  hosts: common
  become: true
  roles:
    - ofzhur.ansible.firewall
    - ofzhur.ansible.wireguard
"""

# One host on this machine for the checks. Modules cannot run on it (the
# interpreter does not exist): only the checks of the control machine run.
LOCAL = """\
plugin: ofzhur.ansible.host
groups: [common]
vars:
  ansible_connection: local
  ansible_python_interpreter: /nonexistent/python
  ump_admin: ump
  ump_private_networks:
    default: {address: 10.0.0.1, cidr: 10.0.0.0/24}
    lab: {address: 10.0.1.1, cidr: 10.0.1.0/24}
"""


class Checks(unittest.TestCase):
    """The playbook resolves; a bad variable or network fails before the first change."""

    def infra(self, files):
        i = Infra({'playbooks/wireguard.yml': PLAYBOOK, **files})
        self.addCleanup(i.close)
        return i

    def run_role(self, files, host=LOCAL):
        i = self.infra({'inventory/hosts/web-01.yml': host, **files})
        return i.run('ansible-playbook', 'playbooks/wireguard.yml', '--check', '-e', 'ansible_become=false', *AS_UMP,
                     env=CHECK_ENV)

    def assertRefused(self, files, *messages, host=LOCAL, ok=0):
        r = self.run_role(files, host)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        for m in messages:
            self.assertIn(m, r.stdout)
        self.assertEqual(recap(r.stdout)['web-01'], {
            'ok': ok, 'changed': 0, 'unreachable': 0, 'failed': 1,
            'skipped': 0, 'rescued': 0, 'ignored': 0,
        })

    def test_syntax(self):
        i = self.infra({'inventory/hosts/web-01.yml': LOCAL})
        r = i.run('ansible-playbook', '--syntax-check', 'playbooks/wireguard.yml')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_documentation(self):
        r = self.infra({}).run('ansible-doc', '-t', 'role', 'ofzhur.ansible.wireguard')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('wireguard_groups', r.stdout)

    def test_valid(self):
        # every check passes; the first module fails, with no interpreter on this host
        r = self.run_role({'inventory/host_vars/web-01.yml': 'wireguard_groups: {lab: [db]}\nwireguard_ports: {lab: 51820}\n',
                           'inventory/group_vars/all.yml': 'wireguard_isolation: [common]\n'})
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn('TASK [ofzhur.ansible.wireguard : Look for /etc/wireguard]', r.stdout)
        self.assertEqual(recap(r.stdout)['web-01']['ok'], 5)

    def test_wrong_type(self):
        cases = {
            'networks': 'wireguard_networks: [default]\n',
            'ports': 'wireguard_ports: [51820]\n',
            'firewall': 'wireguard_firewall: maybe\n',
            'isolation': 'wireguard_isolation: {foo: 1}\n',
        }
        for name, host_vars in cases.items():
            with self.subTest(name):
                self.assertRefused({'inventory/host_vars/web-01.yml': host_vars}, 'Validation of arguments failed')

    def test_invalid_networks(self):
        net = 'wireguard_networks: {{{}: {{address: {}, cidr: {}}}}}\n'.format
        cases = {
            'long name': (net('abcdefghijklm', '10.0.0.1', '10.0.0.0/24'), 'network abcdefghijklm: the name is not'),
            'upper case': (net('Lab', '10.0.0.1', '10.0.0.0/24'), 'network Lab: the name is not'),
            'host as cidr': (net('lab', '10.0.0.1', '10.0.0.5/24'), 'network lab: cidr 10.0.0.5/24 is no IPv4 network'),
            '/31': (net('lab', '10.0.0.1', '10.0.0.0/31'), 'cidr 10.0.0.0/31 is no IPv4 network'),
            'octet': (net('lab', '10.0.0.1', '10.0.256.0/24'), 'cidr 10.0.256.0/24 is no IPv4 network'),
            'outside': (net('lab', '10.0.1.5', '10.0.0.0/24'), 'network lab: address 10.0.1.5 is no host of its cidr'),
            'broadcast': (net('lab', '10.0.0.255', '10.0.0.0/24'), 'address 10.0.0.255 is no host'),
            'no address': ('wireguard_networks: {lab: {cidr: 10.0.0.0/24}}\n', 'address (none) is no host'),
            'no mapping': ('wireguard_networks: {lab: 10.0.0.1}\n', 'network lab: cidr (none)'),
            'port': ('wireguard_ports: {lab: 70000}\n', 'network lab: port 70000 is no port'),
            'port string': ("wireguard_ports: {lab: '51820'}\n", 'network lab: port 51820 is no port'),
            'one port': ('wireguard_ports: {default: 51820, lab: 51820}\n',
                         'two networks, one port: default 51820, lab 51820; set wireguard_ports'),
            'groups string': ('wireguard_groups: db\n', 'network default: wireguard_groups is no list'),
            'groups by network': ('wireguard_groups: {lab: db}\n', 'network lab: wireguard_groups is no list'),
            'group name': ('wireguard_groups: [1]\n', 'wireguard_groups is no list'),
            'isolation string': ('wireguard_isolation: common\n',
                                 'network default: wireguard_isolation is no list of group names'),
        }
        for name, (host_vars, message) in cases.items():
            with self.subTest(name):
                self.assertRefused({'inventory/host_vars/web-01.yml': host_vars}, message, ok=3)

    def test_outside_the_inventory(self):
        # the other hosts would not see a role parameter or a play variable
        playbooks = {
            'parameter': PLAYBOOK.replace('- ofzhur.ansible.wireguard',
                                          '- role: ofzhur.ansible.wireguard\n      wireguard_groups: [db]'),
            'play': PLAYBOOK.replace('  roles:', '  vars:\n    wireguard_ports: {default: 51820}\n  roles:'),
            'isolation': PLAYBOOK.replace('  roles:', '  vars:\n    wireguard_isolation: [common]\n  roles:'),
        }
        for name, playbook in playbooks.items():
            with self.subTest(name):
                r = self.run_role({'playbooks/wireguard.yml': playbook})
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn('of web-01 set outside the inventory; set it in group_vars or host_vars', r.stdout)
        # extra variables: every host sees them
        r = self.run_role({})
        self.assertNotIn('outside the inventory', r.stdout)


# --- Docker -------------------------------------------------------------------

DOCKERFILE = """\
FROM {base}
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \\
      systemd systemd-sysv dbus openssh-server python3 sudo iproute2 iputils-ping netcat-openbsd \\
 && rm -rf /var/lib/apt/lists/* \\
 && useradd -m -s /bin/bash ump \\
 && echo 'ump ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-ump-ump && chmod 440 /etc/sudoers.d/90-ump-ump
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
"""

BASES = {'debian': 'debian:trixie', 'ubuntu': 'ubuntu:24.04'}

# All six in default, c and f in lab.1 too (a name with a dot). e's host file
# is one of ump v0.5.0, with its one network alone.
NETWORKS = {
    'a': {'default': '10.0.0.1'},
    'b': {'default': '10.0.0.2'},
    'c': {'default': '10.0.0.3', 'lab.1': '10.0.1.3'},
    'd': {'default': '10.0.0.4'},
    'e': {'default': '10.0.0.5'},
    'f': {'default': '10.0.0.6', 'lab.1': '10.0.1.6'},
}
CIDRS = {'default': '10.0.0.0/24', 'lab.1': '10.0.1.0/24'}
# 51820 + int(sha1(NAME)[:8], 16) % 1000
PORTS = {'default': 52630, 'lab.1': 52579}
HOSTS = {'a': 'debian', 'b': 'ubuntu', 'c': 'debian', 'd': 'ubuntu', 'e': 'debian', 'f': 'ubuntu'}

HOST = """\
plugin: ofzhur.ansible.host
groups: {groups}
vars:
  ansible_host: {address}
  ump_admin: ump
{private}  ansible_ssh_private_key_file: {dir}/ump
  ansible_ssh_common_args: >-
    -o UserKnownHostsFile={dir}/known_hosts -o IdentitiesOnly=yes
    -o ProxyCommand="{docker} exec -i {container} nc 127.0.0.1 22"
"""

ISOLATION = 'wireguard_isolation: [foo, bar]\n'

# Routes another program owns through an interface: one to the interface,
# one via a peer. The tests check that they stay, not that they carry
# anything: WireGuard sends to the peer whose AllowedIPs hold the
# destination, whatever the gateway.
ROUTES = {'default': ('192.0.2.0/24', '198.51.100.0/24'), 'lab.1': ('203.0.113.0/25', '203.0.113.128/25')}


def private(networks, v050=False):
    """The private variables of a host file, as ump writes them."""
    first, address = next(iter(networks.items()))
    lines = []
    if not v050:
        lines.append('  ump_private_networks:\n')
        lines += [f'    {n}: {{address: {a}, cidr: {CIDRS[n]}}}\n' for n, a in networks.items()]
    lines += [f'  ump_private_address: {address}\n', f'  ump_private_network: {first}\n',
              f'  ump_private_cidr: {CIDRS[first]}\n']
    return ''.join(lines)


def both(hosts):
    """New connections between any two of hosts, both ways."""
    return {(x, y) for x in hosts for y in hosts if x != y}


def one_way(sources, targets):
    """New connections from each of sources to each of targets."""
    return {(x, y) for x in sources for y in targets}


def says(r, message):
    """Whether the run's output has message, however the callback wrapped it."""
    return ''.join(message.split()) in ''.join(r.stdout.split())


def task(r, name):
    """The output of the role's task name in the run."""
    return r.stdout.split(f'TASK [ofzhur.ansible.wireguard : {name}]', 1)[1].split('TASK [', 1)[0]


def untagged(value):
    """value without the tags that ansible-core >= 2.19 keeps in its fact cache."""
    if isinstance(value, dict):
        if '__ansible_type' in value and 'value' in value:
            return untagged(value['value'])
        return {k: untagged(v) for k, v in value.items()}
    if isinstance(value, list):
        return [untagged(v) for v in value]
    return value


class Mesh(unittest.TestCase):
    """Six servers as ump leaves them; the role run on them as ump runs it, step by step."""

    @classmethod
    def setUpClass(cls):
        if not have_docker():
            raise unittest.SkipTest('Docker is not available')
        for os_, base in BASES.items():
            docker('build', '-q', '-t', f'ofzhur-test-wireguard:{os_}', '-', input=DOCKERFILE.format(base=base))

        cls.net = 'ofzhur-test-wireguard'
        cls.names = {h: f'ofzhur-test-wireguard-{h}' for h in HOSTS}
        for name in cls.names.values():
            docker('rm', '-f', name, check=False)
        docker('network', 'rm', cls.net, check=False)
        docker('network', 'create', cls.net)
        cls.addClassCleanup(docker, 'network', 'rm', cls.net, check=False)

        cls.infra = Infra({'playbooks/wireguard.yml': PLAYBOOK_FIREWALL if FIREWALL else PLAYBOOK})
        cls.addClassCleanup(cls.infra.close)
        d = cls.infra.dir
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'ump@test', '-f', f'{d}/ump'], check=True)
        with open(f'{d}/ump.pub') as f:
            key = f.read().strip()

        cls.addresses = {}
        cls.networks = {h: dict(n) for h, n in NETWORKS.items()}
        cls.groups = {h: [] for h in HOSTS}
        for host, os_ in HOSTS.items():
            name = cls.names[host]
            cls.addClassCleanup(docker, 'rm', '-f', name, check=False)
            docker('run', '-d', '--name', name, '--hostname', host, '--network', cls.net, '--privileged',
                   '--tmpfs', '/run', '--tmpfs', '/run/lock', f'ofzhur-test-wireguard:{os_}')
            docker('exec', '-i', name, 'sh', '-c',
                   'install -d -m 700 -o ump -g ump /home/ump/.ssh'
                   ' && cat > /home/ump/.ssh/authorized_keys'
                   ' && chown ump:ump /home/ump/.ssh/authorized_keys'
                   ' && chmod 600 /home/ump/.ssh/authorized_keys',
                   input=key + '\n')
            cls.addresses[host] = docker('inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',
                                         name).stdout.strip()
            cls.host_file(host)
        cls.infra.write('inventory/group_vars/all.yml', ISOLATION + ('' if FIREWALL else 'wireguard_firewall: false\n'))

        for _ in range(30):
            r = cls.infra.run('ansible', 'all', '-m', 'ansible.builtin.ping', *AS_UMP)
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            raise AssertionError(f'the containers are not reachable over SSH:\n{r.stdout}{r.stderr}')

    @classmethod
    def host_file(cls, host):
        cls.infra.write(f'inventory/hosts/{host}.yml', HOST.format(
            groups=json.dumps(['common'] + cls.groups[host]), address=cls.addresses[host],
            private=private(cls.networks[host], v050=host == 'e'),
            dir=cls.infra.dir, docker=shutil.which('docker'), container=cls.names[host]))

    def set_groups(self, **groups):
        """Puts each host into the Ansible groups given, the others into none but common."""
        for host in HOSTS:
            self.groups[host] = groups.get(host, [])
            self.host_file(host)

    def play(self, *args):
        r = self.infra.run('ansible-playbook', 'playbooks/wireguard.yml', *AS_UMP, *args)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r

    def assertUnchanged(self, r):
        for host, counts in recap(r.stdout).items():
            self.assertEqual(counts['changed'], 0, f'{host}\n{r.stdout}')

    def sh(self, host, command):
        return docker('exec', self.names[host], 'sh', '-c', command, check=False)

    def out(self, host, command):
        r = self.sh(host, command)
        self.assertEqual(r.returncode, 0, f'{host}: {command}: {r.stderr}')
        return r.stdout

    def public_key(self, host, network):
        return self.out(host, f'wg show wg-{network} public-key').strip()

    def assertPeers(self, host, network, peers):
        keys = set(self.out(host, f'wg show wg-{network} peers').split())
        self.assertEqual(keys, {self.public_key(p, network) for p in peers}, f'peers of {host} in {network}')

    def reaches(self, host, address, tries=1):
        for _ in range(tries):
            if self.sh(host, f'ping -c 1 -W 1 {address}').returncode == 0:
                return True
        return False

    def assertReaches(self, host, address):
        self.assertTrue(self.reaches(host, address, tries=10), f'{host} does not reach {address}')

    def assertNotReaches(self, host, address):
        self.assertFalse(self.reaches(host, address), f'{host} reaches {address}')

    def assertConnections(self, expected, network='default'):
        """Of the hosts in network, those of expected (x, y) reach each other's address, from x; no others."""
        if not FIREWALL:
            expected = expected | {(y, x) for x, y in expected}
        hosts = [h for h in HOSTS if network in self.networks[h]]
        for x, y in sorted(expected):
            self.assertReaches(x, self.networks[y][network])
        for x in hosts:
            for y in hosts:
                if x != y and (x, y) not in expected:
                    self.assertNotReaches(x, self.networks[y][network])

    def ifindex(self, host, network):
        return self.out(host, f'cat /sys/class/net/wg-{network}/ifindex').strip()

    def ifindexes(self, hosts=HOSTS):
        return {(h, n): self.ifindex(h, n) for h in hosts for n in self.networks[h]}

    def inet(self, host, network):
        return [a.split()[3] for a in self.out(host, f'ip -4 -o address show dev wg-{network}').splitlines()]

    def add_routes(self, host, network, via):
        """Puts the ROUTES of network through host's interface, the second via the peer via."""
        to, gateway = ROUTES[network]
        self.out(host, f'ip route replace {to} dev wg-{network}'
                       f' && ip route replace {gateway} via {self.networks[via][network]} dev wg-{network}')
        self.addCleanup(self.sh, host, f'ip route del {to}; ip route del {gateway}')

    def assertRoutes(self, host, network, via):
        """The ROUTES of network, through host's interface, are there."""
        to, gateway = ROUTES[network]
        routes = [r.split() for r in self.out(host, f'ip -4 route show dev wg-{network}').splitlines()]
        self.assertIn([to, 'scope', 'link'], routes, host)
        self.assertIn([gateway, 'via', self.networks[via][network]], routes, host)

    def cache(self, host):
        cache = os.path.join(self.infra.dir, '.cache', 'facts')
        path = os.path.join(cache, f's1_{host}')  # ansible-core >= 2.19
        with open(path if os.path.exists(path) else os.path.join(cache, host)) as f:
            return f.read()

    def forget(self, *hosts):
        """Removes the cached facts of hosts, as when they expire."""
        cache = os.path.join(self.infra.dir, '.cache', 'facts')
        for host in hosts:
            for name in (host, f's1_{host}'):
                if os.path.exists(os.path.join(cache, name)):
                    os.remove(os.path.join(cache, name))

    def cached_keys(self, host):
        facts = json.loads(self.cache(host))
        if '__payload__' in facts:  # ansible-core >= 2.19
            facts = json.loads(facts['__payload__'])
        return untagged(facts['wireguard_public_keys'])

    def ruleset(self, host):
        return self.out(host, 'nft list ruleset')

    def announced(self, host, network):
        """The announcement of network to the firewall, or None."""
        r = self.sh(host, f'cat /etc/ofzhur/firewall.d/wireguard-{network}.json')
        return json.loads(r.stdout) if r.returncode == 0 else None

    def assertAnnounced(self, host, network, accept_from):
        """host announced its peers' addresses and, on the interface, new connections from accept_from."""
        peers = set(self.out(host, f'wg show wg-{network} endpoints').split()[1::2])
        a = self.announced(host, network)
        self.assertEqual([r['sources'] for r in a['rules']], [sorted(p.rsplit(':', 1)[0] for p in peers)], host)
        accept_from = [self.networks[h][network] for h in accept_from]
        self.assertEqual(a['interfaces'], {f'wg-{network}': {'accept_from': accept_from}}, host)

    def test_01_check(self):
        # servers as ump leaves them, without python3-apt: check mode changes nothing
        r = self.play('--check')
        self.assertEqual(sorted(recap(r.stdout)), list(HOSTS))
        for host in HOSTS:
            self.assertNotEqual(self.sh(host, 'ls /etc/wireguard').returncode, 0, host)
            self.assertNotEqual(self.sh(host, 'command -v wg').returncode, 0, host)

    def test_02_mesh(self):
        # all six in foo: any two connect, both ways
        self.set_groups(**{h: ['foo'] for h in HOSTS})
        r = self.play('-v', '--diff')
        self.assertEqual(sorted(recap(r.stdout)), list(HOSTS))
        self.assertFalse(says(r, 'wireguard: default: ') or says(r, 'wireguard: lab.1: '), r.stdout)

        # one interface per network, on its port, with the host's address
        for host, networks in NETWORKS.items():
            self.assertEqual(self.out(host, 'wg show interfaces').split(), [f'wg-{n}' for n in sorted(networks)], host)
            for n, address in networks.items():
                self.assertEqual(self.out(host, f'wg show wg-{n} listen-port').strip(), str(PORTS[n]))
                self.assertIn(f' inet {address}/24 ', self.out(host, f'ip -4 -o address show dev wg-{n}'))
                # wg-quick adds no routes: the network's, of the kernel, is the one
                self.assertIn('\nTable = off\n', self.out(host, f'cat /etc/wireguard/wg-{n}.conf'))
                self.assertEqual(self.out(host, f'ip -4 route show dev wg-{n}').split(),
                                 f'{CIDRS[n]} proto kernel scope link src {address}'.split())
                self.assertEqual(self.out(host, f'stat -c "%a %U" /etc/wireguard /etc/wireguard/wg-{n}.conf'
                                                f' /etc/wireguard/wg-{n}.key').split('\n'),
                                 ['700 root', '600 root', '600 root', ''])
                self.assertEqual(self.out(host, f'systemctl is-enabled wg-quick@wg-{n}').strip(), 'enabled')
                self.assertEqual(self.out(host, f'systemctl is-active wg-quick@wg-{n}').strip(), 'active')
                # the private key: on the host alone; the public key: in the fact cache
                private_key = self.out(host, f'cat /etc/wireguard/wg-{n}.key').strip()
                self.assertNotIn(private_key, r.stdout + r.stderr)
                self.assertEqual(self.out(host, f'wg show wg-{n} private-key').strip(), private_key)
                self.assertEqual(self.cached_keys(host)[n], self.public_key(host, n))
                self.assertNotIn(private_key, self.cache(host))
            self.assertEqual(sorted(self.cached_keys(host)), sorted(networks))

        for host in HOSTS:
            self.assertPeers(host, 'default', [h for h in HOSTS if h != host])
        self.assertPeers('c', 'lab.1', ['f'])
        self.assertPeers('f', 'lab.1', ['c'])
        self.assertIn(f'{self.addresses["c"]}:{PORTS["default"]}', self.out('b', 'wg show wg-default endpoints'))
        self.assertIn('10.0.0.3/32', self.out('b', 'wg show wg-default allowed-ips'))
        self.assertTrue(self.out('b', 'wg show wg-default persistent-keepalive').endswith('\t25\n'))

        self.assertConnections(both(HOSTS))
        self.assertConnections(both('cf'), 'lab.1')
        # networks are apart
        self.assertNotReaches('a', '10.0.1.3')

        if FIREWALL:
            self.assertAnnounced('a', 'default', 'bcdef')
            self.assertAnnounced('c', 'lab.1', 'f')
            rules = self.ruleset('a')
            self.assertIn(str(PORTS['default']), rules)
            for h in 'bcdef':
                self.assertIn(self.addresses[h], rules)

    def test_03_again(self):
        self.assertUnchanged(self.play())
        self.assertUnchanged(self.play('--check'))

    def test_04_foo(self):
        # a and b in foo, the others in none: a and b connect to each other and to the others; the others
        # to each other alone. Without an interruption.
        before = self.ifindexes()
        self.set_groups(a=['foo'], b=['foo'])
        self.play()
        self.assertEqual(self.ifindexes(), before)
        for host in HOSTS:
            self.assertPeers(host, 'default', [h for h in HOSTS if h != host])
        self.assertConnections(both('ab') | both('cdef') | one_way('ab', 'cdef'))
        if FIREWALL:
            self.assertAnnounced('a', 'default', 'b')
            self.assertAnnounced('c', 'default', 'abdef')

    def test_05_foo_bar(self):
        # a and b in foo, c and d in bar: foo and bar apart, no peers; e and f connect to each other, the
        # others to them. c's Ansible groups hold in lab.1 too.
        before = self.ifindexes()
        self.set_groups(a=['foo'], b=['foo'], c=['bar'], d=['bar'])
        self.play()
        self.assertEqual(self.ifindexes(), before)
        self.assertPeers('a', 'default', ['b', 'e', 'f'])
        self.assertPeers('c', 'default', ['d', 'e', 'f'])
        self.assertPeers('e', 'default', ['a', 'b', 'c', 'd', 'f'])
        self.assertConnections(both('ab') | both('cd') | both('ef') | one_way('abcd', 'ef'))
        self.assertConnections(one_way('c', 'f'), 'lab.1')
        if FIREWALL:
            self.assertAnnounced('a', 'default', 'b')
            self.assertAnnounced('e', 'default', 'abcdf')
            self.assertAnnounced('c', 'lab.1', '')

    def test_06_wireguard_groups(self):
        # wireguard_groups in place of the Ansible groups: e's list in every network, c's mapping in lab.1
        self.infra.write('inventory/host_vars/c.yml', 'wireguard_groups: {lab.1: []}\n')
        self.infra.write('inventory/host_vars/e.yml', 'wireguard_groups: [foo]\n')
        self.play()
        self.assertPeers('e', 'default', ['a', 'b', 'f'])
        self.assertPeers('c', 'default', ['d', 'f'])
        self.assertConnections(both('abe') | both('cd') | one_way('abcde', 'f'))
        self.assertConnections(both('cf'), 'lab.1')
        self.assertUnchanged(self.play())

    def test_07_limit(self):
        # the peers outside --limit come from the fact cache
        r = self.play('--limit', 'b')
        self.assertEqual(list(recap(r.stdout)), ['b'])
        self.assertUnchanged(r)
        self.assertPeers('b', 'default', ['a', 'e', 'f'])

    def test_08_expired(self):
        # the keys of the peers outside --limit gone from the fact cache (expired, or flushed: --flush-cache
        # of ansible-core 2.19 flushes every host, of 2.16 those of --limit alone): b's configuration has them
        self.forget(*(h for h in HOSTS if h != 'b'))
        r = self.play('--limit', 'b', '--flush-cache')
        self.assertUnchanged(r)
        self.assertFalse(says(r, 'no public key yet'), r.stdout)
        self.assertPeers('b', 'default', ['a', 'e', 'f'])
        # a peer isolated now goes, whatever its key; back, it waits for its own run
        self.infra.write('inventory/host_vars/e.yml', 'wireguard_groups: [bar]\n')
        self.play('--limit', 'b')
        self.assertPeers('b', 'default', ['a', 'f'])
        self.infra.write('inventory/host_vars/e.yml', 'wireguard_groups: [foo]\n')
        r = self.play('--limit', 'b')
        self.assertTrue(says(r, 'wireguard: default: e: no public key yet; it joins once it ran'), r.stdout)
        self.assertPeers('b', 'default', ['a', 'f'])
        self.play()
        self.assertPeers('b', 'default', ['a', 'e', 'f'])

    def test_09_address(self):
        # a new address, then a new prefix, go onto the running interface: the link stays, and with it the
        # routes of others through it; its peers follow. f's wg-default is up without its unit (wg-quick up
        # by hand): changed in place too, and left so.
        self.out('f', 'systemctl stop wg-quick@wg-default && wg-quick up wg-default 2>&1')
        self.add_routes('a', 'default', 'b')
        before = self.ifindexes()
        self.networks['a'] = {'default': '10.0.0.11'}
        self.host_file('a')
        # check mode tells, and changes nothing
        r = self.play('--check')
        self.assertIn('changed: [a]', task(r, 'Addresses of the running interfaces'))
        self.assertEqual(self.inet('a', 'default'), ['10.0.0.1/24'])

        self.play()
        self.assertEqual(self.inet('a', 'default'), ['10.0.0.11/24'])
        self.assertEqual(self.ifindexes(), before)
        self.assertRoutes('a', 'default', 'b')
        self.assertIn('10.0.0.11/32', self.out('b', 'wg show wg-default allowed-ips'))
        self.assertIn('10.0.0.11/32', self.out('f', 'wg show wg-default allowed-ips'))
        self.assertEqual(self.sh('f', 'systemctl is-active wg-quick@wg-default').stdout.strip(), 'inactive')
        self.assertReaches('b', '10.0.0.11')
        self.assertReaches('a', '10.0.0.6')

        # a new prefix (wireguard_networks in place of ump's), and back
        self.infra.write('inventory/host_vars/a.yml',
                         'wireguard_networks: {default: {address: 10.0.0.11, cidr: 10.0.0.0/16}}\n')
        self.play()
        self.assertEqual(self.inet('a', 'default'), ['10.0.0.11/16'])
        self.assertEqual(self.ifindexes(), before)
        self.assertRoutes('a', 'default', 'b')
        os.remove(os.path.join(self.infra.dir, 'inventory', 'host_vars', 'a.yml'))
        self.play()
        self.assertEqual(self.inet('a', 'default'), ['10.0.0.11/24'])
        self.assertEqual(self.ifindexes(), before)
        self.assertRoutes('a', 'default', 'b')
        self.assertReaches('b', '10.0.0.11')
        self.assertUnchanged(self.play())

    def test_10_leave(self):
        # f leaves its networks (wireguard_networks in place of ump's): its interfaces go, wg-default up without
        # its unit too, and its peers'. The peers' interfaces stay, and the routes of others through them.
        self.add_routes('a', 'default', 'b')
        self.add_routes('c', 'lab.1', 'f')
        before = self.ifindexes('abcde')
        self.infra.write('inventory/host_vars/f.yml', 'wireguard_networks: {}\n')
        self.play()
        self.assertEqual(self.ifindexes('abcde'), before)
        self.assertRoutes('a', 'default', 'b')
        self.assertRoutes('c', 'lab.1', 'f')
        for n in ('default', 'lab.1'):
            self.assertNotEqual(self.sh('f', f'ip link show wg-{n}').returncode, 0)
            self.assertNotEqual(self.sh('f', f'ls /etc/wireguard/wg-{n}.conf').returncode, 0)
            self.assertNotEqual(self.sh('f', f'ls /etc/wireguard/wg-{n}.key').returncode, 0)
            self.assertNotEqual(self.sh('f', f'systemctl is-enabled wg-quick@wg-{n}').stdout.strip(), 'enabled')
        self.assertEqual(self.cached_keys('f'), {})
        self.assertPeers('c', 'lab.1', [])
        self.assertPeers('a', 'default', ['b', 'e'])
        self.assertNotReaches('c', '10.0.1.6')
        if FIREWALL:
            self.assertEqual(self.sh('f', 'ls /etc/ofzhur/firewall.d/wireguard-*').returncode, 2)
            self.assertNotIn(str(PORTS['default']), self.ruleset('f'))
            self.assertNotIn(self.addresses['f'], self.ruleset('c'))
            self.assertIsNone(self.announced('c', 'lab.1'))
        self.assertUnchanged(self.play())

    def test_11_join(self):
        # f back: its peers know it once it ran, and they ran after it; their interfaces stay, and the
        # routes of others through them
        self.add_routes('a', 'default', 'b')
        self.add_routes('c', 'lab.1', 'f')
        before = self.ifindexes('abcde')
        os.remove(os.path.join(self.infra.dir, 'inventory', 'host_vars', 'f.yml'))
        r = self.play('--limit', 'c')
        self.assertTrue(says(r, 'wireguard: lab.1: f: no public key yet; it joins once it ran'), r.stdout)
        self.play('--limit', 'f')
        self.assertPeers('f', 'lab.1', ['c'])
        self.assertPeers('c', 'lab.1', [])
        self.play()
        self.assertPeers('c', 'lab.1', ['f'])
        self.assertReaches('f', '10.0.1.3')
        self.assertEqual(self.ifindexes('abcde'), before)
        self.assertRoutes('a', 'default', 'b')
        self.assertRoutes('c', 'lab.1', 'f')
        self.assertUnchanged(self.play())

    def test_12_outside_the_play(self):
        # hosts of the inventory outside the play are peers too, by their cached (here: inventory) keys;
        # a name is resolved on the host
        key = self.out('a', 'wg genkey | wg pubkey').strip()
        other = 'plugin: ofzhur.ansible.host\ngroups: [other]\nvars:\n  ansible_host: {}\n' \
                '  ump_private_networks:\n    default: {{address: {}, cidr: 10.0.0.0/24}}\n'.format
        self.infra.write('inventory/hosts/g.yml', other('localhost', '10.0.0.7'))
        self.infra.write('inventory/host_vars/g.yml', f'wireguard_public_keys: {{default: "{key}"}}\n')
        self.infra.write('inventory/hosts/h.yml', other('192.0.2.8', '10.0.0.2'))
        self.infra.write('inventory/hosts/i.yml', other('nonexistent.invalid', '10.0.0.9'))
        self.infra.write('inventory/host_vars/i.yml', f'wireguard_public_keys: {{default: "{key}"}}\n')
        r = self.play()
        self.assertEqual(sorted(recap(r.stdout)), list(HOSTS))
        self.assertEqual(set(self.out('a', 'wg show wg-default peers').split()),
                         {self.public_key(h, 'default') for h in 'bef'} | {key})
        self.assertIn(f'{key}\t127.0.0.1:{PORTS["default"]}\n', self.out('a', 'wg show wg-default endpoints'))
        self.assertTrue(says(r, 'wireguard: default: h: no public key yet; it joins once it ran'))
        self.assertTrue(says(r, 'wireguard: default: h: address 10.0.0.2 is no other host of 10.0.0.0/24'))
        self.assertTrue(says(r, 'wireguard: default: i: ansible_host nonexistent.invalid does not resolve'))
        if FIREWALL:
            self.assertIn('127.0.0.1', self.announced('a', 'default')['rules'][0]['sources'])
            self.assertNotIn('10.0.0.7', self.announced('a', 'default')['interfaces']['wg-default']['accept_from'])
            self.assertIn('10.0.0.7', self.announced('f', 'default')['interfaces']['wg-default']['accept_from'])
        # gone from the inventory, gone from the peers
        for path in ('hosts/g.yml', 'host_vars/g.yml', 'hosts/h.yml', 'hosts/i.yml', 'host_vars/i.yml'):
            os.remove(os.path.join(self.infra.dir, 'inventory', path))
        self.play()
        self.assertPeers('a', 'default', ['b', 'e', 'f'])

    @unittest.skipUnless(FIREWALL, 'without ofzhur.ansible.firewall')
    def test_13_without_the_firewall(self):
        # wireguard_firewall false withdraws the announcements; the peers stay
        self.infra.write('inventory/group_vars/all.yml', ISOLATION + 'wireguard_firewall: false\n')
        self.play()
        for host in HOSTS:
            self.assertEqual(self.sh(host, 'ls /etc/ofzhur/firewall.d/wireguard-*').returncode, 2, host)
            self.assertNotIn(str(PORTS['default']), self.ruleset(host))
        self.assertPeers('a', 'default', ['b', 'e', 'f'])
        self.infra.write('inventory/group_vars/all.yml', ISOLATION)
        self.play()
        self.assertAnnounced('a', 'default', 'be')

    def test_14_by_hand(self):
        # what a person, or a run cut short, left on the interfaces is put right, in place: a's old address
        # primary again beside its new one, a peer widened and another removed on b, wg-lab.1 down on c and
        # wg-default on d, their units still active
        self.add_routes('a', 'default', 'b')
        before = self.ifindexes('ab')
        self.out('a', 'ip address add 10.0.0.1/24 dev wg-default && ip address del 10.0.0.11/24 dev wg-default'
                      ' && ip address add 10.0.0.11/24 dev wg-default')
        self.assertEqual(self.inet('a', 'default'), ['10.0.0.1/24', '10.0.0.11/24'])
        self.out('b', f'wg set wg-default peer {self.public_key("a", "default")} allowed-ips 10.0.0.11/32,192.0.2.0/24'
                      f' && wg set wg-default peer {self.public_key("e", "default")} remove')
        self.out('c', 'wg-quick down wg-lab.1 2>&1')
        self.out('d', 'wg-quick down wg-default 2>&1')
        self.assertEqual(self.out('d', 'systemctl is-active wg-quick@wg-default').strip(), 'active')

        # check mode tells, and changes nothing
        r = self.play('--check')
        self.assertIn('changed: [a]', task(r, 'Addresses of the running interfaces'))
        self.assertIn('changed: [b]', task(r, 'Peers of the running interfaces'))
        self.assertIn('changed: [c]', task(r, 'Interfaces'))
        self.assertIn('changed: [d]', task(r, 'Interfaces'))
        self.assertEqual(self.inet('a', 'default'), ['10.0.0.1/24', '10.0.0.11/24'])
        self.assertPeers('b', 'default', ['a', 'f'])
        self.assertNotEqual(self.sh('d', 'ip link show wg-default').returncode, 0)

        self.play()
        self.assertEqual(self.inet('a', 'default'), ['10.0.0.11/24'])
        self.assertIn(' src 10.0.0.11 ', self.out('a', 'ip -4 route get 10.0.0.2'))
        self.assertEqual(self.ifindexes('ab'), before)
        self.assertRoutes('a', 'default', 'b')
        self.assertReaches('a', '10.0.0.2')
        self.assertPeers('b', 'default', ['a', 'e', 'f'])
        self.assertIn(f'{self.public_key("a", "default")}\t10.0.0.11/32\n',
                      self.out('b', 'wg show wg-default allowed-ips'))
        for host, n in (('c', 'lab.1'), ('d', 'default')):
            self.assertEqual(self.out(host, f'systemctl is-active wg-quick@wg-{n}').strip(), 'active')
            self.assertEqual(self.inet(host, n), [f'{self.networks[host][n]}/24'])
        self.assertReaches('c', '10.0.1.6')
        self.assertReaches('d', '10.0.0.3')
        self.assertUnchanged(self.play())


if __name__ == '__main__':
    unittest.main()
