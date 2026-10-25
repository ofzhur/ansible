# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""Tests of the role ofzhur.ansible.wireguard.

The checks run the ansible CLI found on PATH only. The scenarios also run
Docker. The mesh: six containers with systemd on one Docker network (a, c
and e on Debian 13, b, d and f on Ubuntu 24.04), each reached over SSH as
the user ump through `docker exec` and nc, so that ansible_host is the
container's address on the network, the endpoint its peers reach, as a
server's public address is. The tunnel: a gateway (Debian 13) and two
hosts tunneled through it (Ubuntu 24.04, Debian 13), with a public /32
each, routed by a fourth container, the internet, which holds addresses
elsewhere that tell the source they see, and through which SSH comes to
the public addresses. Without Docker they are skipped.

    python3 tests/test_wireguard.py

With the role ofzhur.ansible.firewall in the collection the scenarios run
it too and check the ports it opens and the connections it lets in;
without, wireguard_firewall is false and the peers connect both ways.
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

# Hosts outside the play, gateways for the checks of a tunnel: gw in both
# networks of web-01, gw2 in default, gw3 in another one, gw4 tunneled.
OTHER = """\
plugin: ofzhur.ansible.host
groups: [other]
vars:
  ansible_host: {address}
  ump_private_networks: {networks}
"""
GATEWAYS = {
    'inventory/hosts/gw.yml': OTHER.format(address='192.0.2.2', networks='{default: {address: 10.0.0.2, cidr: 10.0.0.0/24},'
                                                                         ' lab: {address: 10.0.1.2, cidr: 10.0.1.0/24}}'),
    'inventory/hosts/gw2.yml': OTHER.format(address='192.0.2.3', networks='{default: {address: 10.0.0.3, cidr: 10.0.0.0/24}}'),
    'inventory/hosts/gw3.yml': OTHER.format(address='192.0.2.4', networks='{far: {address: 10.9.9.4, cidr: 10.9.9.0/24}}'),
    'inventory/hosts/gw4.yml': OTHER.format(address='192.0.2.5', networks='{default: {address: 10.0.0.5, cidr: 10.0.0.0/24}}'),
    'inventory/host_vars/gw4.yml': 'wireguard_tunnel: gw2\n',
}


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
        self.assertIn('wireguard_tunnel_direct', r.stdout)

    def test_valid(self):
        # every check passes; the first module fails, with no interpreter on this host
        r = self.run_role({'inventory/host_vars/web-01.yml': 'wireguard_groups: {lab: [db]}\nwireguard_ports: {lab: 51820}\n',
                           'inventory/group_vars/all.yml': 'wireguard_isolation: [common]\n'})
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn('TASK [ofzhur.ansible.wireguard : Look for /etc/wireguard]', r.stdout)
        self.assertEqual(recap(r.stdout)['web-01']['ok'], 8)
        # with a tunnel, its gateway named either way
        for tunnel in ('gw2', '{host: gw, network: lab}'):
            with self.subTest(tunnel):
                r = self.run_role({**GATEWAYS, 'inventory/host_vars/web-01.yml':
                                   f'wireguard_tunnel: {tunnel}\nwireguard_tunnel_direct: [192.0.2.0/24, 198.51.100.7/32]\n'
                                   'wireguard_tunnel_mark: 0x80000000\nwireguard_tunnel_table: 100\nwireguard_tunnel_priority: 1\n'})
                self.assertIn('TASK [ofzhur.ansible.wireguard : Look for /etc/wireguard]', r.stdout)
                self.assertEqual(recap(r.stdout)['web-01']['ok'], 8)

    def test_wrong_type(self):
        cases = {
            'networks': 'wireguard_networks: [default]\n',
            'ports': 'wireguard_ports: [51820]\n',
            'firewall': 'wireguard_firewall: maybe\n',
            'isolation': 'wireguard_isolation: {foo: 1}\n',
            'tunnel_direct': 'wireguard_tunnel_direct: {a: 1}\n',
            'tunnel_mark': 'wireguard_tunnel_mark: many\n',
            'tunnel_table': 'wireguard_tunnel_table: [1]\n',
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

    def test_invalid_tunnel(self):
        cases = {
            'unknown': ('wireguard_tunnel: nohost\n', 'wireguard_tunnel: nohost is no host of the inventory'),
            'self': ('wireguard_tunnel: web-01\n', 'wireguard_tunnel: a host is no gateway of its own'),
            'list': ('wireguard_tunnel: [gw2]\n', 'wireguard_tunnel: it is no host name, nor a mapping {host: NAME, network: NAME}'),
            'key': ('wireguard_tunnel: {host: gw2, net: default}\n', 'wireguard_tunnel: it is no host name, nor a mapping'),
            'two networks': ('wireguard_tunnel: gw\n',
                             'wireguard_tunnel: web-01 and gw share the networks default, lab; set {host: gw, network: NAME}'),
            'not the gateway\'s': ('wireguard_tunnel: {host: gw2, network: lab}\n', 'wireguard_tunnel: gw2 is in no network lab'),
            'not the host\'s': ('wireguard_tunnel: {host: gw3, network: far}\n', 'wireguard_tunnel: web-01 is in no network far'),
            'none shared': ('wireguard_tunnel: gw3\n', 'wireguard_tunnel: web-01 and gw3 share no network'),
            'chain': ('wireguard_tunnel: gw4\n', 'wireguard_tunnel: gw4 has a tunnel of its own; a gateway has none'),
            'direct host': ('wireguard_tunnel_direct: [10.0.0.1/8]\n',
                            'wireguard_tunnel_direct: 10.0.0.1/8 is no IPv4 network of /1 to /32'),
            'direct all': ('wireguard_tunnel_direct: [0.0.0.0/0]\n', 'wireguard_tunnel_direct: 0.0.0.0/0 is no IPv4 network'),
            'direct IPv6': ('wireguard_tunnel_direct: [fd00::/8]\n', 'wireguard_tunnel_direct: fd00::/8 is no IPv4 network'),
            'direct address': ('wireguard_tunnel_direct: [192.0.2.1]\n', 'wireguard_tunnel_direct: 192.0.2.1 is no IPv4 network'),
            'mark': ('wireguard_tunnel_mark: 3\n', 'wireguard_tunnel_mark: 3 is no single bit'),
            'no mark': ('wireguard_tunnel_mark: 0\n', 'wireguard_tunnel_mark: 0 is no single bit'),
            'table main': ('wireguard_tunnel_table: 254\n', 'wireguard_tunnel_table: 254 is no table of its own'),
            'table 0': ('wireguard_tunnel_table: 0\n', 'wireguard_tunnel_table: 0 is no table of its own'),
            'priority': ('wireguard_tunnel_priority: 32763\n', 'wireguard_tunnel_priority: 32763 is not 1 to 32762'),
        }
        for name, (host_vars, message) in cases.items():
            with self.subTest(name):
                self.assertRefused({**GATEWAYS, 'inventory/host_vars/web-01.yml': host_vars}, message, ok=6)
        # a gateway isolated from the host, its groups sharing none of the host's
        self.assertRefused({**GATEWAYS, 'inventory/host_vars/web-01.yml': 'wireguard_tunnel: gw2\nwireguard_groups: [foo]\n',
                            'inventory/host_vars/gw2.yml': 'wireguard_groups: [bar]\n'},
                           'wireguard_tunnel: web-01 and gw2 are isolated in default (groups foo; bar): no tunnel between them',
                           ok=6)

    def test_outside_the_inventory(self):
        # the other hosts would not see a role parameter or a play variable
        playbooks = {
            'parameter': PLAYBOOK.replace('- ofzhur.ansible.wireguard',
                                          '- role: ofzhur.ansible.wireguard\n      wireguard_groups: [db]'),
            'play': PLAYBOOK.replace('  roles:', '  vars:\n    wireguard_ports: {default: 51820}\n  roles:'),
            'isolation': PLAYBOOK.replace('  roles:', '  vars:\n    wireguard_isolation: [common]\n  roles:'),
            'tunnel': PLAYBOOK.replace('  roles:', '  vars:\n    wireguard_tunnel: gw2\n  roles:'),
        }
        for name, playbook in playbooks.items():
            with self.subTest(name):
                r = self.run_role({**GATEWAYS, 'playbooks/wireguard.yml': playbook})
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


# --- Docker: a tunnel ---------------------------------------------------------

# test_wireguard's image with the packages of a tunnel (and iptables, for
# Docker's chain, conntrack, to flush it), and the user of systemd-resolved:
# the servers here have no way out to install them.
DOCKERFILE_TUNNEL = """\
FROM {image}
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \\
      wireguard-tools nftables iptables conntrack \\
 && rm -rf /var/lib/apt/lists/* \\
 && {{ id systemd-resolve >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin systemd-resolve; }}
"""

# The gateway g, c and x tunneled through it (c in foo, x in bar: isolated
# from each other, not from g; g and x in lab too), and i, the internet: the
# router of their public addresses, each a /32 as with some providers, and
# the holder of addresses elsewhere, which tell the source they see.
TUNNEL_HOSTS = {'g': 'debian', 'c': 'ubuntu', 'x': 'debian'}
SUBNET, SUBNET6 = '10.231.0.0/24', 'fd7a:231::/64'
PUBLIC = {'g': '10.231.0.11', 'c': '10.231.0.12', 'x': '10.231.0.13', 'i': '10.231.0.100'}
PUBLIC6 = {'g': 'fd7a:231::11', 'c': 'fd7a:231::12', 'x': 'fd7a:231::13', 'i': 'fd7a:231::100'}
MESH = {'g': '10.0.0.1', 'c': '10.0.0.2', 'x': '10.0.0.3'}
LAB = {'g': '10.0.1.1', 'x': '10.0.1.3'}
GROUPS = {'g': [], 'c': ['foo'], 'x': ['bar']}
INTERNET, INTERNET6 = '203.0.113.1', 'fd7a:232::1'
DIRECT = '192.0.2.5'
METADATA = '169.254.169.254'
# The provider's MTU, which its network sets at boot, after Docker's 1500: a
# WireGuard interface gets 80 less.
MTU = 1450

# ump's runs come from the internet to the public address, as they do to a server.
TUNNEL_HOST = """\
plugin: ofzhur.ansible.host
groups: {groups}
vars:
  ansible_host: {address}
  ump_admin: ump
  ump_private_networks: {networks}
  ansible_ssh_private_key_file: {dir}/ump
  ansible_ssh_common_args: >-
    -o UserKnownHostsFile={dir}/known_hosts -o IdentitiesOnly=yes
    -o ProxyCommand="{docker} exec -i {internet} nc -s {source} {address} 22"
"""

TUNNELS = {
    'c': f'wireguard_tunnel: g\nwireguard_tunnel_direct: [{DIRECT}/32]\n',
    'x': 'wireguard_tunnel: {host: g, network: default}\n',
}

# The provider's network of a server, at every boot after network-pre.target
# and before network.target, as a network manager brings it up: its MTU, the
# public address a /32, the internet behind i, IPv4 and IPv6, and behind that
# an IPv6 default unreachable (dev lo, no uplink); on g, a private network
# too, lan0, without a default route.
NETWORK = """\
#!/bin/sh
ip link set eth0 mtu {mtu}
ip address replace {address}/32 dev eth0
ip address del {address}/24 dev eth0 2>/dev/null
ip route replace {router} dev eth0 scope link
ip route replace default via {router} dev eth0
ip -6 route replace default via {router6} dev eth0
ip -6 route replace unreachable default metric 4000000
{lan}true
"""
LAN0 = """\
ip link add lan0 type dummy 2>/dev/null
ip address replace 10.97.0.1/24 dev lan0
ip link set lan0 up
"""
NETWORK_UNIT = """\
[Unit]
Description=The provider's network
DefaultDependencies=no
After=network-pre.target
Before=network.target
Wants=network.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh /usr/local/sbin/test-network

[Install]
WantedBy=multi-user.target
"""

# A TCP server that answers, and writes down, the source address it sees.
WHOAMI = """\
import socket, socketserver, sys
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        with open('/tmp/seen', 'a') as f:
            f.write(self.client_address[0] + '\\n')
        self.request.sendall((self.client_address[0] + '\\n').encode())
class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    address_family = socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
Server((sys.argv[1], int(sys.argv[2])), Handler).serve_forever()
"""

# A resolver, as far as the tunnel is concerned: it answers the source address it sees.
RESOLVER = """\
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((sys.argv[1], int(sys.argv[2])))
while True:
    data, address = s.recvfrom(512)
    s.sendto((address[0] + '\\n').encode(), address)
"""

# A question to it, as systemd-resolved asks the resolvers of a link: from a
# socket bound to the link (IP_UNICAST_IF, the index in network byte order).
ASK = """\
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
if len(sys.argv) > 3:
    s.setsockopt(socket.IPPROTO_IP, 50, socket.if_nametoindex(sys.argv[3]).to_bytes(4, 'big'))
s.settimeout(3)
try:
    s.sendto(b'?', (sys.argv[1], int(sys.argv[2])))
    print(s.recv(64).decode().strip())
except OSError:
    pass
"""

# Docker's way on c: a container's network namespace, port 8080 of c's
# address DNAT to it, and its own connections masqueraded.
APP = """\
ip netns add app
ip link add vapp type veth peer name veth0 netns app
ip address add 10.99.0.1/24 dev vapp
ip link set vapp up
ip -n app address add 10.99.0.2/24 dev veth0
ip -n app link set veth0 up
ip -n app link set lo up
ip -n app route add default via 10.99.0.1
nft -f - <<EOF
table ip app {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr {address} tcp dport 8080 dnat to 10.99.0.2:80
	}
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 10.99.0.0/24 oifname != "vapp" masquerade
	}
}
EOF
"""

# c's networks beside the internet: lan, a host behind another interface
# (a route of main but its default), and a bridge with two containers on
# it, which br_netfilter shows to the IPv4 and IPv6 hooks.
LOCAL_NETWORKS = """\
ip netns add lan
ip link add vlan type veth peer name eth0 netns lan
ip address add 10.98.0.1/24 dev vlan
ip link set vlan up
ip -n lan address add 10.98.0.2/24 dev eth0
ip -n lan link set eth0 up
ip -n lan link set lo up
ip -n lan route add default via 10.98.0.1
ip link add br-test type bridge
ip link set br-test up
for n in 2 3; do
  ip netns add b$n
  ip link add vb$n type veth peer name eth0 netns b$n
  ip link set vb$n master br-test up
  ip -n b$n address add 10.88.0.$n/24 dev eth0
  ip -n b$n address add fd88::$n/64 dev eth0 nodad
  ip -n b$n link set eth0 up
  ip -n b$n link set lo up
done
echo 1 > /proc/sys/net/bridge/bridge-nf-call-iptables
echo 1 > /proc/sys/net/bridge/bridge-nf-call-ip6tables
"""
LOCAL_NETWORKS_GONE = """\
for n in lan b2 b3; do ip netns pids $n | xargs -r kill; ip netns del $n; done
ip link del br-test
"""

# A port of c's container published on an address that came after the run.
PUBLISHED = """\
ip address add 10.231.0.22/32 dev eth0
nft -f - <<EOF
table ip app2 {
	chain prerouting {
		type nat hook prerouting priority dstnat; policy accept;
		ip daddr 10.231.0.22 tcp dport 8080 dnat to 10.99.0.2:80
	}
}
EOF
"""

# Docker on g, as it sets itself up: FORWARD drops what it does not let
# through, DOCKER-USER first (with a rule of the owner's), its bridge
# docker0 with a container, nothing published, its connections out
# masqueraded.
DOCKER = """\
ip netns add ctr
ip link add docker0 type bridge
ip address add 172.18.0.1/24 dev docker0
ip link set docker0 up
echo 1 > /proc/sys/net/ipv4/conf/docker0/forwarding
ip link add vctr type veth peer name eth0 netns ctr
ip link set vctr master docker0 up
ip -n ctr address add 172.18.0.2/24 dev eth0
ip -n ctr link set eth0 up
ip -n ctr link set lo up
ip -n ctr route add default via 172.18.0.1
iptables -w -P FORWARD DROP
iptables -w -N DOCKER-USER
iptables -w -A DOCKER-USER -s 192.0.2.99/32 -j DROP
iptables -w -A DOCKER-USER -j RETURN
iptables -w -A FORWARD -j DOCKER-USER
iptables -w -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -w -A FORWARD -i docker0 ! -o docker0 -j ACCEPT
iptables -w -t nat -A POSTROUTING -s 172.18.0.0/24 ! -o docker0 -j MASQUERADE
"""
OWNER = '-A DOCKER-USER -s 192.0.2.99/32 -j DROP'

# Packets in through the tunnel from others than the gateway, by source:
# from the internet, and from the other client, sent through the gateway.
COUNTER = """\
table inet ofzhur-test
delete table inet ofzhur-test
table inet ofzhur-test {{
	chain prerouting {{
		type filter hook prerouting priority -400; policy accept;
		iifname "wg-default" ip saddr {internet} counter comment "internet"
		iifname "wg-default" ip saddr {mesh} counter comment "mesh"
	}}
}}
"""


class Tunnel(unittest.TestCase):
    """A gateway and two hosts tunneled through it, on the internet; the role run on them as ump runs it, step by step."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        if not have_docker():
            raise unittest.SkipTest('Docker is not available')
        for os_, base in BASES.items():
            docker('build', '-q', '-t', f'ofzhur-test-wireguard:{os_}', '-', input=DOCKERFILE.format(base=base))
            docker('build', '-q', '-t', f'ofzhur-test-tunnel:{os_}', '-',
                   input=DOCKERFILE_TUNNEL.format(image=f'ofzhur-test-wireguard:{os_}'))

        cls.net = 'ofzhur-test-tunnel'
        cls.names = {h: f'ofzhur-test-tunnel-{h}' for h in [*TUNNEL_HOSTS, 'i']}
        for name in cls.names.values():
            docker('rm', '-f', name, check=False)
        docker('network', 'rm', cls.net, check=False)
        docker('network', 'create', '--ipv6', '--subnet', SUBNET, '--subnet', SUBNET6, cls.net)
        cls.addClassCleanup(docker, 'network', 'rm', cls.net, check=False)

        cls.infra = Infra({'playbooks/wireguard.yml': PLAYBOOK_FIREWALL if FIREWALL else PLAYBOOK,
                           'inventory/group_vars/all.yml': ISOLATION + ('' if FIREWALL else 'wireguard_firewall: false\n')})
        cls.addClassCleanup(cls.infra.close)
        d = cls.infra.dir
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'ump@test', '-f', f'{d}/ump'], check=True)
        with open(f'{d}/ump.pub') as f:
            key = f.read().strip()

        # the internet: it forwards between the servers, never redirecting them to each other
        i = cls.names['i']
        cls.addClassCleanup(docker, 'rm', '-f', i, check=False)
        docker('run', '-d', '--name', i, '--hostname', 'i', '--network', cls.net, '--ip', PUBLIC['i'], '--ip6', PUBLIC6['i'],
               '--privileged', '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0', '--sysctl', 'net.ipv4.ip_forward=1',
               '--sysctl', 'net.ipv6.conf.all.forwarding=1', 'ofzhur-test-tunnel:debian', 'sleep', 'infinity')
        docker('exec', '-i', i, 'sh', '-c', 'cat > /tmp/whoami.py', input=WHOAMI)
        docker('exec', '-i', i, 'sh', '-c', 'cat > /tmp/resolver.py', input=RESOLVER)
        docker('exec', i, 'sh', '-c',
               f'for a in {INTERNET} {DIRECT} {METADATA}; do ip address add $a/32 dev lo; done'
               f' && ip address add {INTERNET6}/128 dev lo'
               f' && ip link set eth0 mtu {MTU}'
               ' && for f in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $f; done && touch /tmp/seen')
        for address in (INTERNET, DIRECT, METADATA, PUBLIC6['i'], INTERNET6):
            docker('exec', '-d', i, 'python3', '/tmp/whoami.py', address, '8080')
        docker('exec', '-d', i, 'python3', '/tmp/resolver.py', INTERNET, '53')

        for host, os_ in TUNNEL_HOSTS.items():
            name = cls.names[host]
            cls.addClassCleanup(docker, 'rm', '-f', name, check=False)
            # g forwards nothing until the role has it forward; c forwards for its container, as Docker has it
            docker('run', '-d', '--name', name, '--hostname', host, '--network', cls.net,
                   '--ip', PUBLIC[host], '--ip6', PUBLIC6[host], '--privileged', '--tmpfs', '/run', '--tmpfs', '/run/lock',
                   '--sysctl', 'net.ipv6.conf.all.disable_ipv6=0',
                   '--sysctl', f'net.ipv4.ip_forward={0 if host == "g" else 1}', f'ofzhur-test-tunnel:{os_}')
            docker('exec', '-i', name, 'sh', '-c',
                   'install -d -m 700 -o ump -g ump /home/ump/.ssh'
                   ' && cat > /home/ump/.ssh/authorized_keys'
                   ' && chown ump:ump /home/ump/.ssh/authorized_keys'
                   ' && chmod 600 /home/ump/.ssh/authorized_keys',
                   input=key + '\n')
            docker('exec', '-i', name, 'sh', '-c', 'cat > /usr/local/bin/whoami.py', input=WHOAMI)
            docker('exec', '-i', name, 'sh', '-c', 'cat > /usr/local/bin/ask.py', input=ASK)
            docker('exec', '-i', name, 'sh', '-c', 'cat > /usr/local/sbin/test-network',
                   input=NETWORK.format(mtu=MTU, address=PUBLIC[host], router=PUBLIC['i'], router6=PUBLIC6['i'],
                                        lan=LAN0 if host == 'g' else ''))
            docker('exec', '-i', name, 'sh', '-c', 'cat > /etc/systemd/system/test-network.service'
                   ' && ln -s /etc/systemd/system/test-network.service /etc/systemd/system/multi-user.target.wants/'
                   ' && sh /usr/local/sbin/test-network', input=NETWORK_UNIT)
            networks = {'default': (MESH[host], '10.0.0.0/24'), **({'lab': (LAB[host], '10.0.1.0/24')} if host in LAB else {})}
            cls.infra.write(f'inventory/hosts/{host}.yml', TUNNEL_HOST.format(
                groups=json.dumps(['common'] + GROUPS[host]), address=PUBLIC[host], dir=d,
                networks='{' + ', '.join(f'{n}: {{address: {a}, cidr: {c}}}' for n, (a, c) in networks.items()) + '}',
                docker=shutil.which('docker'), internet=i, source=INTERNET))
        cls.boot()

    @classmethod
    def boot(cls):
        """What Docker sets up anew at every start, c's container; then SSH to all."""
        docker('exec', '-i', cls.names['c'], 'sh', '-c', APP.replace('{address}', PUBLIC['c']))
        docker('exec', '-d', cls.names['c'], 'ip', 'netns', 'exec', 'app', 'python3', '/usr/local/bin/whoami.py', '0.0.0.0', '80')
        for _ in range(60):
            r = cls.infra.run('ansible', 'all', '-m', 'ansible.builtin.ping', *AS_UMP)
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            raise AssertionError(f'the containers are not reachable over SSH:\n{r.stdout}{r.stderr}')

    def tunnels(self, on=True):
        for host, host_vars in TUNNELS.items():
            path = os.path.join(self.infra.dir, 'inventory', 'host_vars', f'{host}.yml')
            if on:
                self.infra.write(f'inventory/host_vars/{host}.yml', host_vars)
            elif os.path.exists(path):
                os.remove(path)

    def play(self, *args, hosts=TUNNEL_HOSTS):
        r = self.infra.run('ansible-playbook', 'playbooks/wireguard.yml', *AS_UMP, *args)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(sorted(recap(r.stdout)), sorted(hosts))
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

    def source(self, host, address=INTERNET, port=8080, netns=None):
        """The source address that a new TCP connection from host shows at address, or '' when none gets there."""
        command = f'nc -w 3 {address} {port} </dev/null'
        return self.sh(host, f'ip netns exec {netns} {command}' if netns else command).stdout.strip()

    def assertSource(self, host, expected, address=INTERNET, port=8080, netns=None):
        for _ in range(10):
            seen = self.source(host, address, port, netns)
            if seen == expected:
                break
            time.sleep(1)
        self.assertEqual(seen, expected, f'{host} to {address}')

    def seen(self):
        return self.out('i', 'cat /tmp/seen').split()

    def assertClosed(self, host, netns=None):
        """Nothing new from host gets to the internet, IPv4 or IPv6, on the link or beyond, from its own address least of all."""
        before = len(self.seen())
        for address in (INTERNET, PUBLIC6['i'], INTERNET6):
            self.assertEqual(self.source(host, address, netns=netns), '', f'{host} to {address}')
        self.assertEqual(self.seen()[before:], [])

    def answers(self, host, port=22, family=4, source=None, address=None):
        """What the first bytes from port of host are, connected to from the internet."""
        address = address or (PUBLIC[host] if family == 4 else PUBLIC6[host])
        source = source or (INTERNET if family == 4 else PUBLIC6['i'])
        r = self.sh('i', f'python3 -c \'import socket; s = socket.create_connection(("{address}", {port}), 3,'
                         f' ("{source}", 0)); print(s.recv(64).decode())\'')
        return r.stdout.strip()

    def assertIncoming(self, host='c'):
        """SSH from the internet to host's address, IPv4 and IPv6, and to c's container behind DNAT, answered directly."""
        self.assertTrue(self.answers(host).startswith('SSH-2.0-'), host)
        for source in (PUBLIC6['i'], INTERNET6):
            self.assertTrue(self.answers(host, family=6, source=source).startswith('SSH-2.0-'), f'{host} from {source}')
        if host == 'c':
            self.assertEqual(self.answers('c', 8080), INTERNET)

    def counted(self, host, source):
        line = [l for l in self.out(host, 'nft list chain inet ofzhur-test prerouting').splitlines() if f'"{source}"' in l][0]
        return int(line.split('packets ')[1].split()[0])

    def count(self):
        """Counters on c and x of what comes in through the tunnel from the internet, and from the other client."""
        for host, other in (('c', 'x'), ('x', 'c')):
            docker('exec', '-i', self.names[host], 'nft', '-f', '-',
                   input=COUNTER.format(internet=PUBLIC['i'], mesh=MESH[other]))

    def allowed(self, host):
        """The AllowedIPs of g on host's interface."""
        key = self.out('g', 'wg show wg-default public-key').strip()
        line = [l for l in self.out(host, 'wg show wg-default allowed-ips').splitlines() if l.startswith(key)]
        return set(line[0].split()[1:])

    def rules(self, host):
        """The tunnel's rules, IPv4 and IPv6 (those of its protocol): the family, the priority, the rule."""
        rules = []
        for f in ('-4', '-6'):
            for r in self.out(host, f'ip {f} rule show').splitlines():
                if ' proto 111' in r:
                    priority, rule = r.split(':', 1)
                    rules.append(f'{f} {priority} {" ".join(rule.split())}')
        return sorted(rules)

    def table(self, host, table=32000):
        """The routes of the tunnel's table, IPv4 and IPv6."""
        return [r.split() for f in ('-4', '-6') for r in self.out(host, f'ip {f} route show table {table} 2>/dev/null; true').splitlines()]

    def dropins(self, host):
        """The interfaces whose unit runs tunnel.sh before and once it comes up (the role's drop-in), as systemd read it."""
        run = 'argv[]=/bin/sh /etc/wireguard/tunnel.sh up ; ignore_errors=yes ;'
        found = set()
        for d in self.out(host, 'cd /etc/systemd/system && ls -d wg-quick@*.service.d 2>/dev/null; true').split():
            unit = d[:-len('.d')]
            show = self.out(host, f'systemctl show -p ExecStartPre -p ExecStartPost -p NeedDaemonReload -p DropInPaths {unit}')
            self.assertIn(f'ExecStartPre={{ path=/bin/sh ; {run}', show, f'{host}: {unit}')
            self.assertIn(f'ExecStartPost={{ path=/bin/sh ; {run}', show, f'{host}: {unit}')
            self.assertIn('NeedDaemonReload=no\n', show, f'{host}: {unit}')
            self.assertIn(f'/etc/systemd/system/{d}/ofzhur-wireguard.conf', show, f'{host}: {unit}')
            found.add(unit[len('wg-quick@'):-len('.service')])
        return found

    def mtu(self, host, interface):
        return int(self.out(host, f'cat /sys/class/net/{interface}/mtu'))

    def forwarding(self, uplink='eth0'):
        """g's forwarding: all, its uplink, its interfaces, its private network."""
        names = ['all', uplink, 'wg-default', 'wg-lab', 'lan0']
        return dict(zip(names, self.out('g', 'cd /proc/sys/net/ipv4 && cat ip_forward'
                                             + ''.join(f' conf/{n}/forwarding' for n in names[1:])).split()))

    def index(self, interface):
        return self.out('g', f'cat /sys/class/net/{interface}/ifindex').strip()

    def recorded(self):
        """The interfaces whose forwarding g's tunnel.sh turned on, as it wrote them down: index, name."""
        return dict(l.split()[:2] for l in self.out('g', 'cat /run/ofzhur-wireguard/forwarding 2>/dev/null; true').splitlines())

    def rename(self, old, new):
        """g's uplink renamed, as udev renames one: down, renamed, up, its addresses and routes as before."""
        docker('exec', self.names['g'], 'sh', '-c',
               f'echo 1 > /proc/sys/net/ipv6/conf/{old}/keep_addr_on_down'
               f' && ip link set {old} down && ip link set {old} name {new} && ip link set {new} up'
               f' && sed s/eth0/{new}/g /usr/local/sbin/test-network | sh')
        self.assertIn(f'default via {PUBLIC["i"]} dev {new} ', self.out('g', 'ip -4 route show default'))

    def assertTunnel(self, priority=32000, table=32000):
        """The tunnel's state on c and x, and g's as their gateway."""
        p = priority
        for host in TUNNELS:
            self.assertEqual(self.rules(host), sorted([
                f'-4 {p} from all to 169.254.0.0/16 lookup main proto 111',
                *([f'-4 {p} from all to {DIRECT} lookup main proto 111'] if host == 'c' else []),
                f'-4 {p} from all ipproto tcp sport 22 lookup main proto 111',
                f'-4 {p + 1} from all lookup main suppress_prefixlength 0 proto 111',
                f'-4 {p + 2} from all fwmark 0x2000/0x2000 lookup main proto 111',
                f'-4 {p + 3} from all lookup {table} proto 111',
                f'-6 {p} from all ipproto tcp sport 22 lookup main proto 111',
                f'-6 {p + 1} from all lookup main suppress_prefixlength 0 proto 111',
                f'-6 {p + 2} from all fwmark 0x2000/0x2000 lookup main proto 111',
                f'-6 {p + 3} from all lookup {table} proto 111']), host)
            self.assertEqual(self.table(host, table), [
                f'default dev wg-default scope link src {MESH[host]}'.split(),
                'default dev ofzhur-closed scope link metric 4294967295'.split(),
                'default dev ofzhur-closed metric 4294967295 pref medium'.split()], host)
            self.assertEqual(self.out(host, 'wg show wg-default fwmark').strip(), '0x2000', host)
            self.assertEqual(self.allowed(host), {'0.0.0.0/0', '10.0.0.1/32'}, host)
            self.assertEqual(self.out(host, 'sysctl -n net.ipv4.conf.all.src_valid_mark').strip(), '1')
            self.assertEqual(self.out(host, 'systemctl is-enabled ofzhur-wireguard-tunnel; systemctl is-active'
                                            ' ofzhur-wireguard-tunnel'), 'enabled\nactive\n', host)
            self.assertIn('table inet ofzhur-wireguard\n', self.out(host, 'nft list tables'))
            # its uplink eth0 alone, not lo of the unreachable default
            self.assertIn('elements = { "eth0" }', self.out(host, 'nft list set inet ofzhur-wireguard uplinks'), host)
            # the unit of the tunnel's interface runs tunnel.sh, not wg-quick; ofzhur-closed has the uplink's MTU
            self.assertEqual(self.dropins(host), {'wg-default'}, host)
            self.assertEqual(self.mtu(host, 'ofzhur-closed'), MTU, host)
        for host in TUNNEL_HOSTS:
            self.assertNotIn('PostUp', self.out(host, 'cat /etc/wireguard/wg-*.conf'), host)
        # g forwards on its interfaces that serve and its uplink alone, net.ipv4.ip_forward still off, and wrote them
        # down by index; its clients go out masqueraded; nothing from wg-default to the networks of g, also by its
        # rules
        self.assertEqual(self.forwarding(), {'all': '0', 'eth0': '1', 'wg-default': '1', 'wg-lab': '0', 'lan0': '0'})
        self.assertEqual(self.recorded(), {self.index(n): n for n in ('eth0', 'wg-default')})
        self.assertEqual(self.out('g', 'wg show wg-default fwmark').strip(), 'off')
        table = self.out('g', 'nft list table inet ofzhur-wireguard')
        self.assertIn(f'iifname "wg-default" oifname != "wg-*" ip saddr {{ {MESH["c"]}, {MESH["x"]} }} masquerade', table)
        self.assertEqual(self.out('g', 'systemctl is-active ofzhur-wireguard-tunnel').strip(), 'active')
        self.assertEqual(self.dropins('g'), {'wg-default'})
        self.assertEqual(self.rules('g'), [f'-4 {p} from all to 10.0.0.0/24 iif wg-default prohibit proto 111',
                                           f'-4 {p} from all to 10.0.1.0/24 iif wg-default prohibit proto 111'])

    def assertWorks(self):
        """What the tunnel carries, what stays direct, what comes in."""
        for host in TUNNELS:
            self.assertSource(host, PUBLIC['g'])
            self.assertSource(host, PUBLIC[host], METADATA)
            # IPv6: nothing new out, on the link or beyond
            self.assertEqual(self.source(host, PUBLIC6['i']), '')
            self.assertEqual(self.source(host, INTERNET6), '')
            self.assertIncoming(host)
        self.assertSource('c', PUBLIC['c'], DIRECT)
        self.assertSource('x', PUBLIC['g'], DIRECT)
        # c's container: out through the tunnel, in directly
        self.assertSource('c', PUBLIC['g'], netns='app')
        # WireGuard's own packets direct: the handshake with g is recent
        self.assertLess(time.time() - int(self.out('c', 'wg show wg-default latest-handshakes').split()[1]), 180)

    def test_01_check(self):
        # check mode changes nothing
        self.tunnels()
        r = self.play('--check')
        for host in TUNNEL_HOSTS:
            self.assertNotIn('ofzhur-wireguard', self.out(host, 'nft list tables'), host)
            self.assertEqual(self.rules(host), [], host)
            self.assertNotEqual(self.sh(host, 'ls /etc/wireguard/tunnel.sh').returncode, 0, host)
        self.assertIn('changed: [c]', task(r, 'Tunnel'))

    def test_02_tunnel(self):
        # direct before
        self.assertSource('c', PUBLIC['c'])
        self.assertSource('c', PUBLIC['c'], netns='app')
        self.tunnels()
        self.play()
        self.assertTunnel()
        self.assertWorks()
        # systemd-networkd keeps the tunnel's rules; Docker, once there, lets g's clients through
        for host in TUNNELS:
            self.assertIn('\nManageForeignRoutingPolicyRules=no\n',
                          self.out(host, 'cat /etc/systemd/networkd.conf.d/ofzhur-wireguard.conf'))
        self.assertIn('\nExecStartPost=-/bin/sh /etc/wireguard/tunnel.sh up\n',
                      self.out('g', 'cat /etc/systemd/system/docker.service.d/ofzhur-wireguard.conf'))
        self.assertUnchanged(self.play())
        self.assertUnchanged(self.play('--check'))

    def test_03_isolation(self):
        # through g, nothing from c reaches x, nothing from the internet the mesh: g's table and its rules each hold
        # the one, its table alone the other
        self.count()
        self.out('i', f'ip route replace 10.0.0.0/24 via {PUBLIC["g"]}')
        self.addCleanup(self.sh, 'i', 'ip route del 10.0.0.0/24')

        def send():
            self.sh('c', f'ping -c 3 -i 0.2 -W 1 {MESH["x"]}')
            self.sh('x', f'ping -c 3 -i 0.2 -W 1 {MESH["c"]}')
            self.sh('i', f'ping -c 3 -i 0.2 -W 1 {MESH["c"]}; ping -c 3 -i 0.2 -W 1 {MESH["x"]}')

        def counted():
            return {(h, s): self.counted(h, s) for h in TUNNELS for s in ('internet', 'mesh')}

        send()
        self.assertEqual(set(counted().values()), {0})
        self.out('g', 'nft delete table inet ofzhur-wireguard')
        send()
        n = counted()
        self.assertGreater(n['c', 'internet'], 0)
        self.assertGreater(n['x', 'internet'], 0)
        self.assertEqual((n['c', 'mesh'], n['x', 'mesh']), (0, 0))
        for r in self.rules('g'):
            f, priority, rule = r.split(' ', 2)
            self.out('g', f'ip {f} rule del priority {priority} {rule}')
        send()
        n = counted()
        self.assertGreater(n['c', 'mesh'], 0)
        self.assertGreater(n['x', 'mesh'], 0)
        # the next run puts both back
        r = self.play()
        self.assertIn('changed: [g]', task(r, 'Tunnel'))
        self.assertTunnel()
        self.count()
        send()
        self.assertEqual(set(counted().values()), {0})
        self.assertWorks()

    def test_04_gateway_down(self):
        # g's interface down: nothing of c's goes out, directly least of all; SSH and c's container still answer
        self.out('g', 'ip link set wg-default down')
        try:
            self.assertClosed('c')
            self.assertClosed('c', netns='app')
            self.assertIncoming()
            self.assertSource('c', PUBLIC['c'], DIRECT)
        finally:
            self.out('g', 'ip link set wg-default up')
        self.assertSource('c', PUBLIC['g'])

    def test_05_local(self):
        # c's other networks stay direct, its container's too; a bridge's containers reach each other (br_netfilter
        # on), the tunnel up or down
        self.out('c', LOCAL_NETWORKS)
        self.addCleanup(self.sh, 'c', LOCAL_NETWORKS_GONE)
        for host, address in (('lan', '0.0.0.0'), ('b3', '0.0.0.0'), ('b3', 'fd88::3')):
            docker('exec', '-d', self.names['c'], 'ip', 'netns', 'exec', host, 'python3', '/usr/local/bin/whoami.py',
                   address, '80' if host == 'lan' else '8080')
        self.assertSource('c', '10.98.0.1', '10.98.0.2', 80, netns='app')
        # SSH from lan first, then the host to lan: the route there does not change
        self.assertTrue(self.out('c', 'ip netns exec lan nc -w 3 10.98.0.1 22 </dev/null').startswith('SSH-2.0-'))
        for _ in range(2):
            self.assertSource('c', '10.98.0.1', '10.98.0.2', 80)
        for down in (False, True):
            if down:
                self.out('g', 'ip link set wg-default down')
            try:
                self.assertSource('c', '10.88.0.2', '10.88.0.3', netns='b2')
                self.assertSource('c', 'fd88::2', 'fd88::3', netns='b2')
                self.assertSource('c', '10.98.0.1', '10.98.0.2', 80, netns='app')
            finally:
                self.out('g', 'ip link set wg-default up')

        # a port of c's container published on an address that came after the run
        self.out('c', PUBLISHED)
        self.addCleanup(self.sh, 'c', 'ip address del 10.231.0.22/32 dev eth0; nft delete table ip app2')
        self.assertEqual(self.answers('c', 8080, address='10.231.0.22'), INTERNET)

        # systemd-resolved asks a link's resolver from a socket bound to the link: directly; another program's
        # socket bound to it gets nowhere; the host's other questions go through the tunnel
        ask = f'python3 /usr/local/bin/ask.py {INTERNET} 53'
        self.assertEqual(self.out('c', f'setpriv --reuid systemd-resolve --regid systemd-resolve --clear-groups {ask} eth0')
                         .strip(), PUBLIC['c'])
        self.assertEqual(self.out('c', f'{ask} eth0').strip(), '')
        self.assertEqual(self.out('c', ask).strip(), PUBLIC['g'])

    def test_06_interface_down(self):
        # c's interface down (as at boot before it is up): nothing goes out but through ofzhur-closed; incoming
        # still answered. Stopped, then up by the run.
        self.out('c', 'systemctl stop wg-quick@wg-default')
        self.assertEqual(self.table('c'), ['default dev ofzhur-closed scope link metric 4294967295'.split(),
                                           'default dev ofzhur-closed metric 4294967295 pref medium'.split()])
        self.assertClosed('c')
        self.assertClosed('c', netns='app')
        self.assertIncoming()
        self.assertSource('c', PUBLIC['c'], METADATA)
        # started with a failing tunnel.sh: the interface up, without its route; closed still
        self.out('c', 'echo "exit 1" > /etc/wireguard/tunnel.sh && systemctl start wg-quick@wg-default')
        self.assertEqual(self.out('c', 'systemctl is-active wg-quick@wg-default').strip(), 'active')
        self.assertEqual(self.table('c'), ['default dev ofzhur-closed scope link metric 4294967295'.split(),
                                           'default dev ofzhur-closed metric 4294967295 pref medium'.split()])
        self.assertClosed('c')
        self.assertIncoming()
        self.play()
        self.assertTunnel()
        self.assertSource('c', PUBLIC['g'])

    def test_07_rules_gone(self):
        # the tunnel's rules gone (systemd-networkd removing others', a person): the guard drops what would leave
        # directly; incoming still answered
        for r in self.rules('c'):
            f, priority, rule = r.split(' ', 2)
            self.out('c', f'ip {f} rule del priority {priority} {rule}')
        self.assertEqual(self.rules('c'), [])
        self.assertClosed('c')
        self.assertClosed('c', netns='app')
        self.assertIncoming()
        r = self.play('--check')
        self.assertIn('changed: [c]', task(r, 'Tunnel'))
        self.play()
        self.assertTunnel()
        self.assertWorks()

    def test_08_conntrack(self):
        # conntrack forgets c's connections (conntrack -F; none knew them before the tunnel): in an SSH session c then
        # speaks first, as in the run's own at the task Tunnel, and the session goes on
        self.out('c', 'rm -f /tmp/speaking')
        e = {k: v for k, v in os.environ.items() if not k.startswith('ANSIBLE_')}
        p = subprocess.Popen(['ansible', 'c', '-m', 'ansible.builtin.shell', '-a', 'touch /tmp/speaking; sleep 5; echo alive',
                              *AS_UMP], cwd=self.infra.dir, env=e, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for _ in range(60):
            if self.sh('c', 'test -e /tmp/speaking').returncode == 0:
                break
            time.sleep(0.5)
        self.out('c', 'conntrack -F')
        out = p.communicate(timeout=120)[0]
        self.assertEqual(p.returncode, 0, out)
        self.assertIn('alive', out)
        self.assertWorks()

    def test_08_table_gone(self):
        # c's table of nftables gone (nft flush ruleset, a person): what the tunnel carries still goes through it,
        # nothing directly, IPv6 beyond the link least of all; SSH still answered, by its rules
        self.out('c', 'nft delete table inet ofzhur-wireguard')
        self.assertSource('c', PUBLIC['g'])
        self.assertEqual(self.source('c', INTERNET6), '')
        self.assertTrue(self.answers('c').startswith('SSH-2.0-'))
        self.assertTrue(self.answers('c', family=6, source=INTERNET6).startswith('SSH-2.0-'))
        self.out('g', 'ip link set wg-default down')
        try:
            before = len(self.seen())
            self.assertEqual(self.source('c'), '')
            self.assertEqual(self.source('c', netns='app'), '')
            self.assertEqual(self.seen()[before:], [])
            self.assertTrue(self.answers('c').startswith('SSH-2.0-'))
        finally:
            self.out('g', 'ip link set wg-default up')
        r = self.play()
        self.assertIn('changed: [c]', task(r, 'Tunnel'))
        self.assertWorks()

    def test_09_change(self):
        # another priority and table: the new rules in before the old go; the old table emptied. And back.
        self.infra.write('inventory/host_vars/c.yml', TUNNELS['c'] + 'wireguard_tunnel_priority: 31000\n'
                                                                    'wireguard_tunnel_table: 31000\n')
        self.play()
        self.assertEqual(self.table('c'), [])
        self.assertSource('c', PUBLIC['g'])
        self.assertEqual(sorted(int(r.split()[1]) for r in self.rules('c')), [31000] * 4 + [31001] * 2 + [31002] * 2 + [31003] * 2)
        self.tunnels()
        self.play()
        self.assertTunnel()
        self.assertUnchanged(self.play())

    def test_09_mtu(self):
        # the uplink's MTU changed (back to Docker's): the next run gives it to ofzhur-closed in place, the running
        # interface left as it is; below IPv6's minimum, 1280, and ofzhur-closed keeps IPv6 and its route
        try:
            self.out('c', 'ip link set eth0 mtu 1500')
            self.play()
            self.assertEqual(self.mtu('c', 'ofzhur-closed'), 1500)
            self.assertEqual(self.mtu('c', 'wg-default'), MTU - 80)
            self.out('c', 'ip link add ofzhur-test mtu 1200 type dummy && ip link set ofzhur-test up'
                          ' && ip route prepend default dev ofzhur-test && sh /etc/wireguard/tunnel.sh up')
            self.assertEqual(self.mtu('c', 'ofzhur-closed'), 1280)
            self.assertEqual(self.table('c')[1:], ['default dev ofzhur-closed scope link metric 4294967295'.split(),
                                                   'default dev ofzhur-closed metric 4294967295 pref medium'.split()])
        finally:
            self.sh('c', f'ip link del ofzhur-test; ip link set eth0 mtu {MTU}')
        self.play()
        self.assertTunnel()
        self.assertWorks()

    def test_10_docker(self):
        # Docker on g: FORWARD drops the clients' traffic until DOCKER-USER lets it through, as the run does, after the
        # owner's rule there; into Docker's bridges Docker decides, and g's container publishes nothing
        self.out('g', DOCKER)
        docker('exec', '-d', self.names['g'], 'ip', 'netns', 'exec', 'ctr', 'python3', '/usr/local/bin/whoami.py', '0.0.0.0', '80')
        self.assertClosed('c')
        r = self.play()
        self.assertIn('changed: [g]', task(r, 'Tunnel'))
        comment = '-m comment --comment ofzhur-wireguard'
        self.assertEqual(self.out('g', 'iptables -w -S DOCKER-USER 2>/dev/null').splitlines(), [
            '-N DOCKER-USER',
            OWNER,
            f'-A DOCKER-USER -i wg-default -o docker0 {comment} -j RETURN',
            f'-A DOCKER-USER -i wg-default -o br-+ {comment} -j RETURN',
            f'-A DOCKER-USER -i wg-default {comment} -j ACCEPT',
            f'-A DOCKER-USER -o wg-default -m conntrack --ctstate RELATED,ESTABLISHED {comment} -j ACCEPT',
            '-A DOCKER-USER -j RETURN'])
        self.assertWorks()
        self.assertEqual(self.source('c', '172.18.0.2', 80), '')
        self.assertUnchanged(self.play())

    def test_11_clients(self):
        # x through g in lab: g serves both interfaces
        self.infra.write('inventory/host_vars/x.yml', 'wireguard_tunnel: {host: g, network: lab}\n')
        self.play()
        self.assertSource('x', PUBLIC['g'])
        self.assertEqual(self.table('x')[0], f'default dev wg-lab scope link src {LAB["x"]}'.split())
        self.assertEqual(self.forwarding(), {'all': '0', 'eth0': '1', 'wg-default': '1', 'wg-lab': '1', 'lan0': '0'})
        self.assertEqual(self.recorded(), {self.index(n): n for n in ('eth0', 'wg-default', 'wg-lab')})
        self.assertIn('-4 32000 from all to 10.0.0.0/24 iif wg-lab prohibit proto 111', self.rules('g'))
        self.assertEqual(self.dropins('g'), {'wg-default', 'wg-lab'})
        self.assertEqual(self.dropins('x'), {'wg-lab'})
        # x without a tunnel, and without groups: g serves wg-default alone, and wg-lab forwards no more
        self.infra.write('inventory/host_vars/x.yml', 'wireguard_groups: []\n')
        self.play()
        self.assertEqual(self.rules('x'), [])
        self.assertSource('x', PUBLIC['x'])
        self.assertEqual(self.forwarding(), {'all': '0', 'eth0': '1', 'wg-default': '1', 'wg-lab': '0', 'lan0': '0'})
        self.assertEqual(self.recorded(), {self.index(n): n for n in ('eth0', 'wg-default')})
        self.assertEqual([r for r in self.rules('g') if 'wg-lab' in r], [])
        self.assertEqual(self.dropins('g'), {'wg-default'})
        self.assertEqual(self.dropins('x'), set())
        self.assertSource('c', PUBLIC['g'])
        # g's container reaches a peer that is not a client, masqueraded, and gets its answers
        docker('exec', '-d', self.names['x'], 'python3', '/usr/local/bin/whoami.py', MESH['x'], '8080')
        self.assertSource('g', MESH['g'], MESH['x'], netns='ctr')
        self.tunnels()
        self.play()
        self.assertTunnel()

    def test_11_cut_short(self):
        # a run cut short after it wrote a drop-in, before systemd read it: the next run has systemd read it,
        # changing nothing else
        f = '/etc/systemd/system/wg-quick@wg-default.service.d/ofzhur-wireguard.conf'
        self.out('c', f'cp {f} /root/drop-in && echo "# before" >> {f} && systemctl daemon-reload && cat /root/drop-in > {f}')
        self.assertEqual(self.out('c', 'systemctl show -p NeedDaemonReload --value wg-quick@wg-default').strip(), 'yes')
        self.assertUnchanged(self.play())
        self.assertEqual(self.dropins('c'), {'wg-default'})

    def test_11_restart(self):
        # g's interface restarted: another one, of another index; the record of the one gone is forgotten, and the
        # new one forwards once it is up, by its unit
        before = self.index('wg-default')
        self.out('g', 'systemctl restart wg-quick@wg-default')
        self.assertNotEqual(self.index('wg-default'), before)
        self.assertTunnel()
        # stopped, its record left behind, and its index given to another interface (as one moved in from a network
        # namespace keeps its own) that forwards by someone else's doing: not the role's, left as it is when the
        # interface starts again
        before = self.index('wg-default')
        self.out('g', f'systemctl stop wg-quick@wg-default && ip link add ofzhur-test index {before} type dummy'
                      ' && echo 1 > /proc/sys/net/ipv4/conf/ofzhur-test/forwarding')
        self.addCleanup(self.sh, 'g', 'ip link del ofzhur-test')
        self.out('g', 'systemctl start wg-quick@wg-default')
        self.assertEqual(self.out('g', 'cat /proc/sys/net/ipv4/conf/ofzhur-test/forwarding').strip(), '1')
        self.out('g', 'ip link del ofzhur-test')
        self.assertTunnel()
        self.assertWorks()
        self.assertUnchanged(self.play())

    def test_12_reboot(self):
        # c restarted without its interface (as at boot before it is up, or when it fails): closed from the start;
        # SSH and c's container answered
        self.out('c', 'systemctl mask wg-quick@wg-default')
        docker('restart', self.names['c'])
        self.boot()
        try:
            self.assertNotEqual(self.sh('c', 'ip link show wg-default').returncode, 0)
            self.assertClosed('c')
            self.assertClosed('c', netns='app')
            self.assertIncoming()
            self.assertSource('c', PUBLIC['c'], METADATA)
        finally:
            self.out('c', 'systemctl unmask wg-quick@wg-default && systemctl start wg-quick@wg-default')
        # started after the boot: its unit puts the route through it in place; its MTU that of the provider's
        # network, which came after the tunnel's unit
        self.assertSource('c', PUBLIC['g'])
        self.assertEqual(self.mtu('c', 'wg-default'), MTU - 80)
        # all restarted: the tunnel comes back, guard first, without a run; each interface's MTU as without the
        # tunnel (g's); nothing to change
        for host in TUNNEL_HOSTS:
            docker('restart', self.names[host])
        self.boot()
        self.assertTunnel()
        self.assertWorks()
        for host in TUNNEL_HOSTS:
            self.assertEqual(self.mtu(host, 'wg-default'), MTU - 80, host)
        self.assertUnchanged(self.play())

    def test_13_remove(self):
        # g's uplink renamed after the run that turned its forwarding on, as udev renames one at boot after the
        # tunnel's unit ran: still known by its index; the next run turns on nothing, and Docker's bridge, on
        # already, is not the role's
        self.out('g', DOCKER)
        self.play()
        uplink = self.index('eth0')
        self.rename('eth0', 'ext01')
        self.addCleanup(self.rename, 'ext01', 'eth0')
        r = self.play()
        self.assertNotIn('changed: [g]', task(r, 'Tunnel'))
        self.assertEqual(self.forwarding('ext01'), {'all': '0', 'ext01': '1', 'wg-default': '1', 'wg-lab': '0', 'lan0': '0'})
        self.assertEqual(self.recorded(), {uplink: 'eth0', self.index('wg-default'): 'wg-default'})
        self.assertWorks()

        # no tunnel any more: check mode tells, and changes nothing
        before = {h: (self.rules(h), self.out(h, 'nft list tables')) for h in TUNNEL_HOSTS}
        self.tunnels(False)
        r = self.play('--check')
        self.assertIn('changed: [c]', task(r, 'Tunnel of a host tunneled no longer'))
        self.assertEqual({h: (self.rules(h), self.out(h, 'nft list tables')) for h in TUNNEL_HOSTS}, before)
        self.assertEqual(self.allowed('c'), {'0.0.0.0/0', '10.0.0.1/32'})
        self.assertSource('c', PUBLIC['g'])

        # g first: it forwards no more before its rules go, its uplink by its new name too; c, not yet run, stays
        # closed
        self.play('--limit', 'g', hosts=['g'])
        self.assertEqual(self.forwarding('ext01'), {'all': '0', 'ext01': '0', 'wg-default': '0', 'wg-lab': '0', 'lan0': '0'})
        self.assertEqual(self.recorded(), {})
        self.assertEqual(self.rules('g'), [])
        self.assertClosed('c')

        # all of it goes, and c's traffic goes direct
        self.play()
        for host in TUNNEL_HOSTS:
            self.assertEqual(self.rules(host), [], host)
            self.assertNotIn('ofzhur-wireguard', self.out(host, 'nft list tables'), host)
            self.assertNotEqual(self.sh(host, 'ip link show ofzhur-closed').returncode, 0, host)
            self.assertEqual(self.out(host, 'wg show wg-default fwmark').strip(), 'off', host)
            self.assertNotIn('PostUp', self.out(host, 'cat /etc/wireguard/wg-default.conf'), host)
            self.assertEqual(self.dropins(host), set(), host)
            self.assertNotEqual(self.sh(host, 'ls /etc/wireguard/tunnel.sh').returncode, 0, host)
            self.assertNotEqual(self.sh(host, 'systemctl cat ofzhur-wireguard-tunnel').returncode, 0, host)
            self.assertEqual(self.out(host, 'sysctl -n net.ipv4.conf.all.src_valid_mark').strip(), '0', host)
            self.assertNotEqual(self.sh(host, 'test -e /etc/systemd/networkd.conf.d/ofzhur-wireguard.conf'
                                              ' || test -e /etc/systemd/system/docker.service.d/ofzhur-wireguard.conf')
                                .returncode, 0, host)
        for host in TUNNELS:
            self.assertEqual(self.allowed(host), {'10.0.0.1/32'}, host)
            self.assertEqual(self.table(host), [], host)
            self.assertSource(host, PUBLIC[host])
            self.assertSource(host, PUBLIC6[host], PUBLIC6['i'])
            self.assertSource(host, PUBLIC6[host], INTERNET6)
        self.assertSource('c', PUBLIC['c'], netns='app')
        self.assertEqual(self.forwarding('ext01'), {'all': '0', 'ext01': '0', 'wg-default': '0', 'wg-lab': '0', 'lan0': '0'})
        self.assertEqual(self.out('g', 'cat /proc/sys/net/ipv4/conf/docker0/forwarding').strip(), '1')
        self.assertEqual(self.out('g', 'iptables -w -S DOCKER-USER 2>/dev/null').splitlines(),
                         ['-N DOCKER-USER', OWNER, '-A DOCKER-USER -j RETURN'])
        self.assertIncoming()
        self.assertUnchanged(self.play())
        self.assertUnchanged(self.play('--check'))


if __name__ == '__main__':
    unittest.main()
