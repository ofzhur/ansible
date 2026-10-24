# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""Tests of the roles ofzhur.ansible.firewall and ofzhur.ansible.wireguard
together: the mesh, isolated by group.

Docker: six containers with systemd on one Docker network, a to f (a, c and
e on Debian 13, b, d and f on Ubuntu 24.04; b, c and f with the iptables
backend), all in the network default, 10.0.0.0/24, of their host files.
Each is reached over SSH as the user ump on a port Docker publishes, so
that SSH comes in on eth0, the interface the peers reach each other on.
A seventh container on the network, outside the inventory, sends from
elsewhere. They are privileged (systemd, WireGuard and netfilter in their
own network namespace). Without Docker it is skipped.

    python3 tests/test_mesh.py

Each step puts the hosts into groups, runs the playbook on all of them and
checks every ordered pair over the mesh: ping, and TCP to a listener on the
private address and to SSH there; the tunnels; the listen port, open to
the peers alone; SSH on eth0, open to all.
"""

import concurrent.futures
import itertools
import json
import os
import subprocess
import time
import unittest

import test_host
from test_users import AS_UMP, docker, have_docker, recap
from test_wireguard import BASES, DOCKERFILE as DOCKERFILE_WIREGUARD

Infra = test_host.Infra

PLAYBOOK = """\
- name: Mesh
  hosts: common
  become: true
  roles:
    - ofzhur.ansible.firewall
    - ofzhur.ansible.wireguard
"""

# test_wireguard's image, and conntrack: whether a firewall took a datagram in
DOCKERFILE = DOCKERFILE_WIREGUARD + """\
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends conntrack \\
 && rm -rf /var/lib/apt/lists/*
"""

# ansible_host is the address on the Docker network, the endpoint the peers
# reach, as a server's public address is; SSH goes to the port published.
HOST = """\
plugin: ofzhur.ansible.host
groups: {groups}
vars:
  ansible_host: {address}
  ansible_port: {port}
  ump_admin: ump
  ump_private_networks:
    default: {{address: {private}, cidr: 10.0.0.0/24}}
  ansible_ssh_private_key_file: {dir}/ump
  ansible_ssh_common_args: -o HostName=127.0.0.1 -o UserKnownHostsFile={dir}/known_hosts -o IdentitiesOnly=yes
"""

HOSTS = {'a': 'debian', 'b': 'ubuntu', 'c': 'debian', 'd': 'ubuntu', 'e': 'debian', 'f': 'ubuntu'}
IPTABLES = 'bcf'
PRIVATE = {h: f'10.0.0.{i}' for i, h in enumerate(HOSTS, 1)}
# 51820 + int(sha1('default')[:8], 16) % 1000
PORT = 52630
# the listener on the private address
HTTP = 8000
# the container outside the inventory
OUTSIDER = 'x'
# the source ports of the UDP datagrams, one per check
SPORTS = itertools.count(40001)

RULE = f"""\
firewall_rules:
  - proto: tcp
    port: {HTTP}
    interface: wg-default
    hosts: [a, c]
    comment: http over the mesh
"""

# Run on a host: from it, to each target, whether a new connection gets
# through (ping, TCP), retried.
PROBE = """\
import concurrent.futures, json, socket, subprocess, sys, time

http, targets = json.loads(sys.argv[1])

def retried(once):
    for _ in range(5):
        if once():
            return True
        time.sleep(0.2)
    return False

def ping(address):
    return retried(lambda: subprocess.run(['ping', '-c', '1', '-W', '1', address], capture_output=True).returncode == 0)

def connects(address, port):
    def once():
        try:
            socket.create_connection((address, port), timeout=1).close()
            return True
        except OSError:
            return False
    return retried(once)

checks = {}
with concurrent.futures.ThreadPoolExecutor(64) as pool:
    for name, t in targets.items():
        checks[name, 'ssh'] = pool.submit(connects, t['public'], 22)
        if t.get('private'):
            checks[name, 'ping'] = pool.submit(ping, t['private'])
            checks[name, 'http'] = pool.submit(connects, t['private'], http)
            checks[name, 'ssh over wg'] = pool.submit(connects, t['private'], 22)
out = {}
for (name, kind), f in checks.items():
    out.setdefault(name, {})[kind] = f.result()
print(json.dumps(out))
"""

# Run on a host: UDP datagrams to the listen port of each address, from a
# port of their own; the target's conntrack has the flow once its firewall
# took one in.
SEND = """\
import json, socket, sys

sport, port, addresses = json.loads(sys.argv[1])
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.bind(('0.0.0.0', sport))
for _ in range(3):
    for a in addresses:
        u.sendto(b'probe', (a, port))
"""


def both(hosts):
    """New connections between any two of hosts, both ways."""
    return {(x, y) for x in hosts for y in hosts if x != y}


def one_way(sources, targets):
    """New connections from each of sources to each of targets."""
    return {(x, y) for x in sources for y in targets}


def matrix(sources, cell):
    """A row per source, a column per host."""
    lines = ['   ' + ''.join(f'{t:>5}' for t in HOSTS)]
    for s in sources:
        lines.append(f'{s:<3}' + ''.join(f'{"" if s == t else cell(s, t):>5}' for t in HOSTS))
    return '\n'.join(lines) + '\n'


class Mesh(unittest.TestCase):
    """Six servers as ump leaves them; the groups changed, the playbook run on all of them, step by step."""

    maxDiff = None

    @classmethod
    def setUpClass(cls):
        if not have_docker():
            raise unittest.SkipTest('Docker is not available')
        for os_, base in BASES.items():
            docker('build', '-q', '-t', f'ofzhur-test-mesh:{os_}', '-', input=DOCKERFILE.format(base=base))

        cls.net = 'ofzhur-test-mesh'
        cls.names = {h: f'ofzhur-test-mesh-{h}' for h in [*HOSTS, OUTSIDER]}
        for name in cls.names.values():
            docker('rm', '-f', name, check=False)
        docker('network', 'rm', cls.net, check=False)
        docker('network', 'create', cls.net)
        cls.addClassCleanup(docker, 'network', 'rm', cls.net, check=False)

        cls.infra = Infra({
            'playbooks/mesh.yml': PLAYBOOK,
            'inventory/group_vars/all/wireguard.yml': 'wireguard_isolation: [foo, bar]\n',
            **{f'inventory/host_vars/{h}.yml': 'firewall_backend: iptables\n' for h in IPTABLES},
        })
        cls.addClassCleanup(cls.infra.close)
        d = cls.infra.dir
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'ump@test', '-f', f'{d}/ump'], check=True)
        with open(f'{d}/ump.pub') as f:
            key = f.read().strip()

        cls.addresses = {}
        cls.ports = {}
        for host, os_ in [*HOSTS.items(), (OUTSIDER, 'debian')]:
            name = cls.names[host]
            cls.addClassCleanup(docker, 'rm', '-f', name, check=False)
            if host == OUTSIDER:
                docker('run', '-d', '--name', name, '--network', cls.net, f'ofzhur-test-mesh:{os_}', 'sleep', 'infinity')
            else:
                docker('run', '-d', '--name', name, '--hostname', host, '--network', cls.net, '--privileged',
                       '--tmpfs', '/run', '--tmpfs', '/run/lock', '-p', '127.0.0.1::22', f'ofzhur-test-mesh:{os_}')
                docker('exec', '-i', name, 'sh', '-c',
                       'install -d -m 700 -o ump -g ump /home/ump/.ssh'
                       ' && cat > /home/ump/.ssh/authorized_keys'
                       ' && chown ump:ump /home/ump/.ssh/authorized_keys'
                       ' && chmod 600 /home/ump/.ssh/authorized_keys',
                       input=key + '\n')
                cls.ports[host] = docker('port', name, '22/tcp').stdout.split()[0].rsplit(':', 1)[1]
            cls.addresses[host] = docker('inspect', '-f', '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}',
                                         name).stdout.strip()
        cls.set_groups()

        for _ in range(60):
            r = cls.infra.run('ansible', 'all', '-m', 'ansible.builtin.ping', *AS_UMP)
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            raise AssertionError(f'the containers are not reachable over SSH:\n{r.stdout}{r.stderr}')

    @classmethod
    def set_groups(cls, **groups):
        """Puts each host into the Ansible groups given, the others into none but common."""
        for host in HOSTS:
            cls.infra.write(f'inventory/hosts/{host}.yml', HOST.format(
                groups=json.dumps(['common'] + groups.get(host, [])), address=cls.addresses[host],
                port=cls.ports[host], private=PRIVATE[host], dir=cls.infra.dir))

    def play(self, *args):
        r = self.infra.run('ansible-playbook', 'playbooks/mesh.yml', *AS_UMP, *args)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(sorted(recap(r.stdout)), list(HOSTS))
        return r

    def assertUnchanged(self, r):
        for host, counts in recap(r.stdout).items():
            self.assertEqual(counts['changed'], 0, f'{host}\n{r.stdout}')

    def sh(self, host, command, input=None):
        return docker('exec', '-i', self.names[host], 'sh', '-c', command, check=False, input=input)

    def out(self, host, command):
        r = self.sh(host, command)
        self.assertEqual(r.returncode, 0, f'{host}: {command}: {r.stderr}')
        return r.stdout

    def assertSSH(self):
        """A new SSH connection (none of Ansible's) gets in, on eth0."""
        d = self.infra.dir
        for host in HOSTS:
            r = subprocess.run(['ssh', '-F', '/dev/null', '-o', 'ControlPath=none', '-o', 'BatchMode=yes',
                                '-o', 'ConnectTimeout=10', '-o', 'IdentitiesOnly=yes', '-i', f'{d}/ump',
                                '-o', f'UserKnownHostsFile={d}/known_hosts', '-o', 'StrictHostKeyChecking=accept-new',
                                '-p', self.ports[host], 'ump@127.0.0.1', 'true'], capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, f'SSH to {host}: {r.stderr}')

    def listen(self):
        """The listener on each private address."""
        for host in HOSTS:
            if not self.sh(host, f'ss -Hltn src {PRIVATE[host]}:{HTTP} | grep -q LISTEN').returncode:
                continue
            docker('exec', '-d', self.names[host], 'python3', '-m', 'http.server', '--bind', PRIVATE[host],
                   '--directory', '/tmp', str(HTTP))
            for _ in range(20):
                if not self.sh(host, f'ss -Hltn src {PRIVATE[host]}:{HTTP} | grep -q LISTEN').returncode:
                    break
                time.sleep(0.5)
            else:
                self.fail(f'no listener on {host}')

    def peers(self):
        """{host: the hosts of its peers}, by their public keys."""
        keys = {self.out(h, 'wg show wg-default public-key').strip(): h for h in HOSTS}
        return {h: {keys.get(k, k) for k in self.out(h, 'wg show wg-default peers').split()} for h in HOSTS}

    def observe(self):
        """What gets through, as matrices: the mesh, the tunnels and the listen port, SSH on eth0."""
        self.listen()
        sport = next(SPORTS)

        def probe(source):
            targets = {h: {'public': self.addresses[h], **({'private': PRIVATE[h]} if source != OUTSIDER else {})}
                       for h in HOSTS if h != source}
            r = self.sh(source, f"python3 - '{json.dumps([HTTP, targets])}'", input=PROBE)
            self.assertEqual(r.returncode, 0, f'{source}: {r.stderr}')
            return json.loads(r.stdout)

        def send(source):
            addresses = [self.addresses[h] for h in unseen[source]]
            if addresses:
                r = self.sh(source, f"python3 - '{json.dumps([sport, PORT, addresses])}'", input=SEND)
                self.assertEqual(r.returncode, 0, f'{source}: {r.stderr}')

        def taken(target):
            sources = ' '.join(self.addresses[s] for s in self.names if s != target)
            return {by_address[a] for a in self.out(target, f'for s in {sources}; do conntrack -G -p udp -s $s'
                                                             f' -d {self.addresses[target]} --sport {sport} --dport {PORT}'
                                                             ' >/dev/null 2>&1 && echo $s; done; true').split()}

        by_address = {a: h for h, a in self.addresses.items()}
        took = {h: set() for h in HOSTS}
        unseen = {s: [h for h in HOSTS if h != s] for s in self.names}
        with concurrent.futures.ThreadPoolExecutor(len(self.names)) as pool:
            seen = dict(zip(self.names, pool.map(probe, self.names)))
            # a datagram can get lost on the way: sent again where it did not show
            for _ in range(3):
                list(pool.map(send, self.names))
                time.sleep(1)
                for h, sources in zip(HOSTS, pool.map(taken, HOSTS)):
                    took[h] |= sources
                unseen = {s: [h for h in targets if s not in took[h]] for s, targets in unseen.items()}
        peers = self.peers()

        def mesh(s, t):
            c = seen[s][t]
            return ''.join(k if c[kind] else '-' for k, kind in (('p', 'ping'), ('h', 'http'), ('s', 'ssh over wg')))

        return {
            'mesh': matrix(HOSTS, mesh),
            'tunnels': matrix(HOSTS, lambda s, t: ('w' if t in peers[s] else '-') + ('u' if s in took[t] else '-')),
            'from outside': matrix([OUTSIDER], lambda s, t: 'u' if s in took[t] else '-'),
            'ssh': matrix([*HOSTS, OUTSIDER], lambda s, t: 'y' if seen[s][t]['ssh'] else '-'),
        }

    def assertMesh(self, connections, apart=frozenset(), http=frozenset()):
        """New connections over the mesh between the pairs (x, y) of connections, from x alone, and to the
        listener alone between those of http; tunnels between any two hosts but those of apart, the listen
        port open to the peers alone; SSH on eth0 from anywhere."""
        tunnel = {(x, y) for x in HOSTS for y in HOSTS if x != y and (x, y) not in apart and (y, x) not in apart}
        expected = {
            'mesh': matrix(HOSTS, lambda s, t: 'phs' if (s, t) in connections else '-h-' if (s, t) in http else '---'),
            'tunnels': matrix(HOSTS, lambda s, t: 'wu' if (s, t) in tunnel else '--'),
            'from outside': matrix([OUTSIDER], lambda s, t: '-'),
            'ssh': matrix([*HOSTS, OUTSIDER], lambda s, t: 'y'),
        }
        observed = self.observe()
        for name, m in expected.items():
            self.assertMultiLineEqual(observed[name], m, name)
        self.assertSSH()

    def step(self, connections, apart=frozenset(), http=frozenset()):
        self.play()
        self.assertSSH()
        self.assertMesh(connections, apart, http)
        self.assertUnchanged(self.play())

    def test_1_one_group(self):
        # all six in foo: any two connect, both ways
        self.set_groups(**{h: ['foo'] for h in HOSTS})
        self.step(both(HOSTS))

    def test_2_foo(self):
        # a and b in foo, the others in none: a and b connect to each other and to the others, the others
        # to each other alone
        self.set_groups(a=['foo'], b=['foo'])
        self.step(both('ab') | both('cdef') | one_way('ab', 'cdef'))

    def test_3_foo_and_bar(self):
        # a and b in foo, c and d in bar: foo and bar apart, no tunnel; e and f connect to each other, the
        # others to them
        self.set_groups(a=['foo'], b=['foo'], c=['bar'], d=['bar'])
        self.step(both('ab') | both('cd') | both('ef') | one_way('abcd', 'ef'), apart=one_way('ab', 'cd'))

    def test_4_rule_for_the_interface(self):
        # groups as before, and a rule for wg-default on a and c: their peers get to the listener, nothing
        # else; foo and bar still apart
        self.infra.write('inventory/group_vars/all/firewall.yml', RULE)
        self.step(both('ab') | both('cd') | both('ef') | one_way('abcd', 'ef'), apart=one_way('ab', 'cd'),
                  http=one_way('ef', 'ac'))

    def test_5_no_groups(self):
        # none in a group, no rule: any two connect again, the tunnels between foo and bar back
        os.remove(os.path.join(self.infra.dir, 'inventory', 'group_vars', 'all', 'firewall.yml'))
        self.set_groups()
        self.step(both(HOSTS))


if __name__ == '__main__':
    unittest.main()
