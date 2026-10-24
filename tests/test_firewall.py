# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

"""Tests of the role ofzhur.ansible.firewall.

The checks run the ansible CLI found on PATH only. The scenarios also run
Docker: two containers per image (web-01, db-01) with systemd, reached over
SSH as the user ump the way ump leaves a server; db-01 has the firewall ump
installs, web-01 none and the nftables.service of Arch Linux. A network of
their own (eth1, IPv4 and IPv6) joins them and a third container, the
client. They are privileged (systemd, netfilter in their own network
namespace). db-01 also forwards, the way Docker does: rules of other
software the firewall leaves alone. Without Docker they are skipped.

    python3 tests/test_firewall.py
"""

import json
import re
import subprocess
import time
import unittest
import urllib.request

import test_host
from test_users import AS_UMP, CHECK_ENV, LOCAL, docker, have_docker, recap

Infra = test_host.Infra

PLAYBOOK = """\
- hosts: common
  become: true
  roles:
    - ofzhur.ansible.firewall
"""

ANNOUNCE = """\
- hosts: "{{ target }}"
  become: true
  tasks:
    - ansible.builtin.include_role:
        name: ofzhur.ansible.firewall
        tasks_from: announce
      vars:
        firewall_announce: "{{ announcement }}"
"""

# The role's own expression for the connection, on the control machine
# alone: debug runs no module.
ADMITS = """\
- hosts: web-01
  gather_facts: false
  vars_files:
    - ../collections/ansible_collections/ofzhur/ansible/roles/firewall/vars/main.yml
  tasks:
    - ansible.builtin.debug:
        msg: "case {{ item.0 }}: {{ __firewall_ssh_admits | bool }}"
      loop: "{{ sourced | default([]) }}"
      vars:
        __firewall_connection: {stdout: "{{ item.1 }}"}
        firewall_ssh_port: "{{ item.2 }}"
        firewall_ssh_sources: "{{ item.3 }}"
    - ansible.builtin.debug:
        msg: "case {{ item.0 }}: {{ __firewall_ssh_admits | bool }}"
      loop: "{{ anywhere | default([]) }}"
      vars:
        __firewall_connection: {stdout: "{{ item.1 }}"}
        firewall_ssh_port: "{{ item.2 }}"
    - ansible.builtin.debug:
        msg: "case {{ item.0 }}: {{ __firewall_ssh_admits | bool }}"
      loop: "{{ policed | default([]) }}"
      vars:
        __firewall_connection: {stdout: "{{ item.1 }}"}
        firewall_ssh_port: 22
        __firewall_interfaces: "{{ item.2 }}"
        __firewall_policy: "{{ item.3 }}"
"""


class Checks(unittest.TestCase):
    """The role resolves; a bad variable or rule fails before the first change."""

    def infra(self, files=None):
        i = Infra({
            'inventory/hosts/web-01.yml': LOCAL,
            'playbooks/firewall.yml': PLAYBOOK,
            'playbooks/announce.yml': ANNOUNCE,
            'playbooks/admits.yml': ADMITS,
            **(files or {}),
        })
        self.addCleanup(i.close)
        return i

    def firewall(self, firewall_yml, *args, files=None):
        i = self.infra({'inventory/group_vars/common/firewall.yml': firewall_yml, **(files or {})})
        return i.run('ansible-playbook', 'playbooks/firewall.yml', '--check', '-e', 'ansible_become=false', *args,
                     env=CHECK_ENV)

    def assertRefused(self, r, *messages, ok=None):
        self.assertNotEqual(r.returncode, 0, r.stdout)
        squeezed = ' '.join(r.stdout.split())
        for m in messages:
            self.assertIn(m, squeezed)
        counts = recap(r.stdout)['web-01']
        self.assertEqual((counts['changed'], counts['failed'], counts['skipped']), (0, 1, 0))
        if ok is not None:
            self.assertEqual(counts['ok'], ok)

    def test_syntax(self):
        i = self.infra()
        for playbook in ('playbooks/firewall.yml', 'playbooks/announce.yml'):
            r = i.run('ansible-playbook', '--syntax-check', playbook, '-e', 'target=all')
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_documentation(self):
        r = self.infra().run('ansible-doc', '-t', 'role', 'ofzhur.ansible.firewall')
        self.assertEqual(r.returncode, 0, r.stderr)
        for word in ('ENTRY POINT: main', 'ENTRY POINT: announce', 'firewall_rules', 'firewall_announce',
                     'firewall_ssh_sources', 'accept_from'):
            self.assertIn(word, re.sub(r'\x1b\[[0-9;]*m', '', r.stdout))

    def test_unknown_key(self):
        r = self.firewall('firewall_rules:\n  - proto: tcp\n    port: 80\n    source: [10.0.0.0/8]\n')
        self.assertRefused(r, 'firewall_rules.source. Supported parameters include', ok=0)

    def test_wrong_type(self):
        cases = {
            'backend': 'firewall_backend: nft\n',
            'port': 'firewall_ssh_port: ssh\n',
            'no port': 'firewall_ssh_port: null\n',
            'rule': 'firewall_rules: [tcp/80]\n',
            'proto': 'firewall_rules:\n  - proto: icmp\n    port: 1\n',
            'required': 'firewall_rules:\n  - proto: tcp\n',
            'icmp': 'firewall_icmp: sometimes\n',
        }
        for name, firewall_yml in cases.items():
            with self.subTest(name):
                self.assertRefused(self.firewall(firewall_yml), 'Validation of arguments failed', ok=0)

    def test_outside_the_inventory(self):
        # an announcement applies the firewall in another play, without these
        playbooks = {
            'parameter': (PLAYBOOK.replace('- ofzhur.ansible.firewall',
                                           '- role: ofzhur.ansible.firewall\n      firewall_icmp: false'),
                          'firewall_icmp'),
            'play': (PLAYBOOK.replace('  roles:', '  vars:\n    firewall_rules: [{proto: tcp, port: 80}]\n'
                                                  '    firewall_ssh_sources: [10.0.0.0/8]\n  roles:'),
                     'firewall_ssh_sources, firewall_rules'),
        }
        for name, (playbook, unseen) in playbooks.items():
            with self.subTest(name):
                r = self.firewall('firewall_ssh_port: 22\n', files={'playbooks/firewall.yml': playbook})
                self.assertRefused(r, f'firewall: {unseen} of web-01 set outside the inventory;'
                                      ' set it in group_vars or host_vars', ok=1)
        # the inventory, and extra variables: every play sees them
        for args in ((), ('-e', 'firewall_ssh_port=2222'), ('-e', '{"firewall_rules": [{"proto": "tcp", "port": 80}]}')):
            with self.subTest(args):
                r = self.firewall('firewall_ssh_sources: [10.0.0.0/8]\nfirewall_icmp: false\n', *args)
                self.assertNotIn('of web-01 set outside the inventory', r.stdout)
                self.assertIn('TASK [ofzhur.ansible.firewall : Look at the host]', r.stdout)

    def test_no_ssh(self):
        for firewall_yml in ('firewall_ssh_sources: []\n', 'firewall_ssh_port: 0\n', 'firewall_ssh_port: 65536\n'):
            with self.subTest(firewall_yml):
                self.assertRefused(self.firewall(firewall_yml), 'firewall: no SSH', ok=3)

    def test_invalid_rules(self):
        cases = {
            'port: 0': 'port: a port',
            'port: "2000-1000"': 'port: a port',
            'port: 65536': 'port: a port',
            'port: "80,443"': 'port: a port',
            'port: http': 'port: a port',
            'port: []': 'port: a port',
            'port: 80\n    sources: [10.0.0.0/33]': 'sources: 10.0.0.0/33 is no address or network',
            'port: 80\n    sources: [example.com]': 'sources: example.com is no address or network',
            'port: 80\n    sources: ["10.0.0.1; accept"]': 'sources: 10.0.0.1; accept is no address or network',
            'port: 80\n    sources: ["1::2::3"]': 'sources: 1::2::3 is no address or network',
            'port: 80\n    sources: ["12345::1"]': 'sources: 12345::1 is no address or network',
            'port: 80\n    sources: ["1:2:3:4:5:6:7:8:9"]': 'sources: 1:2:3:4:5:6:7:8:9 is no address or network',
            'port: 80\n    sources: ["1:2:3:4:5:6:7:8::"]': 'sources: 1:2:3:4:5:6:7:8:: is no address or network',
            'port: 80\n    sources: ["2001:db8::/129"]': 'sources: 2001:db8::/129 is no address or network',
            'port: 80\n    sources: ["::1.2.3.256"]': 'sources: ::1.2.3.256 is no address or network',
            'port: 80\n    sources: ["1.2.3.4::"]': 'sources: 1.2.3.4:: is no address or network',
            'port: 80\n    sources: ["::1 accept"]': 'sources: ::1 accept is no address or network',
            'port: 80\n    interface: wg default': 'interface: 1-15 letters',
            'port: 80\n    interface: a-very-long-interface': 'interface: 1-15 letters',
            'port: 80\n    comment: \'say "hi"\'': 'comment: up to 64',
            'port: 80\n    comment: ' + 'x' * 65: 'comment: up to 64',
        }
        for rule, message in cases.items():
            with self.subTest(rule):
                r = self.firewall(f'firewall_rules:\n  - proto: tcp\n    port: 80\n    hosts: web-*\n  - proto: udp\n    {rule}\n')
                self.assertRefused(r, f'firewall_rules[1]: {message}', ok=4)
        # the SSH sources are checked too
        self.assertRefused(self.firewall('firewall_ssh_sources: [10.0.0.256]\n'),
                           'SSH: sources: 10.0.0.256 is no address or network', ok=4)

    def test_valid_sources(self):
        # IPv6 in its forms; the run goes on to the host (no interpreter there)
        sources = ['::/0', '::1', '2001:db8::/32', '2001:0DB8:0:0:0:0:0:5/128', '1:2:3:4:5:6:7::', '::2:3:4:5:6:7:8',
                   '::ffff:203.0.113.5', '64:ff9b::/96', '64:ff9b::198.51.100.0/120', '1:2:3:4:5:6:1.2.3.4',
                   '10.0.0.0/8', '192.0.2.1']
        r = self.firewall('firewall_rules:\n  - proto: tcp\n    port: 80\n    sources: ' + json.dumps(sources) + '\n')
        self.assertNotIn('is no address or network', r.stdout)
        self.assertIn('TASK [ofzhur.ansible.firewall : Look at the host]', r.stdout)

    def test_targeted(self):
        # a rule for other hosts is not checked here; the run goes on to the host (no interpreter there)
        r = self.firewall('firewall_rules:\n  - proto: tcp\n    port: 0\n    hosts: db-*\n')
        self.assertNotIn('firewall_rules[0]', r.stdout)
        failed_at = r.stdout[:r.stdout.index('fatal: [web-01]')].rsplit('TASK [', 1)[1]
        self.assertTrue(failed_at.startswith('ofzhur.ansible.firewall : Look at the host]'), failed_at)
        self.assertEqual(recap(r.stdout)['web-01']['ok'], 5)

    def announce(self, i, announcement):
        return i.run('ansible-playbook', 'playbooks/announce.yml', '--check', '-e', 'ansible_become=false',
                     '-e', json.dumps({'target': 'web-01', 'announcement': announcement}), env=CHECK_ENV)

    def test_announce_refused(self):
        i = self.infra()
        mesh = {'name': 'mesh', 'rules': []}
        cases = {
            'name': ({'name': 'my app', 'rules': []}, 'name: up to 32'),
            'long name': ({'name': 'x' * 33, 'rules': []}, 'name: up to 32'),
            'dot first': ({'name': '.app', 'rules': []}, 'name: up to 32'),
            'dots': ({'name': '..', 'rules': []}, 'name: up to 32'),
            'port': ({'name': 'app', 'rules': [{'proto': 'tcp', 'port': 0}]}, 'rules[0]: port: a port'),
            'unknown key': ({'name': 'app', 'rules': [{'proto': 'tcp', 'port': 1, 'hosts': ['all']}]},
                            'firewall_announce.rules.hosts. Supported parameters include'),
            'no rules': ({'name': 'app'}, 'missing required arguments: rules'),
            'interfaces': ({**mesh, 'interfaces': ['wg-mesh']}, "found in 'firewall_announce'. and we were unable to convert to dict"),
            'interface name': ({**mesh, 'interfaces': {'wg mesh': {'accept_from': []}}},
                               'announcement mesh: interfaces.wg mesh: interface: 1-15 letters'),
            'long interface': ({**mesh, 'interfaces': {'wg-a-long-network': {'accept_from': []}}},
                               'interfaces.wg-a-long-network: interface: 1-15 letters'),
            'policy': ({**mesh, 'interfaces': {'wg-mesh': ['10.0.0.2']}},
                       'interfaces.wg-mesh: {accept_from: [...]}'),
            'policy key': ({**mesh, 'interfaces': {'wg-mesh': {'accept_from': [], 'drop': True}}},
                           'interfaces.wg-mesh: {accept_from: [...]}'),
            'no accept_from': ({**mesh, 'interfaces': {'wg-mesh': {}}}, 'interfaces.wg-mesh: {accept_from: [...]}'),
            'accept_from': ({**mesh, 'interfaces': {'wg-mesh': {'accept_from': ['10.0.0.2', '10.0.0.0/33']}}},
                            'interfaces.wg-mesh: accept_from: 10.0.0.0/33 is no address or network'),
            'accept_from v6': ({**mesh, 'interfaces': {'wg-mesh': {'accept_from': ['fd00::1::2']}}},
                               'interfaces.wg-mesh: accept_from: fd00::1::2 is no address or network'),
            'accept_from mapping': ({**mesh, 'interfaces': {'wg-mesh': {'accept_from': {'a': 1}}}},
                                    'interfaces.wg-mesh: accept_from: a list of addresses and networks'),
        }
        for name, (announcement, message) in cases.items():
            with self.subTest(name):
                self.assertRefused(self.announce(i, announcement), message)

    def test_announce_valid(self):
        # the checks pass; the run goes on to the host (no interpreter there)
        i = self.infra()
        for announcement in ({'name': 'app.v2', 'rules': [{'proto': 'tcp', 'port': 8443}]},
                             {'name': 'mesh', 'rules': [], 'interfaces': {'wg-mesh': {'accept_from': ['10.0.0.2', 'fd00::2']}}},
                             {'name': 'mesh', 'rules': [], 'interfaces': {'wg-mesh': {'accept_from': '10.0.0.0/24'}}},
                             {'name': 'mesh', 'rules': [], 'interfaces': {'wg-mesh': {'accept_from': []}}}):
            with self.subTest(announcement):
                r = self.announce(i, announcement)
                self.assertNotIn('firewall: announcement', r.stdout)
                self.assertIn('fatal: [web-01]', r.stdout.split('TASK [ofzhur.ansible.firewall : Directory of the announcements]')[1])

    def test_ssh_admits(self):
        # case: (SSH_CONNECTION, firewall_ssh_port, firewall_ssh_sources)
        sourced = {
            'v4 in network': ('172.17.0.1 50000 172.17.0.2 22', 22, ['172.16.0.0/12'], True),
            'v4 address': ('172.17.0.1 50000 172.17.0.2 22', 22, ['10.0.0.0/8', '172.17.0.1'], True),
            'v4 host bits': ('172.17.0.1 50000 172.17.0.2 22', 22, ['172.17.0.9/24'], True),
            'v4 outside': ('172.17.0.1 50000 172.17.0.2 22', 22, ['172.17.1.0/24'], False),
            'v4 next to it': ('172.17.0.1 50000 172.17.0.2 22', 22, ['172.17.0.2'], False),
            'v4 any': ('172.17.0.1 50000 172.17.0.2 22', 22, ['0.0.0.0/0'], True),
            'v4 by v6': ('172.17.0.1 50000 172.17.0.2 22', 22, ['::/0'], False),
            'mapped v4': ('::ffff:203.0.113.5 50000 ::ffff:203.0.113.1 22', 22, ['203.0.113.0/24'], True),
            'mapped v4 outside': ('::FFFF:203.0.113.5 50000 ::ffff:203.0.113.1 22', 22, ['198.51.100.0/24'], False),
            'v6 in network': ('2001:db8:1::5 50000 2001:db8::1 22', 22, ['2001:db8::/32'], True),
            'v6 compressed': ('2001:db8::5 50000 2001:db8::1 22', 22, ['2001:0db8:0000:0000:0000:0000:0000:0005'], True),
            'v6 outside': ('2001:db9::5 50000 2001:db8::1 22', 22, ['2001:db8::/32'], False),
            'v6 by v4': ('2001:db8::5 50000 2001:db8::1 22', 22, ['0.0.0.0/0'], False),
            'v6 link-local': ('fe80::1%eth0 50000 fe80::2%eth0 22', 22, ['fe80::/10'], True),
            'v6 /127': ('2001:db8::5 50000 2001:db8::1 22', 22, ['2001:db8::4/127'], True),
            'v6 /128 other': ('2001:db8::5 50000 2001:db8::1 22', 22, ['2001:db8::4/128'], False),
            'v6 dotted': ('64:ff9b::c633:6405 50000 2001:db8::1 22', 22, ['64:ff9b::198.51.100.0/120'], True),
            'v6 dotted outside': ('64:ff9b::c633:6505 50000 2001:db8::1 22', 22, ['64:ff9b::198.51.100.0/120'], False),
            'wrong port': ('172.17.0.1 50000 172.17.0.2 2222', 22, ['172.16.0.0/12'], False),
            'string': ('172.17.0.1 50000 172.17.0.2 22', 22, '172.17.0.0/16', True),
        }
        anywhere = {
            'any': ('172.17.0.1 50000 172.17.0.2 22', 22, None, True),
            'any, wrong port': ('172.17.0.1 50000 172.17.0.2 22', 2222, None, False),
            'other port': ('172.17.0.1 50000 172.17.0.2 2222', 2222, None, True),
            'no connection': ('', 2222, None, True),
        }
        # case: (SSH_CONNECTION and the addresses of `ip -o address`, accept_from of wg-a, rules)
        addresses = ('\n1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever preferred_lft forever'
                     '\n2: eth0    inet 172.17.0.2/16 brd 172.17.255.255 scope global eth0\\       valid_lft forever'
                     '\n2: eth0    inet6 2001:db8::1/64 scope global \\       valid_lft forever preferred_lft forever'
                     '\n5: wg-a    inet 10.0.0.1/24 scope global wg-a\\       valid_lft forever preferred_lft forever'
                     '\n5: wg-a    inet6 fd00::1/64 scope global \\       valid_lft forever preferred_lft forever')
        wg = '10.0.0.5 50000 10.0.0.1 22' + addresses
        rule = {'proto': 'tcp', 'ports': ['22'], 'sources': None, 'interface': 'wg-a', 'comment': None}
        policed = {
            'accepted': (wg, ['10.0.0.5'], [], True),
            'accepted by network': (wg, ['10.0.0.0/24'], [], True),
            'not accepted': (wg, ['10.0.0.6'], [], False),
            'none accepted': (wg, [], [], False),
            'the SSH rule does not count': (wg, ['10.0.0.6'], [{**rule, 'interface': None}], False),
            'a rule for it': (wg, ['10.0.0.6'], [rule], True),
            'a rule for it, range': (wg, [], [{**rule, 'ports': ['8080', '20-30']}], True),
            'a rule for it, other port': (wg, [], [{**rule, 'ports': ['2222']}], False),
            'a rule for it, udp': (wg, [], [{**rule, 'proto': 'udp'}], False),
            'a rule for it, other sources': (wg, [], [{**rule, 'sources': ['10.0.1.0/24']}], False),
            'a rule for it, its sources': (wg, [], [{**rule, 'sources': ['10.0.0.4/30']}], True),
            'a rule for another': (wg, [], [{**rule, 'interface': 'wg-b'}], False),
            'v6': ('fd00::5 50000 fd00::1 22' + addresses, ['fd00::/64'], [], True),
            'v6 not accepted': ('fd00::5 50000 fd00::1 22' + addresses, ['10.0.0.5', 'fd00::6'], [], False),
            'mapped v4': ('::ffff:10.0.0.5 50000 ::ffff:10.0.0.1 22' + addresses, ['10.0.0.5'], [], True),
            'link-local': ('fe80::5%wg-a 50000 fe80::1%wg-a 22', ['fe80::5'], [], True),
            'link-local not accepted': ('fe80::5%wg-a 50000 fe80::1%wg-a 22', ['fe80::6'], [], False),
            'another interface': ('172.17.0.1 50000 172.17.0.2 22' + addresses, [], [], True),
            'another interface, v6': ('2001:db8::5 50000 2001:db8::1 22' + addresses, [], [], True),
            'an address of none': ('192.0.2.1 50000 192.0.2.2 22' + addresses, [], [], True),
        }
        extra = {
            'sourced': [[name, c, p, s] for name, (c, p, s, _) in sourced.items()],
            'anywhere': [[name, c, p] for name, (c, p, _, _) in anywhere.items()],
            'policed': [[name, c, {'wg-a': [{'name': 'mesh', 'sources': s}]}, rules]
                        for name, (c, s, rules, _) in policed.items()],
        }
        r = self.infra().run('ansible-playbook', 'playbooks/admits.yml', '-e', json.dumps(extra), env=CHECK_ENV)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        got = dict(re.findall(r'case (.+?): (True|False)', r.stdout))
        for name, admitted in [(n, c[-1]) for n, c in {**sourced, **anywhere, **policed}.items()]:
            with self.subTest(name):
                self.assertEqual(got.get(name), str(admitted))


# --- Docker -------------------------------------------------------------------

# systemd as PID 1, sshd as the image enables it, HTTP on 8080 and 8081
DOCKERFILE = """\
FROM {base}
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \\
      systemd systemd-sysv openssh-server python3 sudo iproute2 iputils-ping \\
 && rm -rf /var/lib/apt/lists/* \\
 && useradd -m -s /bin/bash ump \\
 && echo 'ump ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-ump-ump && chmod 440 /etc/sudoers.d/90-ump-ump \\
 && mkdir -p /srv/www && echo ok > /srv/www/index.html \\
 && printf '[Service]\\nExecStart=/usr/bin/python3 -m http.server %%i --bind :: --directory /srv/www\\n[Install]\\nWantedBy=multi-user.target\\n' \\
      > /etc/systemd/system/http@.service \\
 && systemctl enable http@8080 http@8081
CMD ["/sbin/init"]
"""

# the same with nftables, for the firewall ump installs
DOCKERFILE_UMP = """\
FROM {image}
RUN apt-get update \\
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nftables \\
 && rm -rf /var/lib/apt/lists/*
"""

# as ump's installer writes it (install/install.sh, nft_ruleset), firewall default
UMP_RULESET = """\
#!/usr/sbin/nft -f
# written by UMP from the profile's firewall section; nft -f after editing
flush ruleset
table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    iif lo accept
    ct state established,related accept
    ct state invalid drop
    ip protocol icmp accept
    meta l4proto 58 accept
    tcp dport 22 accept
  }
  chain forward {
    type filter hook forward priority 0; policy accept;
    ct state established,related accept
    ct state invalid drop
    iifname { "eth0" } ct state new jump forward-in
  }
  chain forward-in {
    meta l4proto tcp ct original proto-dst 22 accept
    drop
  }
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
"""

# nftables.service as Arch Linux and CachyOS ship it (nftables 1:1.1.7), for
# web-01: a oneshot without RemainAfterExit, ExecReload or ExecStop. nft in
# /usr/sbin, as on Debian; on Arch /usr/sbin is /usr/bin.
ARCH_UNIT = """\
[Unit]
Description=Netfilter Tables
Documentation=man:nft(8)
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables.conf

[Install]
WantedBy=multi-user.target
"""

HOST = """\
plugin: ofzhur.ansible.host
groups: [common]
vars:
  ansible_host: 127.0.0.1
  ansible_port: {port}
  ump_admin: ump
  ansible_ssh_private_key_file: {dir}/ump
  ansible_ssh_common_args: -o UserKnownHostsFile={dir}/known_hosts -o IdentitiesOnly=yes
"""

FIREWALL = """\
firewall_backend: {backend}
firewall_rules:
  - proto: tcp
    port: 8080
    hosts: web-01
    comment: http
"""

# Docker's way through db-01, in short: a network namespace behind a veth
# pair, forwarding on, masquerade and a forward chain, policy drop, in a
# table of its own.
FOREIGN = """\
table ip foreign {
  chain forward {
    type filter hook forward priority 0; policy drop;
    iifname "veth-foreign" accept
    oifname "veth-foreign" ct state established,related accept
  }
  chain postrouting {
    type nat hook postrouting priority 100;
    ip saddr 10.231.0.0/24 oifname != "veth-foreign" masquerade
  }
}
"""

NAMESPACE = ('ip netns add foreign'
             ' && ip link add veth-foreign type veth peer name eth0 netns foreign'
             ' && ip address add 10.231.0.1/24 dev veth-foreign && ip link set veth-foreign up'
             ' && ip -n foreign address add 10.231.0.2/24 dev eth0 && ip -n foreign link set eth0 up'
             ' && ip -n foreign route add default via 10.231.0.1'
             ' && sysctl -qw net.ipv4.ip_forward=1')

# Docker's chain in the table filter, in short: jumped to from FORWARD,
# whose policy Docker sets to drop.
DOCKER_CHAIN = ('iptables -w -N DOCKER-TEST'
                ' && iptables -w -A DOCKER-TEST -i veth-foreign -j ACCEPT'
                ' && iptables -w -A DOCKER-TEST -o veth-foreign -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT'
                ' && iptables -w -A FORWARD -j DOCKER-TEST && iptables -w -P FORWARD DROP')


# The unit 0.4.0 wrote: the whole table filter, restored from rules.v4 and
# rules.v6.
OLD_UNIT = """\
# Managed by Ansible: ofzhur.ansible.firewall. Changes here are overwritten.
# The firewall's iptables rules, loaded before the network comes up. No
# ExecStop: stopping the unit leaves them in place.
[Unit]
Description=Firewall (iptables, ofzhur.ansible.firewall)
Wants=network-pre.target
Before=network-pre.target shutdown.target
Conflicts=shutdown.target
DefaultDependencies=no

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/iptables-restore /etc/iptables/rules.v4
ExecStart=/usr/sbin/ip6tables-restore /etc/iptables/rules.v6
ExecReload=/usr/sbin/iptables-restore /etc/iptables/rules.v4
ExecReload=/usr/sbin/ip6tables-restore /etc/iptables/rules.v6

[Install]
WantedBy=sysinit.target
"""


def old_rules(family):
    """The rules 0.4.0 wrote for db-01: the whole table filter, the role's rules right in INPUT."""
    command = 'iptables' if family == 4 else 'ip6tables'
    icmp6 = ''.join(f'-A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type {t} -j ACCEPT\n' for t in (1, 2, 3, 4, 130, 134, 135, 136))
    echo = '-p icmp -m icmp --icmp-type 8' if family == 4 else '-p ipv6-icmp -m icmp6 --icmpv6-type 128'
    return ('# Managed by Ansible: ofzhur.ansible.firewall. Changes here are overwritten.\n'
            f'# {command}-restore /etc/iptables/rules.v{family} applies it; ofzhur-iptables.service loads it at boot.\n'
            '*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT ACCEPT [0:0]\n'
            '-A INPUT -i lo -j ACCEPT\n'
            '-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT\n'
            '-A INPUT -m conntrack --ctstate INVALID -j DROP\n'
            + (icmp6 if family == 6 else '')
            + f'-A INPUT {echo} -j ACCEPT\n'
            '-A INPUT -p tcp -m tcp --dport 22 -m comment --comment "ssh" -j ACCEPT\n'
            'COMMIT\n')


HOSTS = ('web-01', 'db-01')
PORTS = ('22', '8080', '8081')

# The IPv6 addresses on the network of the test (eth1; the client's eth0).
ADDRESS6 = {'web-01': 'fd6f:7a68::1', 'db-01': 'fd6f:7a68::2', 'client': 'fd6f:7a68::3'}


class Scenario:
    """Servers as ump leaves them; the firewall applied, announced to, switched, step by step."""

    BASE = None

    @classmethod
    def setUpClass(cls):
        if not have_docker():
            raise unittest.SkipTest('Docker is not available')
        tag = cls.BASE.replace(':', '-')
        image = f'ofzhur-test-firewall:{tag}'
        docker('build', '-q', '-t', image, '-', input=DOCKERFILE.format(base=cls.BASE))
        docker('build', '-q', '-t', f'{image}-ump', '-', input=DOCKERFILE_UMP.format(image=image))

        cls.infra = Infra({'playbooks/firewall.yml': PLAYBOOK, 'playbooks/announce.yml': ANNOUNCE})
        cls.addClassCleanup(cls.infra.close)
        d = cls.infra.dir
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'ump@test', '-f', f'{d}/ump'], check=True)
        with open(f'{d}/ump.pub') as f:
            key = f.read().strip()

        cls.names = {host: f'ofzhur-test-firewall-{tag}-{host}' for host in (*HOSTS, 'client')}
        cls.network = f'ofzhur-test-firewall-{tag}'
        for name in cls.names.values():
            docker('rm', '-f', name, check=False)
        docker('network', 'rm', cls.network, check=False)
        docker('network', 'create', cls.network)
        cls.addClassCleanup(docker, 'network', 'rm', cls.network, check=False)
        for host in HOSTS:
            name = cls.names[host]
            cls.addClassCleanup(docker, 'rm', '-f', name, check=False)
            docker('run', '-d', '--name', name, '--hostname', host, '--privileged', '--cgroupns=private',
                   '--tmpfs', '/run', '--tmpfs', '/run/lock',
                   *[a for p in PORTS for a in ('-p', f'127.0.0.1::{p}')],
                   f'{image}-ump' if host == 'db-01' else image)
            docker('network', 'connect', cls.network, name)
            docker('exec', '-i', name, 'sh', '-c',
                   'install -d -m 700 -o ump -g ump /home/ump/.ssh'
                   ' && cat > /home/ump/.ssh/authorized_keys'
                   ' && chown ump:ump /home/ump/.ssh/authorized_keys'
                   ' && chmod 600 /home/ump/.ssh/authorized_keys',
                   input=key + '\n')
        cls.addClassCleanup(docker, 'rm', '-f', cls.names['client'], check=False)
        docker('run', '-d', '--name', cls.names['client'], '--privileged', '--network', cls.network, image,
               'sleep', 'infinity')
        docker('exec', '-i', cls.names['db-01'], 'sh', '-c',
               'cat > /etc/nftables.conf && chmod 755 /etc/nftables.conf && systemctl enable --now nftables',
               input=UMP_RULESET)
        docker('exec', '-i', cls.names['web-01'], 'sh', '-c',
               'cat > /etc/systemd/system/nftables.service && systemctl daemon-reload', input=ARCH_UNIT)
        cls.ready()

    @classmethod
    def ready(cls):
        """Host files with the ports Docker published; every host reachable over SSH."""
        cls.ports = {}
        for host in HOSTS:
            name = cls.names[host]
            cls.ports[host] = {p: docker('port', name, f'{p}/tcp').stdout.split()[0].rsplit(':', 1)[1] for p in PORTS}
            cls.infra.write(f'inventory/hosts/{host}.yml', HOST.format(port=cls.ports[host]['22'], dir=cls.infra.dir))
        for _ in range(60):
            r = cls.infra.run('ansible', 'all', '-m', 'ansible.builtin.ping', *AS_UMP)
            if r.returncode == 0:
                break
            time.sleep(1)
        else:
            raise AssertionError(f'the containers are not reachable over SSH:\n{r.stdout}{r.stderr}')

    def firewall(self, backend='nftables'):
        self.infra.write('inventory/group_vars/common/firewall.yml', FIREWALL.format(backend=backend))

    def play(self, *args, playbook='playbooks/firewall.yml'):
        r = self.infra.run('ansible-playbook', playbook, *AS_UMP, *args)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return recap(r.stdout)

    def refused(self, *args, playbook='playbooks/firewall.yml'):
        r = self.infra.run('ansible-playbook', playbook, *AS_UMP, *args)
        self.assertNotEqual(r.returncode, 0, r.stdout)
        return ' '.join(r.stdout.split())

    def announcement(self, host, name, rules, interfaces=None):
        return ('-e', json.dumps({'target': host, 'announcement': {
            'name': name, 'rules': rules, **({'interfaces': interfaces} if interfaces is not None else {})}}))

    def announce(self, host, name, rules, interfaces=None):
        return self.play(*self.announcement(host, name, rules, interfaces), playbook='playbooks/announce.yml')[host]

    def sh(self, host, command):
        return docker('exec', self.names[host], 'sh', '-c', command, check=False)

    def out(self, host, command):
        r = self.sh(host, command)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def tables(self, host):
        return self.out(host, 'nft list tables').splitlines()

    def input(self, host):
        return self.out(host, 'nft list chain inet ofzhur input')

    def assertSSH(self, *hosts):
        """A new SSH connection (none of Ansible's) gets in."""
        d = self.infra.dir
        for host in hosts or HOSTS:
            r = subprocess.run(['ssh', '-F', '/dev/null', '-o', 'ControlPath=none', '-o', 'BatchMode=yes',
                                '-o', 'ConnectTimeout=10', '-o', 'IdentitiesOnly=yes', '-i', f'{d}/ump',
                                '-o', f'UserKnownHostsFile={d}/known_hosts', '-o', 'StrictHostKeyChecking=accept-new',
                                '-p', self.ports[host]['22'],
                                'ump@127.0.0.1', 'true'], capture_output=True, text=True, timeout=60)
            self.assertEqual(r.returncode, 0, f'SSH to {host}: {r.stderr}')

    def http(self, host, port):
        """Whether HTTP on the port gets through; Docker accepts the connection either way."""
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(f'http://127.0.0.1:{self.ports[host][port]}/', timeout=3) as r:
                return r.read() == b'ok\n'
        except Exception:
            return False

    def link(self):
        """The addresses on the network of the test, IPv6 set by hand (Docker restarts drop them)."""
        self.address = {}
        for host, name in self.names.items():
            dev = 'eth0' if host == 'client' else 'eth1'
            self.out(host, f'sysctl -qw net.ipv6.conf.{dev}.disable_ipv6=0'
                           f' && ip -6 address replace {ADDRESS6[host]}/64 dev {dev} nodad')
            networks = json.loads(docker('inspect', '-f', '{{json .NetworkSettings.Networks}}', name).stdout)
            self.address[host] = {4: networks[self.network]['IPAddress'], 6: ADDRESS6[host]}

    def connects(self, source, host, port, family=4):
        """Whether a new TCP connection from source gets to the port of host on the network of the test."""
        r = self.sh(source, f'python3 -c \'import socket; socket.create_connection(("{self.address[host][family]}",'
                            f' {port}), timeout=2)\'')
        return r.returncode == 0

    def pings(self, source, host, family=4):
        return self.sh(source, f'ping -c 1 -W 2 {self.address[host][family]}').returncode == 0

    def assertUnchanged(self, counts):
        for host in HOSTS:
            self.assertEqual(counts[host]['changed'], 0, host)

    def forwarding(self):
        """Docker's way through db-01, built where missing (a restart drops it)."""
        self.link()
        if self.sh('db-01', 'ip netns list | grep -qw foreign').returncode:
            self.out('db-01', NAMESPACE)
        docker('exec', '-i', self.names['db-01'], 'sh', '-c', 'nft list table ip foreign >/dev/null 2>&1 || nft -f -',
               input=FOREIGN)

    def forwards(self):
        """Whether a new connection from the namespace behind db-01 gets to HTTP on web-01, forwarded."""
        return self.sh('db-01', 'ip netns exec foreign python3 -c \'import socket; socket.create_connection('
                                f'("{self.address["web-01"][4]}", 8080), timeout=2)\'').returncode == 0

    def assertDocker(self):
        """Docker's chain on db-01, FORWARD dropping but for it, and its way through."""
        self.assertEqual(self.out('db-01', 'iptables -S FORWARD'), '-P FORWARD DROP\n-A FORWARD -j DOCKER-TEST\n')
        self.assertEqual(len(self.out('db-01', 'iptables -S DOCKER-TEST').splitlines()), 3)
        self.assertTrue(self.forwards())

    def old_layout(self, host):
        """The host as 0.4.0 left it with iptables: its rules loaded, its files and its unit, none of this layout's."""
        for family, command in ((4, 'iptables'), (6, 'ip6tables')):
            docker('exec', '-i', self.names[host], 'sh', '-c', f'tee /etc/iptables/rules.v{family} | {command}-restore',
                   input=old_rules(family))
        docker('exec', '-i', self.names[host], 'sh', '-c',
               'cat > /etc/systemd/system/ofzhur-iptables.service && systemctl daemon-reload'
               ' && rm -f /etc/iptables/ofzhur-firewall.v4 /etc/iptables/ofzhur-firewall.v6', input=OLD_UNIT)
        self.assertTrue(self.out(host, 'iptables -S INPUT').startswith('-P INPUT DROP\n-A INPUT -i lo -j ACCEPT\n'))

    def assertNftables(self):
        for host in HOSTS:
            # the role's table, ump's gone; the tables of other software are theirs
            self.assertEqual([t for t in self.tables(host) if t.startswith('table inet ')], ['table inet ofzhur'], host)
            self.assertEqual(self.out(host, 'head -2 /etc/nftables.conf'),
                             '#!/usr/sbin/nft -f\n# Managed by Ansible: ofzhur.ansible.firewall. Changes here are overwritten.\n')
            self.assertEqual(self.out(host, 'stat -c "%a %U %G" /etc/nftables.conf'), '755 root root\n')
            self.assertEqual(self.out(host, 'systemctl is-enabled nftables; systemctl is-active nftables'), 'enabled\nactive\n')
            table = self.out(host, 'nft list table inet ofzhur')
            for line in ('type filter hook input priority filter; policy drop;',
                         'iif "lo" accept', 'ct state established,related accept', 'ct state invalid drop',
                         'icmp type echo-request accept', 'icmpv6 type echo-request accept',
                         'tcp dport 22 accept comment "ssh"'):
                self.assertIn(line, table, host)
            self.assertIn('nd-neighbor-solicit', table)
            # input alone: no forward chain to drop what others let through, no output chain
            self.assertNotIn('hook forward', table, host)
            self.assertNotIn('hook output', table, host)
            # stopping nftables.service deletes the role's table alone; Arch's unit stays active once loaded
            dropin = '/etc/systemd/system/nftables.service.d/ofzhur-firewall.conf'
            self.assertEqual(self.out(host, f'stat -c "%a %U %G" {dropin}'), '644 root root\n')
            self.assertEqual(self.out(host, f"grep -v '^#' {dropin}"),
                             '[Service]\nRemainAfterExit=yes\nExecReload=\nExecReload=/usr/sbin/nft -f /etc/nftables.conf\n'
                             'ExecStop=\nExecStop=-/usr/sbin/nft delete table inet ofzhur\n')
            unit = self.out(host, 'systemctl show -p RemainAfterExit -p ExecReload -p ExecStop -p NeedDaemonReload nftables')
            self.assertIn('RemainAfterExit=yes', unit)
            self.assertIn('argv[]=/usr/sbin/nft delete table inet ofzhur ; ignore_errors=yes', unit)
            self.assertIn('argv[]=/usr/sbin/nft -f /etc/nftables.conf', unit)
            self.assertNotIn('flush ruleset', unit)
            self.assertIn('NeedDaemonReload=no', unit)
            self.assertApplied(host)
        self.assertIn('tcp dport 8080 accept comment "http"', self.input('web-01'))
        self.assertNotIn('8080', self.input('db-01'))

    def assertIptables(self, host):
        """The role's chain, ending in its drop, jumped to first from INPUT; INPUT's policy untouched."""
        for command in ('iptables', 'ip6tables'):
            self.assertEqual(self.out(host, f'{command} -S INPUT'), '-P INPUT ACCEPT\n-A INPUT -j OFZHUR-INPUT\n', host)
            chain = self.out(host, f'{command} -S OFZHUR-INPUT')
            self.assertIn('-A OFZHUR-INPUT -p tcp -m tcp --dport 22 -m comment --comment ssh -j ACCEPT', chain)
            self.assertTrue(chain.endswith('\n-A OFZHUR-INPUT -j DROP\n'), chain)
            self.assertEqual(self.out(host, f'grep -c "^:" /etc/iptables/ofzhur-firewall.v{4 if command == "iptables" else 6}'),
                             '1\n')
        self.assertIn('--icmpv6-type 135', self.out(host, 'ip6tables -S OFZHUR-INPUT'))
        # the role's unit loaded, refilling the chain alone
        unit = self.out(host, 'systemctl show -p ExecReload -p NeedDaemonReload ofzhur-iptables')
        self.assertIn('argv[]=/usr/sbin/iptables-restore -w --noflush /etc/iptables/ofzhur-firewall.v4 ;', unit)
        self.assertIn('NeedDaemonReload=no', unit)
        self.assertApplied(host, 'iptables')

    def assertApplied(self, host, backend='nftables'):
        """The stamp names the files in place."""
        files = ['/etc/nftables.conf'] if backend == 'nftables' else ['/etc/iptables/ofzhur-firewall.v4',
                                                                     '/etc/iptables/ofzhur-firewall.v6']
        sums = [line.split()[0] for line in self.out(host, 'sha1sum ' + ' '.join(files)).splitlines()]
        self.assertEqual(self.out(host, 'cat /etc/ofzhur/firewall.applied'), ' '.join([backend, *sums]) + '\n')
        self.assertEqual(self.out(host, 'stat -c "%a %U %G" /etc/ofzhur/firewall.applied'), '644 root root\n')

    def interfaces(self, backend):
        """The policy of an interface: on eth1 of db-01, new connections from the client alone."""
        self.link()
        a = self.address
        rules = [{'proto': 'tcp', 'port': 8081},
                 {'proto': 'tcp', 'port': 8080, 'interface': 'eth1', 'sources': [a['web-01'][4], a['web-01'][6]],
                  'comment': 'from web-01'}]
        policy = {'eth1': {'accept_from': [a['client'][4], a['client'][6]]}}
        self.assertGreater(self.announce('db-01', 'app', rules, policy)['changed'], 0)
        self.assertEqual(json.loads(self.out('db-01', 'cat /etc/ofzhur/firewall.d/app.json')),
                         {'name': 'app', 'rules': rules, 'interfaces': policy})
        if backend == 'nftables':
            chain = self.input('db-01')
            for line in (f'iifname "eth1" ip saddr {a["client"][4]} accept comment "app"',
                         f'iifname "eth1" ip6 saddr {a["client"][6]} accept comment "app"',
                         f'iifname "eth1" ip saddr {a["web-01"][4]} tcp dport 8080 accept comment "app: from web-01"'):
                self.assertIn(line, chain)
            # before ICMP echo, SSH and the rules for any interface
            self.assertLess(chain.index('iifname "eth1" drop'), chain.index('icmp type echo-request accept'))
            self.assertLess(chain.index('iifname "eth1" drop'), chain.index('tcp dport 22 accept'))
            self.assertLess(chain.index('iifname "eth1" drop'), chain.index('tcp dport 8081 accept'))
        else:
            for command, family in (('iptables', 4), ('ip6tables', 6)):
                rules_ = self.out('db-01', f'{command} -S OFZHUR-INPUT')
                prefix = '/32' if family == 4 else '/128'
                self.assertIn(f'-A OFZHUR-INPUT -s {a["client"][family]}{prefix} -i eth1 -m comment --comment app -j ACCEPT',
                              rules_)
                self.assertLess(rules_.index('-A OFZHUR-INPUT -i eth1 -j DROP'), rules_.index('--dport 22 '))
        for family in (4, 6):
            with self.subTest(family=family):
                # from the client: anything, ICMP too
                self.assertTrue(self.connects('client', 'db-01', 8081, family))
                self.assertTrue(self.connects('client', 'db-01', 22, family))
                self.assertTrue(self.pings('client', 'db-01', family))
                # from web-01: its rule alone; neither SSH, ICMP echo nor the rules for any interface
                self.assertTrue(self.connects('web-01', 'db-01', 8080, family))
                self.assertFalse(self.connects('web-01', 'db-01', 8081, family))
                self.assertFalse(self.connects('web-01', 'db-01', 22, family))
                self.assertFalse(self.pings('web-01', 'db-01', family))
                # the answers to db-01's own connections
                self.assertTrue(self.connects('db-01', 'web-01', 8080, family))
                self.assertTrue(self.pings('db-01', 'web-01', family))
        # other interfaces as before: SSH and the port from anywhere, ICMP echo
        self.assertSSH()
        self.assertTrue(self.http('db-01', '8081'))
        eth0 = self.out('db-01', "ip -4 -o address show dev eth0 | awk '{ print $4 }'").split('/')[0]
        self.assertEqual(self.sh('web-01', f'ping -c 1 -W 2 {eth0}').returncode, 0)
        self.assertUnchanged(self.play())

        # a second announcement for eth1, with no rules: both let in
        self.announce('db-01', 'app.v2', [], {'eth1': {'accept_from': [a['web-01'][4]]}})
        self.assertTrue(self.connects('web-01', 'db-01', 8081, 4))
        self.assertTrue(self.pings('web-01', 'db-01', 4))
        self.assertFalse(self.connects('web-01', 'db-01', 8081, 6))
        self.assertTrue(self.connects('client', 'db-01', 8081, 4))
        self.announce('db-01', 'app.v2', [], {})
        self.assertNotEqual(self.sh('db-01', 'test -e /etc/ofzhur/firewall.d/app.v2.json').returncode, 0)
        self.assertFalse(self.connects('web-01', 'db-01', 8081, 4))

        # withdrawn: eth1 like any interface
        self.announce('db-01', 'app', [])
        self.assertTrue(self.connects('web-01', 'db-01', 22, 4))
        self.assertTrue(self.pings('web-01', 'db-01', 6))
        self.assertFalse(self.connects('client', 'db-01', 8081, 4))
        self.assertUnchanged(self.play())

    def test_00_check(self):
        # check mode on new servers: nothing installed, ump's firewall untouched
        self.firewall()
        counts = self.play('--check')
        self.assertEqual(sorted(counts), sorted(HOSTS))
        self.assertNotEqual(self.sh('web-01', 'command -v nft').returncode, 0)
        self.assertEqual(self.tables('db-01'), ['table inet filter'])
        self.assertIn('written by UMP', self.out('db-01', 'cat /etc/nftables.conf'))
        self.assertSSH()

    def test_01_announce_first(self):
        # an announcement where the firewall is not in place yet waits for the role
        counts = self.announce('web-01', 'early', [{'proto': 'udp', 'port': 9999}])
        self.assertEqual(counts['changed'], 2)
        self.assertEqual(self.out('web-01', 'stat -c "%a %U %G" /etc/ofzhur/firewall.d/early.json'), '644 root root\n')
        self.assertNotEqual(self.sh('web-01', 'command -v nft').returncode, 0)

    def test_02_run(self):
        self.play()
        self.assertNftables()
        # ump's table is gone, and the announcement is in
        self.assertNotIn('ct original proto-dst', self.out('db-01', 'nft list ruleset'))
        self.assertIn('udp dport 9999 accept comment "early"', self.input('web-01'))
        self.assertSSH()
        self.assertTrue(self.http('web-01', '8080'))
        self.assertFalse(self.http('db-01', '8080'))
        self.assertFalse(self.http('web-01', '8081'))

    def test_03_again(self):
        self.assertUnchanged(self.play())
        self.assertUnchanged(self.play('--check'))

    def test_04_announce(self):
        counts = self.announce('db-01', 'app', [{'proto': 'tcp', 'port': [8081, '9000-9100'], 'comment': 'the app'}])
        self.assertGreater(counts['changed'], 0)
        self.assertEqual(self.out('db-01', 'stat -c "%a %U %G" /etc/ofzhur/firewall.d/app.json'), '644 root root\n')
        self.assertEqual(json.loads(self.out('db-01', 'cat /etc/ofzhur/firewall.d/app.json')), {
            'name': 'app', 'rules': [{'proto': 'tcp', 'port': [8081, '9000-9100'], 'comment': 'the app'}]})
        self.assertIn('tcp dport { 8081, 9000-9100 } accept comment "app: the app"', self.input('db-01'))
        self.assertTrue(self.http('db-01', '8081'))
        self.assertSSH()
        self.assertEqual(self.announce('db-01', 'app', [{'proto': 'tcp', 'port': [8081, '9000-9100'], 'comment': 'the app'}])['changed'], 0)
        self.assertUnchanged(self.play())

    def test_05_withdraw(self):
        self.announce('db-01', 'app', [])
        self.announce('web-01', 'early', [])
        self.assertNotEqual(self.sh('db-01', 'test -e /etc/ofzhur/firewall.d/app.json').returncode, 0)
        self.assertNotIn('8081', self.input('db-01'))
        self.assertNotIn('9999', self.input('web-01'))
        self.assertFalse(self.http('db-01', '8081'))
        self.assertSSH()
        self.assertUnchanged(self.play())

    def test_06_interfaces(self):
        self.interfaces('nftables')

    def test_07_refused(self):
        before = {host: self.out(host, 'nft list ruleset') for host in HOSTS}
        out = self.refused('-e', 'firewall_ssh_port=2222')
        self.assertIn('firewall: the SSH rule, port 2222 from anywhere, would shut out this connection', out)
        out = self.refused('-e', '{"firewall_ssh_sources": ["203.0.113.0/24", "2001:db8::/32"]}')
        self.assertIn('port 22 from 203.0.113.0/24, 2001:db8::/32, would shut out this connection', out)
        self.assertIn('firewall: no SSH', self.refused('-e', '{"firewall_ssh_sources": []}'))
        # an announcement that is none of the role's, or with a rule that would not be checked otherwise
        self.out('db-01', 'echo \'{"name": "other", "rules": []}\' > /etc/ofzhur/firewall.d/bad.json')
        self.assertIn('/etc/ofzhur/firewall.d/bad.json is no announcement', self.refused('--limit', 'db-01'))
        self.out('db-01', 'echo \'{"name": "bad", "rules": [{"proto": "tcp", "port": "22 accept"}]}\''
                          ' > /etc/ofzhur/firewall.d/bad.json')
        self.assertIn('/etc/ofzhur/firewall.d/bad.json rules[0]: port: a port', self.refused('--limit', 'db-01'))
        self.out('db-01', 'echo \'{"name": "bad", "rules": [], "interfaces": {"eth1": {"accept_from": ["::1;"]}}}\''
                          ' > /etc/ofzhur/firewall.d/bad.json')
        self.assertIn('/etc/ofzhur/firewall.d/bad.json interfaces.eth1: accept_from: ::1; is no address or network',
                      self.refused('--limit', 'db-01'))
        self.out('db-01', 'rm /etc/ofzhur/firewall.d/bad.json')
        # an interface policy that shuts out the connection the run uses (eth0), applied by the announcement
        self.link()
        out = self.refused(*self.announcement('db-01', 'lockout', [], {'eth0': {'accept_from': [self.address['client'][4]]}}),
                           playbook='playbooks/announce.yml')
        self.assertIn(f'firewall: the policy of eth0, accept_from {self.address["client"][4]}, would shut out this connection', out)
        self.announce('db-01', 'lockout', [])
        # a play variable the announcement would apply, and the role run without it would not
        self.infra.write('playbooks/announce-vars.yml', ANNOUNCE.replace('  tasks:', '  vars:\n    firewall_icmp: false\n  tasks:'))
        out = self.refused(*self.announcement('db-01', 'app', [{'proto': 'tcp', 'port': 8081}]),
                           playbook='playbooks/announce-vars.yml')
        self.assertIn('firewall: firewall_icmp of db-01 set outside the inventory', out)
        self.announce('db-01', 'app', [])
        for host in HOSTS:
            self.assertEqual(self.out(host, 'nft list ruleset'), before[host], host)
        # SSH from the networks the connection comes from
        self.play('-e', '{"firewall_ssh_sources": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]}')
        for host in HOSTS:
            self.assertIn('ip saddr 172.16.0.0/12 tcp dport 22 accept comment "ssh"', self.input(host))
            self.assertNotIn('\ttcp dport 22 accept', self.input(host))
        self.assertSSH()
        self.play()

    def test_08_retried(self):
        # a run cut short between the ruleset written and applied: the stamp is not the file's
        self.out('db-01', 'nft add rule inet ofzhur input tcp dport 9999 accept comment stale'
                          ' && echo nftables 0 > /etc/ofzhur/firewall.applied')
        counts = self.play()
        self.assertEqual((counts['db-01']['changed'], counts['web-01']['changed']), (2, 0))
        self.assertNotIn('stale', self.input('db-01'))
        self.assertNftables()
        self.assertUnchanged(self.play())

    def test_09_forwarding(self):
        # Docker's way through db-01 passes: the role has no forward chain and leaves other tables alone
        self.forwarding()
        self.assertTrue(self.forwards())
        self.assertUnchanged(self.play())
        self.assertTrue(self.forwards())
        # applied again (by an announcement), reloaded, restarted: the role's table replaced, the other one kept
        self.announce('db-01', 'app', [{'proto': 'tcp', 'port': 8081}])
        self.assertTrue(self.forwards())
        self.announce('db-01', 'app', [])
        for action in ('reload', 'restart'):
            with self.subTest(action):
                for host in HOSTS:
                    self.out(host, f'systemctl {action} nftables')
                self.assertIn('table ip foreign', self.tables('db-01'))
                self.assertTrue(self.forwards())
                self.assertNftables()
        # stopped: the role's table alone goes
        for host in HOSTS:
            self.out(host, 'systemctl stop nftables')
        self.assertEqual(self.tables('db-01'), ['table ip foreign'])
        self.assertNotIn('table inet ofzhur', self.tables('web-01'))
        self.assertTrue(self.forwards())
        for host in HOSTS:
            self.out(host, 'systemctl start nftables')
        self.assertNftables()
        self.assertSSH()
        self.assertUnchanged(self.play())
        # a run cut short with the drop-in written, not loaded: systemd has Debian's stop still; the next run loads it
        self.out('db-01', 'mv /etc/systemd/system/nftables.service.d/ofzhur-firewall.conf /root/ && systemctl daemon-reload'
                          ' && mv /root/ofzhur-firewall.conf /etc/systemd/system/nftables.service.d/')
        self.assertIn('flush ruleset', self.out('db-01', 'systemctl show -p ExecStop nftables'))
        self.assertUnchanged(self.play())
        self.out('db-01', 'systemctl restart nftables')
        self.assertIn('table ip foreign', self.tables('db-01'))
        self.assertTrue(self.forwards())
        self.assertNftables()

    def test_10_reboot(self):
        # nftables.service loads the ruleset at boot, Debian's on db-01, Arch's on web-01
        for host in HOSTS:
            docker('restart', self.names[host])
        self.ready()
        self.assertNftables()
        self.assertSSH()
        self.assertUnchanged(self.play())

    def test_11_iptables(self):
        # db-01 as ump leaves a server: its ruleset, Debian's nftables.service without the role's drop-in, whose
        # stop would flush the iptables rules too; Docker's way through it again (the restart dropped it): its
        # table stays
        docker('exec', '-i', self.names['db-01'], 'sh', '-c',
               'cat > /etc/nftables.conf && rm -r /etc/systemd/system/nftables.service.d && systemctl daemon-reload'
               ' && nft -f /etc/nftables.conf', input=UMP_RULESET)
        self.assertEqual(self.tables('db-01'), ['table inet filter'])
        self.forwarding()
        self.firewall('iptables')
        self.play()
        self.assertIn('table ip foreign', self.tables('db-01'))
        self.assertTrue(self.forwards())
        for host in HOSTS:
            self.assertEqual([t for t in self.tables(host) if 'inet' in t], [], host)
            self.assertNotEqual(self.sh(host, 'test -e /etc/nftables.conf').returncode, 0)
            self.assertNotEqual(self.sh(host, 'test -e /etc/systemd/system/nftables.service.d').returncode, 0)
            self.assertEqual(self.out(host, 'systemctl is-enabled nftables; systemctl is-active nftables; true'),
                             'disabled\ninactive\n')
            self.assertEqual(self.out(host, 'systemctl is-enabled ofzhur-iptables; systemctl is-active ofzhur-iptables'),
                             'enabled\nactive\n')
            self.assertIptables(host)
            for command in ('iptables', 'ip6tables'):
                self.assertEqual(self.out(host, f'{command} -S FORWARD'), '-P FORWARD ACCEPT\n')
        self.assertIn('--dport 8080 -m comment --comment http', self.out('web-01', 'iptables -S OFZHUR-INPUT'))
        self.assertNotIn('8080', self.out('db-01', 'iptables -S OFZHUR-INPUT'))
        self.assertSSH()
        self.assertTrue(self.http('web-01', '8080'))
        self.assertFalse(self.http('db-01', '8080'))
        self.assertUnchanged(self.play())
        # Docker's chain in the table filter, FORWARD dropping but for it: the role's runs and reloads keep it
        self.out('db-01', DOCKER_CHAIN)
        self.assertDocker()
        self.interfaces('iptables')
        self.assertDocker()
        self.out('db-01', 'systemctl reload ofzhur-iptables')
        self.assertDocker()
        self.assertIptables('db-01')
        # ofzhur-iptables.service loads them at boot
        docker('restart', self.names['db-01'])
        self.ready()
        self.assertIptables('db-01')
        self.assertSSH()
        self.assertUnchanged(self.play())

    def test_12_from_0_4_0(self):
        # the layout of 0.4.0, the role's rules right in INPUT, policies drop: one run puts the chain in place
        self.old_layout('db-01')
        self.assertSSH('db-01')
        self.assertGreater(self.play()['db-01']['changed'], 0)
        self.assertIptables('db-01')
        for command in ('iptables', 'ip6tables'):
            self.assertEqual(self.out('db-01', f'{command} -S FORWARD'), '-P FORWARD ACCEPT\n')
        # 0.4.0's files go: rules.v4 and rules.v6 are iptables-persistent's, restored whole
        for path in ('/etc/iptables/rules.v4', '/etc/iptables/rules.v6'):
            self.assertNotEqual(self.sh('db-01', f'test -e {path}').returncode, 0, path)
        self.out('db-01', 'systemctl reload ofzhur-iptables')
        self.assertIptables('db-01')
        self.assertSSH()
        self.assertUnchanged(self.play())
        # a run cut short: the files of this layout, the rules of 0.4.0
        for family, command in ((4, 'iptables'), (6, 'ip6tables')):
            docker('exec', '-i', self.names['db-01'], f'{command}-restore', input=old_rules(family))
        self.assertEqual(self.play()['db-01']['changed'], 1)
        self.assertIptables('db-01')
        self.assertSSH()
        self.assertUnchanged(self.play())
        # a run cut short with the unit written, not loaded: systemd has 0.4.0's still; the next run loads it
        docker('exec', '-i', self.names['db-01'], 'sh', '-c',
               'cp /etc/systemd/system/ofzhur-iptables.service /root/'
               ' && cat > /etc/systemd/system/ofzhur-iptables.service && systemctl daemon-reload'
               ' && cat /root/ofzhur-iptables.service > /etc/systemd/system/ofzhur-iptables.service', input=OLD_UNIT)
        self.assertIn('argv[]=/usr/sbin/iptables-restore /etc/iptables/rules.v4 ;',
                      self.out('db-01', 'systemctl show -p ExecReload ofzhur-iptables'))
        self.assertUnchanged(self.play())
        self.out('db-01', 'systemctl reload ofzhur-iptables')
        self.assertIptables('db-01')

    def test_13_without_ipv6(self):
        # a kernel booted with ipv6.disable=1 has no /proc/sys/net/ipv6, so no IPv6 rules: hidden here
        self.out('db-01', 'ip6tables -w -D INPUT -j OFZHUR-INPUT && ip6tables -w -F OFZHUR-INPUT'
                          ' && ip6tables -w -X OFZHUR-INPUT && mount -t tmpfs -o size=1m none /proc/sys/net')
        try:
            self.assertGreater(self.announce('db-01', 'app', [{'proto': 'tcp', 'port': 8081}])['changed'], 0)
            self.assertIn('--dport 8081', self.out('db-01', 'iptables -S OFZHUR-INPUT'))
            self.assertIn('--dport 8081', self.out('db-01', 'cat /etc/iptables/ofzhur-firewall.v6'))
            self.assertNotEqual(self.sh('db-01', 'ip6tables -S OFZHUR-INPUT').returncode, 0)
            self.out('db-01', 'systemctl reload ofzhur-iptables')
            self.assertNotEqual(self.sh('db-01', 'ip6tables -S OFZHUR-INPUT').returncode, 0)
            self.assertTrue(self.http('db-01', '8081'))
            self.assertSSH()
            self.assertUnchanged(self.play())
        finally:
            self.sh('db-01', 'umount /proc/sys/net')
        # IPv6 back: its rules are put in place
        self.assertEqual(self.play()['db-01']['changed'], 1)
        self.assertIptables('db-01')
        self.announce('db-01', 'app', [])
        self.assertUnchanged(self.play())

    def test_14_back(self):
        # Docker's way and chain on db-01 again (the restart, then 0.4.0's table, dropped them): they stay; web-01
        # as 0.4.0 left it (its rules let in no HTTP: the way through is checked before)
        self.forwarding()
        self.out('db-01', 'iptables -S DOCKER-TEST >/dev/null 2>&1 || { ' + DOCKER_CHAIN + '; }')
        self.assertDocker()
        self.old_layout('web-01')
        self.firewall()
        self.play()
        self.assertNftables()
        self.assertIn('table ip foreign', self.tables('db-01'))
        self.assertDocker()
        for host in HOSTS:
            for path in ('/etc/systemd/system/ofzhur-iptables.service', '/etc/iptables/ofzhur-firewall.v4',
                         '/etc/iptables/ofzhur-firewall.v6', '/etc/iptables/rules.v4', '/etc/iptables/rules.v6'):
                self.assertNotEqual(self.sh(host, f'test -e {path}').returncode, 0, path)
        for command in ('iptables', 'ip6tables'):
            # on db-01, the role's chain alone goes
            self.assertEqual(self.out('db-01', f'{command} -S INPUT'), '-P INPUT ACCEPT\n')
            self.assertNotEqual(self.sh('db-01', f'{command} -S OFZHUR-INPUT').returncode, 0)
            # on web-01, 0.4.0's whole table is emptied, as 0.4.0 did
            self.assertEqual(self.out('web-01', f'{command} -S'), '-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n')
        self.assertSSH()
        self.assertTrue(self.http('web-01', '8080'))
        self.assertUnchanged(self.play())


class Ubuntu(Scenario, unittest.TestCase):
    BASE = 'ubuntu:24.04'


class Debian(Scenario, unittest.TestCase):
    BASE = 'debian:trixie'


if __name__ == '__main__':
    unittest.main()
