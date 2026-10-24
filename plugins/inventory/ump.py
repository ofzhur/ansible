# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

from __future__ import annotations

DOCUMENTATION = r"""
name: ump
short_description: The servers ump installed, from ump itself
version_added: 0.3.0
author: Oleg Zhurko (@ofzhur)
description:
  - Runs C(ump server list -o ansible) and takes the hosts, groups and variables it prints. A server
    ump installed gets the same as from its host file (see C(ofzhur.ansible.host)).
  - The configuration is a YAML file whose O(plugin) is C(ofzhur.ansible.ump), such as C(inventory/ump.yml).
  - Values are data, never templates, as in host files.
  - One source per host. A host also defined by a host file fails, and so does a host with the C(ump_ref)
    of another (one server under two names).
  - Fails when ump fails (also when it could not list one of its accounts) or prints anything but an
    inventory, and on an unknown key in the configuration. What else ump says, such as a server it left
    out, is a warning; what it took from its cache shows with C(-v).
requirements:
  - ump, with its state, where Ansible runs.
options:
  plugin:
    description: Marks the file as a configuration of this plugin.
    type: str
    required: true
    choices: [ofzhur.ansible.ump]
  command:
    description: The ump program, a name looked up in C(PATH) or a path.
    type: str
    default: ump
  arguments:
    description: Arguments added to C(ump server list -o ansible), such as C(--account) and its value.
    type: list
    elements: str
    default: []
  cached:
    description: Passes C(--cached), the last listing from ump's cache however old; no provider API is called.
    type: bool
    default: false
  timeout:
    description: Seconds ump has to answer; then it is stopped and the inventory fails.
    type: int
    default: 120
"""

EXAMPLES = r"""
# inventory/ump.yml: every server ump installed
plugin: ofzhur.ansible.ump
---
# inventory/ump.yml: the servers of one account, as ump last listed them
plugin: ofzhur.ansible.ump
arguments: [--account, main]
cached: true
"""

import json
import shlex
import subprocess
from collections.abc import Mapping

from ansible.errors import AnsibleParserError
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.utils.display import Display
from ansible.utils.vars import isidentifier

# the rules of host files: the same names, values as data
from ansible_collections.ofzhur.ansible.plugins.inventory.host import GROUP_NAME, HOST_NAME, add_host, as_data, check_host

KEYS = ('plugin', 'command', 'arguments', 'cached', 'timeout')
GROUP_KEYS = ('hosts', 'children', 'vars')

display = Display()


class InventoryModule(BaseInventoryPlugin):

    NAME = 'ofzhur.ansible.ump'

    def verify_file(self, path):
        if not (super().verify_file(path) and path.endswith(('.yml', '.yaml'))):
            return False
        try:
            data = DataLoader().load_from_file(path)
        except Exception:
            return False
        return isinstance(data, Mapping) and data.get('plugin') in self._names()

    def _names(self):
        return getattr(self, '_redirected_names', None) or [self.NAME]

    def parse(self, inventory, loader, path, cache=True):
        super().parse(inventory, loader, path, cache)

        config = self._read_config_data(path)
        unknown = sorted(str(k) for k in config if k not in KEYS)
        if unknown:
            raise AnsibleParserError(f'{path}: unknown key(s) {", ".join(unknown)}; the configuration has {", ".join(KEYS)}')
        # Ansible takes any other value for false
        if not isinstance(config.get('cached', False), bool):
            raise AnsibleParserError(f'{path}: cached must be true or false')

        argv = [self.get_option('command'), 'server', 'list', '-o', 'ansible']
        if self.get_option('cached'):
            argv.append('--cached')
        argv += self.get_option('arguments')
        hosts, groups = self._read(path, argv)
        self._add(path, hosts, groups)

    def _read(self, path, argv):
        """Runs ump and returns the hosts with their variables and the groups, checked."""
        cmd = shlex.join(argv)
        timeout = self.get_option('timeout')
        try:
            p = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout, check=False)
        except FileNotFoundError:
            raise AnsibleParserError(f'{path}: {argv[0]} not found; install ump or set command') from None
        except subprocess.TimeoutExpired:
            raise AnsibleParserError(f'{path}: {cmd} did not finish in {timeout} seconds') from None
        except OSError as e:
            raise AnsibleParserError(f'{path}: {cmd}: {e}') from e
        stderr = p.stderr.decode(errors='replace').strip()
        if p.returncode:
            raise AnsibleParserError(f'{path}: {cmd} failed (exit status {p.returncode})' + (f':\n{stderr}' if stderr else ''))
        # what ump took from its cache is information; anything else is a note, such as a server left out
        lines = stderr.splitlines()
        info = [line for line in lines if line.startswith('From cache:')]
        notes = [line for line in lines if line.strip() and not line.startswith('From cache:')]
        if info:
            display.v(f'{path}: {cmd}:\n' + '\n'.join(info))
        if notes:
            display.warning(f'{path}: {cmd}:\n' + '\n'.join(notes))

        def invalid(why):
            return AnsibleParserError(f'{path}: {cmd} printed no inventory: {why}')

        try:
            data = json.loads(p.stdout)
        except ValueError as e:
            raise invalid(f'not JSON ({e})') from None
        if not isinstance(data, Mapping):
            raise invalid('not a JSON object')

        meta = data.get('_meta', {})
        if not isinstance(meta, Mapping) or set(meta) - {'hostvars'}:
            raise invalid('_meta must have hostvars only')
        hosts = meta.get('hostvars', {})
        if not isinstance(hosts, Mapping):
            raise invalid('_meta.hostvars must be a mapping of hosts to variables')
        self._check_hosts(invalid, hosts)
        for host, hostvars in hosts.items():
            self._check_vars(invalid, f'the variables of {host}', hostvars)

        groups = {name: group for name, group in data.items() if name != '_meta'}
        bad = [str(g) for g in groups if not isinstance(g, str) or not GROUP_NAME.match(g)]
        if bad:
            raise invalid(f'invalid group name(s) {", ".join(bad)}')
        for name, group in groups.items():
            if not isinstance(group, Mapping):
                raise invalid(f'group {name} must be a mapping with {", ".join(GROUP_KEYS)}')
            unknown = sorted(str(k) for k in group if k not in GROUP_KEYS)
            if unknown:
                raise invalid(f'group {name}: unknown key(s) {", ".join(unknown)}')
            members = group.get('hosts', [])
            if not isinstance(members, list):
                raise invalid(f'group {name}: hosts must be a list of host names')
            self._check_hosts(invalid, members)
            children = group.get('children', [])
            if not isinstance(children, list):
                raise invalid(f'group {name}: children must be a list of group names')
            bad = [str(g) for g in children if not isinstance(g, str) or not GROUP_NAME.match(g)]
            if bad:
                raise invalid(f'group {name}: invalid group name(s) {", ".join(bad)}')
            self._check_vars(invalid, f'the variables of group {name}', group.get('vars', {}))
        return hosts, groups

    @staticmethod
    def _check_hosts(invalid, names):
        bad = [str(h) for h in names if not isinstance(h, str) or not HOST_NAME.match(h)]
        if bad:
            raise invalid(f'invalid host name(s) {", ".join(bad)}')

    @staticmethod
    def _check_vars(invalid, what, variables):
        if not isinstance(variables, Mapping):
            raise invalid(f'{what} must be a mapping of variable names to values')
        bad = sorted(str(k) for k in variables if not isinstance(k, str) or not isidentifier(k))
        if bad:
            raise invalid(f'{what}: invalid variable name(s) {", ".join(bad)}')

    def _add(self, path, hosts, groups):
        """Adds what _read checked; nothing when a host or its server (ump_ref) is already defined by a host
        file, or two hosts are one server."""
        names = set(hosts)
        for group in groups.values():
            names.update(group.get('hosts', []))
        # sorted, as Ansible reads the files of a host directory
        names = sorted(names)
        servers = {}
        for host in names:
            ref = hosts.get(host, {}).get('ump_ref')
            check_host(self.inventory, path, host, ref)
            if isinstance(ref, str):
                if ref in servers:
                    raise AnsibleParserError(f'{path}: host {host} has ump_ref {ref}, as has host {servers[ref]}:'
                                             ' one server, two hosts')
                servers[ref] = host

        for host in names:
            # host files of the same host or server fail on it, as on a second file
            add_host(self.inventory, path, host, hosts.get(host, {}).get('ump_ref'))
            for name, value in hosts.get(host, {}).items():
                self.inventory.set_variable(host, name, as_data(value))
        for name, group in groups.items():
            name = self.inventory.add_group(name)
            for child in group.get('children', []):
                child = self.inventory.add_group(child)
                # every group is under all; all as its parent too would lift it out of a static tree
                if name != 'all':
                    self.inventory.add_child(name, child)
            for host in sorted(group.get('hosts', [])):
                self.inventory.add_child(name, host)
            for var, value in group.get('vars', {}).items():
                self.inventory.set_variable(name, var, as_data(value))
