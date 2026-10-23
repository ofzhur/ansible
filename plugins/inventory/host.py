# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

from __future__ import annotations

DOCUMENTATION = r"""
name: host
short_description: One YAML file per host
version_added: 0.1.0
author: Oleg Zhurko (@ofzhur)
description:
  - Reads one host from a YAML file. The file name without its extension is the host name,
    O(groups) are the groups the host belongs to and O(vars) are its variables.
  - Meant for a directory with one file per server, such as C(inventory/hosts/) written by a
    provisioner (ump). Ansible reads every file of an inventory directory; this plugin takes the
    C(.yml) and C(.yaml) files whose O(plugin) is C(ofzhur.ansible.host).
  - Values are data, never templates. Templated values belong in C(group_vars/) or C(host_vars/);
    only C(host_vars/) overrides a value of the file. Group trees belong in a static YAML inventory.
  - One file per host. A second file for the same host fails.
  - Fails on anything else in the file, so that a typo does not silently drop a group or a variable.
options:
  plugin:
    description: Marks the file as a host file.
    type: str
    required: true
    choices: [ofzhur.ansible.host]
  groups:
    description:
      - Groups the host belongs to. A group that does not exist yet is created.
      - Names are letters, digits and C(_), not starting with a digit.
    type: list
    elements: str
    default: []
  vars:
    description: Variables of the host. Names must be valid variable names.
    type: dict
    default: {}
"""

EXAMPLES = r"""
# inventory/hosts/web-01.yml: the host web-01
plugin: ofzhur.ansible.host
groups: [common, web]
vars:
  ansible_host: 203.0.113.10
  ansible_user: ump
"""

import os
import re
from collections.abc import Mapping

from ansible.errors import AnsibleParserError
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.utils.vars import isidentifier

try:
    # ansible-core >= 2.19 loads file data as untrusted: it is never templated.
    from ansible.template import trust_as_template  # noqa: F401 pylint: disable=unused-import
except ImportError:
    # Older ansible-core templates every string; values marked unsafe stay data.
    from ansible.utils.unsafe_proxy import wrap_var as as_data
else:
    def as_data(value):
        return value

KEYS = ('plugin', 'groups', 'vars')
HOST_NAME = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]*$')
GROUP_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


class InventoryModule(BaseInventoryPlugin):

    NAME = 'ofzhur.ansible.host'

    def verify_file(self, path):
        return super().verify_file(path) and path.endswith(('.yml', '.yaml'))

    def parse(self, inventory, loader, path, cache=True):
        super().parse(inventory, loader, path, cache)

        try:
            data = self.loader.load_from_file(path, cache='none')
        except Exception as e:
            raise AnsibleParserError(f'{path}: {e}') from e
        if not isinstance(data, Mapping):
            raise AnsibleParserError(f'{path}: not a host file (a YAML mapping with plugin: {self.NAME})')
        if data.get('plugin') not in (getattr(self, '_redirected_names', None) or [self.NAME]):
            raise AnsibleParserError(f'{path}: not a host file (plugin: {self.NAME} is missing)')
        unknown = sorted(str(k) for k in data if k not in KEYS)
        if unknown:
            raise AnsibleParserError(f'{path}: unknown key(s) {", ".join(unknown)}; a host file has {", ".join(KEYS)}')

        host = os.path.splitext(os.path.basename(path))[0]
        if not HOST_NAME.match(host):
            raise AnsibleParserError(f'{path}: {host!r} is not a host name (letters, digits, ".", "-" and "_")')

        groups = data.get('groups') or []
        if not isinstance(groups, list):
            raise AnsibleParserError(f'{path}: groups must be a list of group names')
        bad = [str(g) for g in groups if not isinstance(g, str) or not GROUP_NAME.match(g)]
        if bad:
            raise AnsibleParserError(f'{path}: invalid group name(s) {", ".join(bad)} (letters, digits and "_", not starting with a digit)')
        hostvars = data.get('vars') or {}
        if not isinstance(hostvars, Mapping):
            raise AnsibleParserError(f'{path}: vars must be a mapping of variable names to values')
        bad = sorted(str(k) for k in hostvars if not isinstance(k, str) or not isidentifier(k))
        if bad:
            raise AnsibleParserError(f'{path}: invalid variable name(s) {", ".join(bad)}')

        # one file per host: a second file (web-01.yaml next to web-01.yml) would merge into it
        first = getattr(self.inventory.get_host(host), '_ofzhur_host_file', None)
        if first and first != path:
            raise AnsibleParserError(f'{path}: host {host} is already defined by {first}')
        self.inventory.add_host(host)
        self.inventory.get_host(host)._ofzhur_host_file = path
        for group in groups:
            self.inventory.add_child(self.inventory.add_group(group), host)
        for name, value in hostvars.items():
            self.inventory.set_variable(host, name, as_data(value))
