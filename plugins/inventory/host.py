# Copyright (c) 2026 Oleg Zhurko <oleg@zhurko.de>
# MIT License (see LICENSE)

from __future__ import annotations

DOCUMENTATION = r"""
name: host
short_description: One YAML file per host, in a directory or in a storage
version_added: 0.1.0
author: Oleg Zhurko (@ofzhur)
description:
  - Reads one host from a YAML file. The file name without its extension is the host name,
    O(groups) are the groups the host belongs to and O(vars) are its variables.
  - Meant for a directory with one file per server, such as C(inventory/hosts/) written by a
    provisioner (ump). Ansible reads every file of an inventory directory; this plugin takes the
    C(.yml) and C(.yaml) files whose O(plugin) is C(ofzhur.ansible.host).
  - A file with O(url) instead, such as C(inventory/hosts.yml), points to host files in a storage
    (S3, R2, Consul, Vault, a directory over SSH or here). Every object directly under the prefix of
    the URL whose name ends in C(.yml) or C(.yaml) is read as a host file, by the same rules. No object
    is no host. The options of the storage are those of C([ofzhur_storage]) in C(ansible.cfg), shared
    with the facts in a storage (C(ofzhur.ansible.facts)); its credentials go nowhere else.
  - A host file in a storage sets no C(ansible_*) variable but C(ansible_host), a host name or an
    address; a connection variable (C(ansible_ssh_common_args), C(ansible_connection),
    C(ansible_python_interpreter)) would run commands on every machine that reads the storage. The
    others go into C(host_vars/).
  - Values are data, never templates. Templated values belong in C(group_vars/) or C(host_vars/);
    only C(host_vars/) overrides a value of the file. Group trees belong in a static YAML inventory.
  - One file per host. A second file for the same host fails, and so does a second host with the
    same C(ump_ref) (one server under two names), also from C(ofzhur.ansible.ump).
  - Fails on anything else in the file, so that a typo does not silently drop a group or a variable,
    and on a storage that cannot be read, rather than an inventory with servers missing.
options:
  plugin:
    description: Marks the file as a host file, or with O(url) as a pointer to host files in a storage.
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
  url:
    description:
      - The storage of the host files, by the URLs of ump's state backends.
      - V(s3://BUCKET/PREFIX), V(r2://ACCOUNT/BUCKET/PREFIX), V(consul://HOST:8500/PREFIX)
        (V(http+consul://) over http), V(vault://HOST:8200/MOUNT/PREFIX) (V(http+vault://) over http),
        V(ssh://[USER@]HOST[:PORT]/PATH), V(file:///PATH); see C(ofzhur.ansible.facts).
      - Next to it the file may set the options of the storage that are no credentials, O(endpoint),
        O(region), O(vault_namespace), O(ca_file) (relative to the file) and O(ssh_args); they win over
        C([ofzhur_storage]).
    type: str
    version_added: 0.3.0
extends_documentation_fragment:
  - ofzhur.ansible.storage
"""

EXAMPLES = r"""
# inventory/hosts/web-01.yml: the host web-01
plugin: ofzhur.ansible.host
groups: [common, web]
vars:
  ansible_host: 203.0.113.10
  ump_admin: ump
---
# inventory/hosts.yml: a host file per server under r2://.../fleet/inventory/, such as web-01.yml
plugin: ofzhur.ansible.host
url: r2://0123456789abcdef0123456789abcdef/fleet-inventory/hosts
"""

import os
import re
from collections.abc import Mapping

from ansible.errors import AnsibleParserError
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.utils.vars import isidentifier

from ansible_collections.ofzhur.ansible.plugins.module_utils.storage import SECTION, StoreError, label_of, open_store

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
# a pointer to host files in a storage: its URL and the options of the storage that are no credentials
POINTER_KEYS = ('plugin', 'url', 'endpoint', 'region', 'vault_namespace', 'ca_file', 'ssh_args')
SUFFIXES = ('.yml', '.yaml')
HOST_NAME = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]*$')
# ansible_host from a storage: a host name or an address, never an option of ssh (-oProxyCommand=...)
ADDRESS = re.compile(r'^[A-Za-z0-9_.:%][A-Za-z0-9_.:%-]*$')
GROUP_NAME = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*$')


def check_host(inventory, where, host, ref):
    """Fails on a host that another file (or ump) defines, and on a server (ump_ref) that is another host."""
    first = getattr(inventory.get_host(host), '_ofzhur_host_file', None)
    if first and first != where:
        raise AnsibleParserError(f'{where}: host {host} is already defined by {first}')
    if isinstance(ref, str):
        other, source = getattr(inventory, '_ofzhur_servers', {}).get(ref, (host, where))
        if other != host:
            raise AnsibleParserError(f'{where}: host {host} has ump_ref {ref}, as has host {other} of {source}:'
                                     ' one server, two hosts')


def add_host(inventory, where, host, ref):
    """Adds host as defined by where, after check_host."""
    inventory.add_host(host)
    inventory.get_host(host)._ofzhur_host_file = where
    if isinstance(ref, str):
        if not hasattr(inventory, '_ofzhur_servers'):
            inventory._ofzhur_servers = {}
        inventory._ofzhur_servers[ref] = (host, where)


class InventoryModule(BaseInventoryPlugin):

    NAME = 'ofzhur.ansible.host'

    def verify_file(self, path):
        return super().verify_file(path) and path.endswith(SUFFIXES)

    def parse(self, inventory, loader, path, cache=True):
        super().parse(inventory, loader, path, cache)

        try:
            data = self.loader.load_from_file(path, cache='none')
        except Exception as e:
            raise AnsibleParserError(f'{path}: {e}') from e
        if isinstance(data, Mapping) and 'url' in data:
            self._parse_storage(path, data)
        else:
            self._add(path, os.path.basename(path), data)

    def _names(self):
        return getattr(self, '_redirected_names', None) or [self.NAME]

    def _add(self, where, file_name, data, stored=False):
        """Adds the host of a host file; where names the file in messages, stored tells one from a storage."""
        if not isinstance(data, Mapping):
            raise AnsibleParserError(f'{where}: not a host file (a YAML mapping with plugin: {self.NAME})')
        if data.get('plugin') not in self._names():
            raise AnsibleParserError(f'{where}: not a host file (plugin: {self.NAME} is missing)')
        unknown = sorted(str(k) for k in data if k not in KEYS)
        if unknown:
            raise AnsibleParserError(f'{where}: unknown key(s) {", ".join(unknown)}; a host file has {", ".join(KEYS)}')

        host = os.path.splitext(file_name)[0]
        if not HOST_NAME.match(host):
            raise AnsibleParserError(f'{where}: {host!r} is not a host name (letters, digits, ".", "-" and "_")')

        groups = data.get('groups') or []
        if not isinstance(groups, list):
            raise AnsibleParserError(f'{where}: groups must be a list of group names')
        bad = [str(g) for g in groups if not isinstance(g, str) or not GROUP_NAME.match(g)]
        if bad:
            raise AnsibleParserError(f'{where}: invalid group name(s) {", ".join(bad)} (letters, digits and "_", not starting with a digit)')
        hostvars = data.get('vars') or {}
        if not isinstance(hostvars, Mapping):
            raise AnsibleParserError(f'{where}: vars must be a mapping of variable names to values')
        bad = sorted(str(k) for k in hostvars if not isinstance(k, str) or not isidentifier(k))
        if bad:
            raise AnsibleParserError(f'{where}: invalid variable name(s) {", ".join(bad)}')
        if stored:
            # whoever writes the storage would run commands on every machine that reads it
            bad = sorted(k for k in hostvars if k.startswith('ansible_') and k != 'ansible_host')
            if bad:
                raise AnsibleParserError(f'{where}: {", ".join(bad)}: a host file in a storage sets no ansible_* variable'
                                         ' but ansible_host; the others go into host_vars/')
            address = hostvars.get('ansible_host')
            if address is not None and not (isinstance(address, str) and ADDRESS.match(address)):
                raise AnsibleParserError(f'{where}: ansible_host {address!r} is not a host name or an address')

        # one file per host: a second file (web-01.yaml next to web-01.yml) would merge into it
        ref = hostvars.get('ump_ref')
        check_host(self.inventory, where, host, ref)
        add_host(self.inventory, where, host, ref)
        for group in groups:
            self.inventory.add_child(self.inventory.add_group(group), host)
        for name, value in hostvars.items():
            self.inventory.set_variable(host, name, as_data(value))

    def _parse_storage(self, path, data):
        """Adds the host of every host file in the storage that a pointer names."""
        unknown = sorted(str(k) for k in data if k not in POINTER_KEYS)
        if unknown:
            raise AnsibleParserError(
                f'{path}: unknown key(s) {", ".join(unknown)}; a pointer to host files in a storage has '
                f'{", ".join(POINTER_KEYS)}; credentials go into [{SECTION}] of ansible.cfg')
        if data.get('plugin') not in self._names():
            raise AnsibleParserError(f'{path}: not a host file (plugin: {self.NAME} is missing)')
        url = data.get('url')
        if not isinstance(url, str) or '://' not in url:
            raise AnsibleParserError(f'{path}: url must be the URL of a storage (s3://, r2://, consul://, vault://, ssh://, file://)')
        options = dict(data)
        if isinstance(options.get('ca_file'), str):
            options['ca_file'] = os.path.join(os.path.dirname(os.path.abspath(path)), os.path.expanduser(options['ca_file']))
        self.set_options(direct=options)

        label = label_of(url).rstrip('/')
        try:
            objects = open_store(url, self.get_option).read_all('', SUFFIXES)
        except StoreError as e:
            raise AnsibleParserError(f'{path}: {label}: {e}') from None

        for name, content in sorted(objects):
            where = f'{label}/{name}'
            try:
                text = content.decode()
            except UnicodeDecodeError:
                raise AnsibleParserError(f'{where}: not UTF-8') from None
            try:
                host_file = self.loader.load(text, show_content=False)
            except Exception as e:
                raise AnsibleParserError(f'{where}: {e}') from e
            self._add(where, name, host_file, stored=True)
