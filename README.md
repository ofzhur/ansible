# ofzhur.ansible

Ansible content shared by infrastructure repositories: written once here,
used by every infrastructure that includes it. Servers are installed by
[ump](https://github.com/ofzhur/ump); Ansible takes over from there.

| What | Where |
|---|---|
| `ofzhur.ansible.host`: inventory plugin, one YAML file per host | [plugins/inventory/host.py](plugins/inventory/host.py) |
| `ansible.cfg` for the push strategy (Ansible runs on a control machine and reaches servers over SSH) | [config/push/ansible.cfg](config/push/ansible.cfg) |

Requires ansible-core 2.16 or later.

## Use it from an infrastructure repository

The collection goes under `collections/` of the repository, where the
template's `collections_path` looks for it.

As a git submodule, pinned to a commit and editable in place:

```sh
git submodule add -b main https://github.com/ofzhur/ansible.git collections/ansible_collections/ofzhur/ansible
cp collections/ansible_collections/ofzhur/ansible/config/push/ansible.cfg .
```

Or installed, pinned to a tag:

```yaml
# requirements.yml
collections:
  - name: https://github.com/ofzhur/ansible.git
    type: git
    version: v0.1.0
```

```sh
ansible-galaxy collection install -r requirements.yml -p collections
```

## Host files

One file per host, in a directory of the inventory (`inventory/hosts/`).
The file name without `.yml` or `.yaml` is the host name.

```yaml
# inventory/hosts/web-01.yml
plugin: ofzhur.ansible.host
groups: [role_web, account_main, os_ubuntu_26_04]
vars:
  ansible_host: 203.0.113.10
  ansible_user: ump
```

- `plugin` is required, `groups` and `vars` are optional. Any other key,
  an invalid group or variable name, or a second file for the same host
  fails the run (with the template's `any_unparsed_is_failed`).
- Values are data, never templates. Templates go to `group_vars/` or
  `host_vars/`; only `host_vars/` overrides a value of the host file.
- Group trees (`prod` with the children `role_web`, `role_db`) go into
  a static YAML inventory next to the directory, such as
  `inventory/groups.yml`.
- The directory belongs to whatever writes it (ump). It writes each file
  under a dot name (`.web-01.yml.tmp`, ignored by Ansible) and renames
  it into place, removes the files of hosts that are gone, and removes
  the directory with its last file: Ansible fails on an empty inventory
  directory.

## Tests

```sh
python3 tests/test_host.py
```

They run the `ansible` commands on `PATH` against a repository laid out
the way the template expects.
