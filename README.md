# ofzhur.ansible

Ansible content shared by infrastructure repositories: written once here,
used by every infrastructure that includes it. Servers are installed by
[ump](https://github.com/ofzhur/ump); Ansible takes over from there.

| What | Where |
|---|---|
| `ofzhur.ansible.host`: inventory plugin, one YAML file per host, in a directory or in a storage | [plugins/inventory/host.py](plugins/inventory/host.py) |
| `ofzhur.ansible.ump`: inventory plugin, the servers ump installed, from ump itself | [plugins/inventory/ump.py](plugins/inventory/ump.py) |
| `ofzhur.ansible.facts`: cache plugin, facts in a storage that every machine running Ansible shares | [plugins/cache/facts.py](plugins/cache/facts.py) |
| `ansible.cfg` for a control machine (Ansible runs there and reaches servers over SSH) | [config/push/ansible.cfg](config/push/ansible.cfg) |
| `ofzhur.ansible.users`: role, OS users and groups with SSH keys and sudo, each targeted at hosts by a pattern | [roles/users](roles/users/README.md) |
| `ofzhur.ansible.firewall`: role, a host firewall, nftables or iptables, from policy as code; other roles announce what they need | [roles/firewall](roles/firewall/README.md) |
| `ofzhur.ansible.wireguard`: role, a WireGuard mesh over the private networks ump gives its servers, isolated by group | [roles/wireguard](roles/wireguard/README.md) |
| `ofzhur.ansible.base`: playbook, the base of every server ump installs (the group `common`; the role `users`) | [playbooks/base.yml](playbooks/base.yml) |

Requires ansible-core 2.16 or later. Plugins use Python's standard library
only, roles `ansible.builtin` modules only.

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
    version: v0.3.0
```

```sh
ansible-galaxy collection install -r requirements.yml -p collections
```

## The inventory

The servers come into `inventory/` in one of three forms; the static
group tree (`inventory/groups.yml`), `group_vars/` and `host_vars/` go
with each.

- `inventory/hosts/`: host files in the repository. Reviewed and diffed
  with it, read without ump; ump writes them, a person commits them.
- `inventory/hosts.yml`: host files in a storage. Shared by every
  machine that runs Ansible, servers that pull included, without git or
  ump; ump writes them.
- `inventory/ump.yml`: ump itself. Always current, nothing to write or
  commit; needs ump and its state wherever Ansible runs.

Host files carry no `ansible_user`: ump's own runs log in as each
server's administrator (`ump_admin`), a person running Ansible logs in
as themselves (`-u`, or the local user name).

### Host files

One file per host, in a directory of the inventory (`inventory/hosts/`).
The file name without `.yml` or `.yaml` is the host name.

```yaml
# inventory/hosts/web-01.yml
plugin: ofzhur.ansible.host
groups: [common, web]
vars:
  ansible_host: 203.0.113.10
  ump_admin: ump
```

- `plugin` is required, `groups` and `vars` are optional. Any other key,
  an invalid group or variable name, or a second file for the same host
  fails the run (with the template's `any_unparsed_is_failed`), and so
  does a second host with the same `ump_ref`: one server under two
  names.
- Values are data, never templates. Templates go to `group_vars/` or
  `host_vars/`; only `host_vars/` overrides a value of the host file.
- Group trees (`prod` with the children `web`, `db`) go into
  a static YAML inventory next to the directory, such as
  `inventory/groups.yml`.
- The directory belongs to whatever writes it (ump). It writes each file
  under a dot name (`.web-01.yml.tmp`, ignored by Ansible) and renames
  it into place, and removes the file of a server's old hostname. The
  file of a server that is gone is removed by hand, and the directory
  with the last file: Ansible fails on an empty inventory directory.

### Host files in a storage

The same host files, one object per host under the prefix of a URL, in
place of `inventory/hosts/`; a file of the inventory points to them:

```yaml
# inventory/hosts.yml
plugin: ofzhur.ansible.host
url: r2://0123456789abcdef0123456789abcdef/fleet-inventory/hosts
```

- Every object directly under the prefix whose name ends in `.yml` or
  `.yaml` (but for dot names) is a host file, read by the rules above:
  `PREFIX/web-01.yml` is the host `web-01`; `PREFIX/old/web-01.yml` is
  not read.
- Of the `ansible_*` variables a host file in a storage sets
  `ansible_host` alone, a host name or an address; any other fails the
  run. Connection variables (`ansible_ssh_common_args`,
  `ansible_connection`, `ansible_python_interpreter`) would run
  commands on every machine that reads the storage: they go into
  `host_vars/`, reviewed with the repository.
- No object is no host: a valid, empty inventory.
- A storage that cannot be read fails the run (with the template's
  `any_unparsed_is_failed`), rather than an inventory with servers
  missing.
- Next to `url`, the file may set the options of the storage that are
  no credentials: `endpoint`, `region`, `vault_namespace`, `ca_file`
  (relative to the file), `ssh_args`. Credentials go into
  `[ofzhur_storage]`, see [Storages](#storages).

### ump as the inventory

ump itself can be the inventory, in place of host files: the plugin
`ofzhur.ansible.ump` runs `ump server list -o ansible` and takes the
same hosts, groups and variables the host files would have, for the
servers ump installed.

```yaml
# inventory/ump.yml
plugin: ofzhur.ansible.ump
# optional: added to the call
arguments: [--account, main]
# optional: ump's last listing, however old; no provider API is called
cached: true
```

- With `inventory/ump.yml` ump writes no host files. A host also in a
  host file fails the run, and so does a server under two names (the
  same `ump_ref`): one source per host.
- Values are data, as in host files; `group_vars/`, `host_vars/` and
  the static group tree apply the same way.
- ump failing fails the run, also when it could not list one of its
  accounts: never an inventory with servers missing. What else it says,
  such as a server it left out, is a warning; what it took from its
  cache shows with `-v`. It runs without a shell and a terminal;
  `command` (default `ump`) and `timeout` (120 seconds) are the other
  options.
- The template's `ansible.cfg` needs no change: `auto` reads the file
  by its `plugin` key.

## Playbooks

An infrastructure repository's `playbooks/` holds its own playbooks and
a one-line import of each playbook of the collection it uses:

```yaml
# playbooks/00-base.yml
- import_playbook: ofzhur.ansible.base
```

All of them run, in the order of their file names, each play on the
servers its `hosts:` matches: a group needs no playbook of its own.
`ofzhur.ansible.base` matches `common`, the group of every server ump
installs.

## Firewall

The role `ofzhur.ansible.firewall` puts a host firewall in place from
policy as code: input lets in loopback, the answers to the host's own
connections, ICMP, SSH and what the policy names, nothing else. Input
alone is the role's, in a table or chain of its own: forwarding, output
and the rules of other software (Docker, Kubernetes) stay as they are.
nftables by default (`firewall_backend: iptables` for iptables), IPv4
and IPv6. It takes over the firewall ump installs; see
[roles/firewall](roles/firewall/README.md).

The policy goes into the inventory, each rule optionally targeted at
hosts:

```yaml
# inventory/group_vars/common/firewall.yml
firewall_rules:
  - proto: tcp
    port: [80, 443]
    hosts: web
```

A role announces what it needs instead; the announcement stays on the
host, applied by the firewall, until withdrawn with `rules: []`:

```yaml
- ansible.builtin.include_role:
    name: ofzhur.ansible.firewall
    tasks_from: announce
  vars:
    firewall_announce:
      name: app
      rules: [{proto: tcp, port: 8443}]
```

A rule is `proto` (`tcp`, `udp`), `port` (a port, `N-M` or a list),
`sources` (addresses and networks; any when left out), `interface` and
`comment`. An announcement may also police an interface, `interfaces:
{IFNAME: {accept_from: [...]}}`: new connections arriving there come
from those addresses alone, or by the rules for it. A policy without
SSH, one that would shut out the connection the run uses, or one set
outside the inventory (a role parameter, a play variable) fails the run
before any change.

## WireGuard mesh

The role `ofzhur.ansible.wireguard` connects the servers over the
private networks ump gives them (`ump_private_networks`): an interface
`wg-NAME` per network of a host, its peers the other hosts of the
inventory in that network, groups to keep hosts of one network apart.
Each server generates its keys, and its public keys reach the others
through the fact cache; each network is announced to the firewall: its
port, open to the peers alone, and the connections its interface lets
in. See [roles/wireguard](roles/wireguard/README.md).

```yaml
# playbooks/10-mesh.yml
- name: Mesh
  hosts: common
  become: true
  roles:
    - ofzhur.ansible.wireguard
```

```yaml
# inventory/group_vars/all/wireguard.yml: the hosts of foo and of bar apart
wireguard_isolation: [foo, bar]
```

Hosts of different groups are no peers; a group's hosts reach the hosts
without groups, which reach each other but not them.

A server joins on its first run, and its peers know it once they ran
after it: after adding a server, run on the whole fleet.

## Storages

The facts in a storage and the host files in a storage take the URLs of
ump's state backends:

| URL | Storage | Options |
|---|---|---|
| `s3://BUCKET/PREFIX` | AWS S3, or an S3-compatible store (MinIO, ...) at `endpoint` | `access_key`, `secret_key`, `session_token`, `region`, `endpoint` |
| `r2://ACCOUNT/BUCKET/PREFIX` | Cloudflare R2; `ACCOUNT` is the account ID | `access_key`, `secret_key` |
| `consul://HOST:8500/PREFIX` | Consul's KV store over https (`http+consul://` for http) | `consul_token` |
| `vault://HOST:8200/MOUNT/PREFIX` | a KV version 2 engine of Vault over https (`http+vault://` for http) | `vault_token`, `vault_namespace` |
| `ssh://[USER@]HOST[:PORT]/PATH` | a directory on another machine, through the ssh client (its keys, agent, `~/.ssh/config`) | `ssh_args` |
| `file:///PATH` | a directory on this machine | |

The options are those of the section `[ofzhur_storage]` of
`ansible.cfg`, each also an environment variable
(`ANSIBLE_OFZHUR_STORAGE_` and its name in capitals), and nowhere else:

```ini
[ofzhur_storage]
access_key_file = secrets/storage.access_key
secret_key_file = secrets/storage.secret_key
```

- Each credential is a value or, better, a file: `access_key_file`,
  `secret_key_file`, `session_token_file`, `consul_token_file`,
  `vault_token_file`. A file wins over a value; a relative path is
  relative to `ansible.cfg`. `ca_file` trusts a private CA.
- Never in a URL, and never from the variables of the storages' own
  clients (`AWS_*`, `CONSUL_HTTP_TOKEN`, `VAULT_TOKEN`): those are
  ump's, for its state, and ump passes its environment to Ansible. ump
  reads `[ofzhur_storage]` and the same variables when it writes host
  files to a storage, so ump and Ansible always agree.
- Three places, each with credentials of its own: ump's state, which
  holds ump's private key (control machines alone); the inventory, the
  host files (control machines write it, servers that pull read it);
  the facts (every machine that runs Ansible writes them). On R2, which
  scopes a token to buckets, not to prefixes, that is three buckets.
- Whoever writes the host files decides how the machines reading them
  connect to the servers.
- Host files and facts are input to every run: whoever can write them
  changes what runs do, also with values read as data (an address, a
  group, a fact a role puts into a firewall rule). Give each machine no
  more than its part:

| | Control machines | A server that pulls, `HOST` |
|---|---|---|
| S3 | `s3:GetObject`, `s3:PutObject`, `s3:DeleteObject` on `PREFIX/*`, `s3:ListBucket` for `PREFIX/` | `s3:GetObject` on `PREFIX/*`, `s3:ListBucket` for `PREFIX/`; `s3:PutObject` on `FACTS/s1_HOST` only |
| Consul | `key_prefix "PREFIX/" { policy = "write" }` | `key_prefix "PREFIX/" { policy = "read" }`, `key "FACTS/s1_HOST" { policy = "write" }` |
| Vault | `create`, `read`, `update` on `MOUNT/data/PREFIX/*`; `list`, `delete` on `MOUNT/metadata/PREFIX/*` | `read` on `MOUNT/data/PREFIX/*`, `list` on `MOUNT/metadata/PREFIX/*`; `create`, `update` on `MOUNT/data/FACTS/s1_HOST` |
| R2 | an API token for the two buckets, Object Read & Write | an API token, Object Read for the bucket of the inventory, Object Read & Write for that of the facts: R2 cannot keep a server to its own object, so every server that pulls can change the others' facts. Where that matters, take S3, Consul or Vault |

`PREFIX` stands for each of the two prefixes, that of the host files
and that of the facts, `FACTS` for the latter (`s1_HOST` from
ansible-core 2.19, `HOST` before).

## Facts in a central storage

The template caches facts in `.cache/facts` of the control machine: a
run there knows the facts of servers outside its `--limit`, no other
machine does. The cache plugin `ofzhur.ansible.facts` keeps them in a
storage that every machine running Ansible on the servers shares:
control machines that push (a laptop, CI, a bastion) see the facts the
others gathered, and servers that pull (`ansible-pull` on a timer) get
the facts of the other servers, which a pull never gathers.

Two lines of the template's `[defaults]` change, and the credentials go
into `[ofzhur_storage]` (see [Storages](#storages)):

```ini
[defaults]
fact_caching = ofzhur.ansible.facts
fact_caching_connection = r2://0123456789abcdef0123456789abcdef/fleet-facts/facts
```

- One JSON object per host, `PREFIX/s1_HOST` (`PREFIX/HOST` before
  ansible-core 2.19; the two do not share), with the facts and the time
  they were written. `fact_caching_timeout` expires them,
  `ansible-playbook --flush-cache` deletes those of the inventory's
  hosts (of the `--limit` before 2.19). A prefix of their own: not that
  of the host files.
- A run reads the facts of every host once, at its first use of the
  cache, and writes those it gathers. A storage that does not answer or
  refuses fails the run: Ansible would go on without the facts of the
  other servers. An object that is none of the plugin's is a warning,
  and the next facts of its host replace it; one of the other scheme
  (`HOST` from ansible-core 2.19, `s1_HOST` before) is not read, and is
  removed by hand.
- Facts read are data, never templates, also where ansible-core 2.19
  and later would keep a string of them trusted as a template: a writer
  of the storage runs nothing on the machines that read it.
- Facts can be sensitive: addresses, keys, whatever a role keeps as a
  fact; ansible-core 2.19 and later store a vault value of a cacheable
  fact with its plain text. Only the machines sharing them read them.
- `ansible-doc -t cache ofzhur.ansible.facts` lists the options.

## Tests

```sh
python3 tests/test_host.py
python3 tests/test_host_storage.py
python3 tests/test_ump.py
python3 tests/test_facts.py
python3 tests/test_users.py
python3 tests/test_firewall.py
python3 tests/test_wireguard.py
python3 tests/test_mesh.py
```

They run the `ansible` commands on `PATH` against a repository laid out
the way the template expects; for another ansible-core, put it first on
`PATH`. With Docker, `test_host_storage.py` and `test_facts.py` also
run the storages on containers (MinIO, Consul, Vault, sshd;
[tests/storages.py](tests/storages.py)), and the roles run on containers
(Ubuntu 24.04, Debian 13): `test_users.py` the playbook `base`,
`test_firewall.py` and `test_wireguard.py` their role, `test_mesh.py`
both on six servers, isolated by group; without Docker, those parts are
skipped.
