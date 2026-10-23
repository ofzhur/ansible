# ofzhur.ansible.users

OS groups and users from variables: accounts, SSH keys, sudo. Each
entry applies to every host of the play, or to the hosts its `hosts`
pattern selects.

It runs in the playbook `ofzhur.ansible.base`, and so in
`ofzhur.ansible.common`, or on its own:

```yaml
- hosts: all
  become: true
  roles:
    - ofzhur.ansible.users
```

## Where the variables go

Into group vars of a group every host is in:
`inventory/group_vars/all/users.yml`, or
`inventory/group_vars/common/users.yml` for servers installed by ump.
Ansible does not merge lists: `users` of a more specific group replaces
`users` of `all` for its hosts. Keep one list; target its entries with
`hosts`.

## Variables

| Variable | Default | |
|---|---|---|
| `users` | `[]` | Users, below. |
| `users_groups` | `[]` | OS groups: `name` (required), `gid`, `system`, `state`, `hosts`. |
| `users_shell` | `/bin/bash` | Shell of a user without `shell`. |
| `users_protected` | `root` and `ansible_user` | See [Safety](#safety). |

A user:

| Key | Default | |
|---|---|---|
| `name` | required | |
| `state` | `present` | `absent` removes the user and its sudoers file. |
| `comment`, `uid`, `home` | the system's | |
| `group` | a new group named after the user | Primary group. It must exist. Set it when a group of the user's name exists already. |
| `groups` | | Supplementary groups. They must exist. |
| `append` | `true` | With `groups`. `false`: `groups` become the user's only ones. |
| `shell` | `users_shell` | |
| `create_home` | `true` | |
| `system` | `false` | A system account, on creation. |
| `password` | not set | A hash. Without it a new user has no usable password: keys only. |
| `keys` | not managed | SSH public key lines. See [Keys](#keys). |
| `sudo` | `false` | See [Sudo](#sudo). |
| `remove` | `false` | With `state: absent`, also remove the home. |
| `hosts` | every host | Host pattern. See [Targeting](#targeting). |

An unknown key or a wrong type fails the run before any change
(`meta/argument_specs.yml`, also shown by
`ansible-doc -t role ofzhur.ansible.users`).

## Targeting

`hosts` is a host pattern, as the `hosts` of a play: host and group
names, globs, regular expressions (`~`, matched from the start of the
name), exclusions (`!`), intersections (`&`). Exclusions alone start
from all hosts. A list is its patterns joined with `:`.

```yaml
users_groups:
  - name: webops
    hosts: web-*

users:
  - name: oleg                  # an administrator everywhere
    sudo: true
    keys: ['ssh-ed25519 AAAA... oleg']
  - name: deploy                # on the hosts matching web-*
    hosts: web-*
    groups: [webops]
    keys: ['ssh-ed25519 AAAA... deploy']
  - name: dba                   # on db-1, db-02, ...
    hosts: '~^db-\d+$'
    keys: ['ssh-ed25519 AAAA... dba']
  - name: ops                   # everywhere but the old servers
    hosts: '!old-*'
  - name: audit                 # the servers of the group web in prod
    hosts: [web, '&prod']
```

- Patterns are matched against the whole inventory, not the hosts of
  `--limit`: a run limited to one host selects the same entries for it.
- A pattern that matches no host selects none; Ansible warns. An invalid
  regular expression selects none, without a warning. `,` and `:`
  separate patterns, also inside `~`, and so does an unclosed `[`:
  `~[db` is `~` (every host) and `db`.
- One entry per user and per group for a host: two selected entries
  with one name fail the run.
- Each entry with `hosts` costs one `inventory_hostnames` lookup per
  host, on the control machine.

## Keys

With `keys`, `~/.ssh/authorized_keys` holds exactly these keys, one per
line: a key dropped from the list leaves the server on the next run;
`keys: []` leaves none, a string is one key. Without `keys` the file is
not touched.
`~/.ssh` is `0700`, the file `0600`, both the user's.

## Sudo

`sudo: true` writes `/etc/sudoers.d/NAME`, checked with `visudo -cf`
before it is put in place:

```
NAME ALL=(ALL:ALL) NOPASSWD: ALL
```

`sudo: false` (the default) and `state: absent` remove the file. A dot
in the name becomes `_` in the file name: sudo skips files with a dot.
Groups such as `sudo` or `wheel` are not touched; `groups` adds them.

## Safety

The run fails before any change when an entry selected for a host names
a user of `users_protected`: root or the user Ansible connects as
(`ansible_user`; `ump` on servers installed by ump). A change to their
keys, home, shell or sudo could lock Ansible out. ump has given its
administrator keys and sudo (`/etc/sudoers.d/90-ump-ump`).
- `~/.ssh` that is a symbolic link fails the run: the role runs as root
  and would hand the link's target to the user.
- Entries with a `password` are not printed, also with `-v`.

## Order

Groups, users, `~/.ssh` and keys, sudoers files, then the groups to
remove: a group may be the primary group of a user removed before it.
A second run changes nothing. In check mode a user not created yet has
no home; its keys are skipped.

Platforms: Ubuntu, Debian, Arch Linux; tested on Ubuntu 24.04 and
Debian 13. Modules: `ansible.builtin` only.
