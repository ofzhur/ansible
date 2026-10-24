# ofzhur.ansible.firewall

A host firewall from variables: policy as code. Input lets in only what
the policy names, nftables (the default) or iptables, IPv4 and IPv6;
other roles announce what they need.

```yaml
- hosts: all
  become: true
  roles:
    - ofzhur.ansible.firewall
```

## Policy

| Chain | |
|---|---|
| input | drop, but: loopback; the answers to the host's own connections; the ICMPv6 IPv6 needs (errors, neighbor and router discovery, MLD queries); on an interface an announcement polices, what its [policy](#interfaces) lets in, nothing else; ICMP echo, `firewall_icmp`; SSH; `firewall_rules` selected for the host, in order; the announcements, in name order |
| forward | drop |
| output | accept |

By default that is ICMP and SSH alone. A host that forwards
(containers, a VPN gateway) needs more than the role gives yet.

## Variables

| Variable | Default | |
|---|---|---|
| `firewall_backend` | `nftables` | Or `iptables`. See [Backends](#backends). |
| `firewall_ssh_port` | `22` | Always let in. |
| `firewall_ssh_sources` | from anywhere | Addresses and networks SSH is let in from. `[]` fails the run. |
| `firewall_icmp` | `true` | ICMP echo (ping), IPv4 and IPv6. |
| `firewall_rules` | `[]` | Rules, below. |

They go into the inventory: see [Policy as code](#policy-as-code).

A rule:

| Key | Default | |
|---|---|---|
| `proto` | required | `tcp` or `udp`. |
| `port` | required | A port, a range `N-M`, or a list of them. |
| `sources` | any | Addresses and networks (CIDR), IPv4 and IPv6. `[]` lets none in. |
| `interface` | any | Only on this input interface, such as `wg-default`; it need not exist yet. |
| `comment` | | Shown with the rule: up to 64 letters, digits, spaces and `_.,:;/()+=@-`. |
| `hosts` | every host | Host pattern, as in [ofzhur.ansible.users](../users/README.md#targeting). |

An unknown key, a wrong type or a value outside these fails the run
before any change (`meta/argument_specs.yml`, also shown by
`ansible-doc -t role ofzhur.ansible.firewall`). Values go into the
ruleset as they are; nothing else gets through.

## Policy as code

The policy goes into group vars of a group every host is in,
`inventory/group_vars/all/firewall.yml`, or
`inventory/group_vars/common/firewall.yml` for servers installed by ump:
one list, its rules targeted with `hosts`. Ansible does not merge lists:
`firewall_rules` of a more specific group replaces the list of `all`.

The variables of the policy belong in `group_vars` or `host_vars`: an
announcement applies the firewall in the play of the role announcing,
which sees the inventory, not the parameters this role is given
elsewhere or another play's variables. A role parameter or a play
variable fails the run; extra variables (`-e`) reach every play.

```yaml
firewall_ssh_sources: [203.0.113.0/24, 2001:db8::/32]

firewall_rules:
  - proto: tcp                  # HTTP and HTTPS on the web servers
    port: [80, 443]
    hosts: web
    comment: http
  - proto: tcp                  # node exporter, from the monitoring network
    port: 9100
    sources: [10.0.0.0/24]
  - proto: udp                  # on the hosts matching db-*, inside the mesh
    port: 5432
    interface: wg-default
    hosts: db-*
```

## Announcing from a role

A role that needs something let in announces it, rather than asking for
an entry in `firewall_rules`:

```yaml
- name: Let the app in
  ansible.builtin.include_role:
    name: ofzhur.ansible.firewall
    tasks_from: announce
  vars:
    firewall_announce:
      name: app
      rules:
        - proto: tcp
          port: 8443
          comment: https
```

- The announcement is `/etc/ofzhur/firewall.d/NAME.json` on the host,
  root's, `0644`, written once it is checked. It stays until withdrawn:
  the same call with `rules: []` and no `interfaces`. One announcement
  per name, up to 32 letters, digits, `_`, `.` and `-`; a role with
  several uses several names.
- A rule is that of `firewall_rules` without `hosts`; its comment shows
  as `NAME: COMMENT`.
- Where the role's firewall is in place, a handler applies it at the end
  of the play (or at `meta: flush_handlers`); elsewhere the announcement
  waits for the role's first run. Every run of the role applies every
  announcement; one that is not the role's fails the run. In check mode
  an announcement shows as its file, the rules it brings on the real
  run.

### Interfaces

An announcement may police input interfaces, `{IFNAME: {accept_from:
[...]}}`; the interface need not exist yet:

```yaml
    firewall_announce:
      name: app
      rules: []
      interfaces:
        eth1:
          accept_from: [192.0.2.10, 2001:db8::10]
```

On `IFNAME`, the answers to the host's own connections pass, then the
rules for it (`interface: IFNAME`, of `firewall_rules` and the
announcements), then new connections of any protocol, ICMP included,
from the addresses and networks of `accept_from`; everything else
arriving there is dropped, ICMP echo and SSH too. The ICMPv6 IPv6 needs
passes regardless. Other interfaces are not affected; several
announcements for one interface let in from all their `accept_from`.

## Backends

| | nftables | iptables |
|---|---|---|
| Rules | `/etc/nftables.conf`, the table `inet ofzhur` | `/etc/iptables/rules.v4`, `rules.v6`, the table `filter` |
| Checked with | `nft -c -f` | `iptables-restore --test`, `ip6tables-restore --test` |
| Applied with | `nft -f`: one transaction | `iptables-restore`, `ip6tables-restore`: one per family |
| Loaded at boot by | `nftables.service` | `ofzhur-iptables.service`, written by the role |

- Each is installed when missing (`apt`, `pacman`).
- nftables: the file replaces the table it held before, ump's or the
  distribution's (`inet filter`), and the role's own; other tables
  (containers', other tools') stay. A server ump installed ends up with
  the role's table alone.
- iptables: the role's rules are the whole table `filter`.
- Switching removes what the role, or ump, put in place with the other
  one. From iptables, the nftables ruleset is up first; from nftables,
  stopping `nftables.service` empties the ruleset just before the
  iptables rules are applied.

## Safety

The run fails before any change when:

- there is no SSH: `firewall_ssh_port` is no port, or
  `firewall_ssh_sources` is `[]`;
- the policy would shut out the connection the run uses:
  `SSH_CONNECTION` of the user it logs in as, the client address and the
  port as the host sees them, and the interface holding the address it
  reached (`ip -o address`). On an interface an announcement polices,
  its `accept_from` or a rule for the interface has to let the client
  in; elsewhere the SSH rule. A local run, or another connection, has
  none to check;
- a rule or an announcement is invalid;
- a variable of the policy is set outside the inventory.

The rules are checked before they are put in place and applied as a
whole: a ruleset the backend refuses changes nothing.

## Order

The checks, the announcements read and checked, the connection checked,
the package, the rules written, checked and applied (when they changed,
are not what was applied last, or are not in place), the service, then
what the other backend left. What was applied last is
`/etc/ofzhur/firewall.applied`, the backend and the checksums of its
files: rules written by a run cut short are applied by the next. A
second run changes nothing. Check mode changes nothing; without
`python3-apt` it leaves the package out.

Platforms: Ubuntu, Debian, Arch Linux; tested on Ubuntu 24.04 and
Debian 13. Modules: `ansible.builtin` only.
