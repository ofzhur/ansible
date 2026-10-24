# ofzhur.ansible.wireguard

A WireGuard mesh over the private networks ump gives its servers: one
interface per network, its peers the other hosts of the inventory in
that network, isolated by group.

```yaml
- hosts: common
  become: true
  roles:
    - ofzhur.ansible.wireguard
```

## Networks

A host's networks are ump's, `ump_private_networks` of its host file or
of `ump server list -o ansible`:

```yaml
ump_private_networks:
  default: {address: 10.0.0.5, cidr: 10.0.0.0/24}
  lab: {address: 10.0.1.5, cidr: 10.0.1.0/24}
```

A host file of ump v0.5.0, with `ump_private_network`,
`ump_private_address` and `ump_private_cidr` alone, is in that one
network. `wireguard_networks`, of the same shape, replaces ump's; `{}`
takes the host out of every network.

For each network `NAME` of the host:

| | |
|---|---|
| Interface | `wg-NAME`: `wg-quick@wg-NAME`, enabled and started, with `Table = off` (see [Interfaces and routes](#interfaces-and-routes)) |
| Address | `address`, with the prefix of `cidr` (`10.0.0.5/24`) |
| Port | see [Ports](#ports) |
| Peers | the other hosts in `NAME` the [isolation](#isolation) lets through: `Endpoint` their `ansible_host` (a name resolved on the host) and port, `AllowedIPs` their address `/32`, `PersistentKeepalive = 25` |
| Files | `/etc/wireguard/wg-NAME.conf` and `wg-NAME.key`, `0600`, in `/etc/wireguard`, `0700` |

- Networks are apart: hosts of two networks are no peers, and a host in
  both does not route between them.
- A change goes onto the running interface, never restarts it: see
  [Interfaces and routes](#interfaces-and-routes).
- A network the host left loses its interface: stopped (deleted, when up
  without its unit), disabled, its configuration and key removed. The
  role owns `/etc/wireguard/wg-*.conf` and `wg-*.key`; other names there
  are not touched.
- A name is lower-case letters, digits, `.`, `_` and `-`, at most 12
  characters (an interface name has 15), as ump's; `cidr` an IPv4
  network of `/8` to `/30`, `address` one of its hosts. Anything else
  fails the run before any change.

## Interfaces and routes

`wg-quick@wg-NAME` brings the interface up with `Table = off`: wg-quick
adds no routes, policy rules or firewall marks, whatever `AllowedIPs`
holds. The interface's one route is the kernel's, to its network
(`10.0.0.0/24` for `10.0.0.5/24`). Routes other software adds through
the interface are its own: the role adds and deletes none.

Such a route reaches the peers' addresses alone. WireGuard sends a
packet to the peer whose `AllowedIPs` hold its destination, whatever the
route's gateway, and the peers and their `AllowedIPs` are the role's:
each run puts them back as configured. A route via a peer to another
network carries nothing; software that routes other networks over the
mesh (a Kubernetes CNI) encapsulates to the peers' addresses (VXLAN,
IPIP over `wg-NAME`).

A restart deletes the link, and with it every route through it, other
software's too. The role never restarts a running interface; each run
holds it against its configuration, whatever changed it (a new
configuration, a person, a run cut short):

- A new configuration, or peers, `AllowedIPs`, a port or key other than
  configured: reloaded, `wg syncconf` with `wg-quick strip`, as the
  unit's reload, without an interruption. An endpoint other than
  configured is no reason: it follows a peer that roams.
- Other IPv4 addresses than the configured one (a new address or
  prefix): it goes on in place, then every other is deleted (with
  `promote_secondaries`, so that the old address does not take the new
  one with it). Routes through the interface stay; those from the old
  address (`src`) go.
- An absent interface starts: its unit is restarted, as after
  `wg-quick down` by hand it is still active. One up without its unit
  (`wg-quick up` by hand) is held in place as well; its unit brings it
  up at the next boot.

Nothing but a person restarts a running interface: `systemctl restart
wg-quick@wg-NAME`.

## Ports

A network listens on `wireguard_ports[NAME]`, else on 51820 plus the
first 32 bits of the SHA-1 of its name modulo 1000: `default` on 52630,
`lab` on 52585. From the name alone: the same on every host, and no
other network's port changes when one is added or removed. Two networks
of a host on one port fail the run; `wireguard_ports` gives one another:

```yaml
# inventory/group_vars/all/wireguard.yml
wireguard_ports:
  default: 51820
```

Each host's own `wireguard_ports` sets where it listens, and where its
peers reach it.

## Isolation

A host's groups in a network are its Ansible groups named in
`wireguard_isolation`, a list for the whole inventory:

```yaml
# inventory/group_vars/all/wireguard.yml
wireguard_isolation: [foo, bar]
```

`wireguard_groups` names them instead: a list for every network of the
host, or a mapping of networks to lists for the networks it names.

```yaml
# inventory/host_vars/app-01.yml: db and web in default, none in lab,
# the Ansible groups in the others
wireguard_groups: {default: [db, web], lab: []}
```

Groups keep hosts apart. A host without groups is a peer of every host
of the network: the hosts with groups reach it, it reaches the hosts
without:

| Two hosts of a network | Peers | New connections |
|---|---|---|
| neither has groups | yes | both ways |
| a group in common | yes | both ways |
| one has groups, the other none | yes | from the one with groups alone |
| both have groups, none in common | no | none |

Six hosts of a network, `a` to `f`:

| Groups | Both ways | One way | Apart |
|---|---|---|---|
| all six `foo` | any two | | |
| `a`, `b` `foo` | `a`-`b`; any two of `c`, `d`, `e`, `f` | `a`, `b` to `c`, `d`, `e`, `f` | |
| `a`, `b` `foo`; `c`, `d` `bar` | `a`-`b`, `c`-`d`, `e`-`f` | `a`, `b`, `c`, `d` to `e`, `f` | `a`, `b` from `c`, `d`: no peers |

- Peers: a host's interface has no peer for a host isolated from it: a
  packet to that address goes nowhere ("Required key not available").
- New connections: the [firewall](#firewall) of a host with groups lets
  in new connections on `wg-NAME` from the peers sharing one alone;
  answers to its own connections pass, and rules for the interface
  (`firewall_rules` with `interface: wg-NAME`, an announcement's) still
  apply. A host without groups lets in every peer, every protocol and
  port. WireGuard takes from a peer its own address alone (`AllowedIPs`),
  so an address on `wg-NAME` is that peer's.
- A host without groups joins no two groups, forwarding on or off: on
  the sender's interface a packet for a host isolated from it has no peer
  to go to, and on the receiver's one from another host's address no peer
  to come from.
- Without the firewall (`wireguard_firewall: false`, or
  `ofzhur.ansible.firewall` not in place) the peers hold alone: hosts
  with groups and those without reach each other both ways.

## Keys and the fact cache

The private key of each interface is generated on the host, once, into
`/etc/wireguard/wg-NAME.key`. It never leaves the host and is never
printed: the host puts the configuration together with it. The public
keys go to the fact `wireguard_public_keys`, `{NAME: KEY}`, cached, where
the other hosts' runs find them, also with `--limit`: the template's
`.cache/facts`, or [ofzhur.ansible.facts](../../README.md#facts-in-a-central-storage)
for every machine that runs Ansible.

- A host whose key the cache lacks (its facts expired after
  `fact_caching_timeout`, or were flushed) stays a peer: each host takes
  its key from its own configuration, the public keys alone. A host in
  no configuration yet (it has not run) is left out of it, with a note,
  until it runs. A peer goes when it left the network or the inventory,
  or is isolated now.
- Whoever can write the cache can put a key into the configuration of a
  host: give the machines no more than their part
  ([Storages](../../README.md#storages)).
- A key removed by hand is generated anew; the peers learn it as a new
  host's.

## A new host

A host joins the mesh on its first run, and its peers know it once they
ran after it. After a host was added, reinstalled or moved to another
network, run the role on the whole fleet, or at least on the hosts of
its networks: the hosts of a play publish their keys before any of them
writes a configuration (the linear strategy, Ansible's default), so one
run completes the mesh.

## Firewall

With `wireguard_firewall` (the default) each network is announced to
[ofzhur.ansible.firewall](../firewall/README.md) as `wireguard-NAME`:
udp to its port from the addresses of the peers, and the policy of
`wg-NAME`, new connections from the peers the host lets in
([Isolation](#isolation)). A network without peers, one the host left,
and every network with `wireguard_firewall: false` withdraw it. The
firewall applies it where it runs.

A peer's address is its `ansible_host`; a name is resolved on the host
(`getent`, IPv4 first), and the address is its endpoint too. A name that
does not resolve there leaves the peer out, with a note: in the
configuration it would fail the whole interface.

## Variables

| Variable | Default | |
|---|---|---|
| `wireguard_networks` | ump's | The host's networks, `{NAME: {address, cidr}}`. See [Networks](#networks). |
| `wireguard_isolation` | `[]` | The Ansible groups that isolate their hosts, for the whole inventory. See [Isolation](#isolation). |
| `wireguard_groups` | its Ansible groups of `wireguard_isolation` | The host's groups, a list or a mapping of networks to lists. See [Isolation](#isolation). |
| `wireguard_ports` | `{}` | Listen ports, `{NAME: PORT}`. See [Ports](#ports). |
| `wireguard_firewall` | `true` | Announce the ports and the policies of the interfaces to `ofzhur.ansible.firewall`; `false` withdraws them. |

They go into the inventory (`group_vars`, `host_vars`): what the other
hosts see of a host is its inventory variables and cached facts, not the
play's variables or a role's parameters, which fail the run. A wrong
type fails it too (`meta/argument_specs.yml`, also shown by
`ansible-doc -t role ofzhur.ansible.wireguard`).

Platforms: Ubuntu, Debian, Arch Linux, with WireGuard in the kernel
(Linux 5.6 or later); tested on Ubuntu 24.04 and Debian 13. Modules:
`ansible.builtin` only.
