# ofzhur.ansible.wireguard

A WireGuard mesh over the private networks ump gives its servers: one
interface per network, its peers the other hosts of the inventory in
that network, isolated by group. A host may send its outgoing traffic
through a peer, its gateway ([Tunnel](#tunnel)).

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
  role owns `/etc/wireguard/wg-*.conf`, `wg-*.key` and `tunnel.sh`;
  other names there are not touched.
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
  so an address on `wg-NAME` is that peer's; a tunneled host takes every
  address from its gateway ([Tunnel](#the-gateway)).
- A host without groups joins no two groups, forwarding on or off: on
  the sender's interface a packet for a host isolated from it has no peer
  to go to, and on the receiver's one from another host's address no peer
  to come from. A gateway, whose clients send it everything, keeps them
  apart by its table and rules ([Tunnel](#the-gateway)).
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

## Tunnel

A host whose inventory names a peer in `wireguard_tunnel` sends all its
outgoing IPv4 through that peer, its gateway, which forwards it and
masquerades it: the internet sees the gateway's address. A NAT gateway
over the mesh.

```yaml
# inventory/host_vars/app-01.yml
wireguard_tunnel: gw-01
```

`{host: gw-01, network: lab}` names the network when the two share more
than one. The gateway is a peer of the host in that network (not
[isolated](#isolation) from it), not the host itself, and has no tunnel
of its own: no chains. Anything else fails the host's run before any
change. The gateway needs nothing in its own inventory: it serves the
hosts whose tunnel names it.

| Variable | Default | |
|---|---|---|
| `wireguard_tunnel` | none | The gateway: its inventory hostname, or `{host: NAME, network: NAME}`. |
| `wireguard_tunnel_direct` | `[]` | IPv4 networks the host reaches directly, beside those below. |
| `wireguard_tunnel_mark` | `0x2000` | The mark of what goes directly: one bit, set and matched alone, the other bits kept; of packets and of connections (conntrack). |
| `wireguard_tunnel_table` | `32000` | The routing table of the tunnel. |
| `wireguard_tunnel_priority` | `32000` | The priority of the first of the four routing rules, which take it to three after (`32000` to `32003`); a gateway's rules take it alone. |

The mark, the table and the priorities clash with none of the usual:
wg-quick's `51820`, kube-proxy's marks `0x4000` and `0x8000`, Calico's
upper 16 bits, Tailscale's `0xff0000` and table `52`. Where one does
clash, the variables move them. The role knows its rules by their
protocol, `111` (`ip rule ... proto 111`).

### Through the tunnel, and directly

Through the gateway: every other new outgoing IPv4 connection, the
host's own and its containers' (Docker masquerades them to the host's
address in the network, the gateway that to its own). Directly, out of
the host's own interfaces:

- link-local `169.254.0.0/16` (a cloud's metadata) and
  `wireguard_tunnel_direct`;
- the routes of the table main but its default: the mesh, Docker's
  networks, the provider's;
- WireGuard's own packets, those of every interface of the host
  (`FwMark`);
- the answers to connections from outside;
- DHCP, and systemd-resolved's queries to the resolvers of a link: it
  asks them from a socket bound to the link, which the tunnel cannot
  carry.

Resolvers asked otherwise (`/etc/resolv.conf` without systemd-resolved,
its global `DNS=`) are asked through the tunnel: a provider's that
answers the host's own address alone goes into
`wireguard_tunnel_direct`, as does any other such service.

Other software that binds its sockets to an uplink (an interface of
main's default routes, where the internet is), or sends its own traffic
to main ahead of the tunnel's rules (Tailscale, at priority `5210`),
gets nowhere by the uplink: the guard drops it. Its fixed destinations
go into `wireguard_tunnel_direct`.

### Incoming

Connections from outside to the host's own addresses are answered
directly, the way they came: SSH, services, the ports Docker publishes.
Those come in on an uplink; those on another interface (a private
network, a container's bridge) are answered by main's routes there, and
what comes in through the tunnel (a port the owner forwards on the
gateway) through it. The gateway forwards nothing inbound: the internet
does not get into the mesh through it, a client is reached at its own
address.

### IPv6

A tunneled host makes no new IPv6 connections out of an uplink: they
would leave beside the gateway. Its routing has nowhere to send them,
and the guard drops them. The answers to connections from outside still
go, and what IPv6 needs on the link: neighbour discovery, router
solicitation, link-local addresses, DHCPv6. The other interfaces
(Docker's IPv6 networks) keep main's routes. A kernel without IPv6
(`ipv6.disable=1`) has nothing to block.

### Fail closed

While the tunnel is not up (the gateway down, the host's interface not
yet up at boot, or down, the tunnel's rules or its table removed),
nothing leaves directly that the tunnel would carry. Connections from
outside, SSH among them, are answered throughout.

| Priority | Rule (IPv4; IPv6 the same, but the direct networks) |
|---|---|
| `32000` | to each direct network, and from the SSH port of the run (`ansible_port`, 22): the table main |
| `32001` | the table main, but its default route (`suppress_prefixlength 0`) |
| `32002` | the mark: the table main |
| `32003` | the tunnel's table |

- The tunnel's table always has a default route: IPv4 through
  `wg-NAME` while it is up, else (and IPv6 always) through
  `ofzhur-closed`, a WireGuard interface without peers, where nothing
  goes anywhere. No lookup gets past it to main's default route.
  `ofzhur-closed` has the MTU of the uplink (`1500` if unknown; with
  IPv6 `1280` at least, below which the kernel takes IPv6 off it):
  wg-quick takes an interface's MTU from the route to its peers, through
  `ofzhur-closed` while the tunnel is down, and so sets the one it would
  without the tunnel (`1420` on a `1500` uplink).
- The table `inet ofzhur-wireguard` (nftables) marks what comes in on
  an uplink, and the connection keeps the mark (the same bit of its
  conntrack mark): the connections from outside, before DNAT (a
  published port is one of them), and the answers to what left
  directly. Their packets carry it, the host's answers and its
  containers' too; marked, they go through main.
  `net.ipv4.conf.all.src_valid_mark` lets the reverse path filter see
  the mark.
- Its guard drops what would leave by an uplink, IPv4 and IPv6, unless
  it carries the mark, answers a connection, comes from the SSH port,
  goes to a direct network or to a route of main but its default, or is
  DHCP, systemd-resolved's or IPv6's on the link. Should the rules go,
  what then takes main's default route is dropped. The other interfaces
  are not the internet: a bridge's containers reach each other,
  br_netfilter or not.
- The uplinks, and main's routes through them, are read anew at every
  run, at boot and when an interface of the tunnel starts; at boot,
  before the network, also those the last run saw. What takes a route
  through an uplink added in between, the guard drops until then.
- At boot all of it is in place before the network, and the interface
  adds its route once it is up ([Reboots and changes](#reboots-and-changes)).

The table `inet ofzhur-wireguard` deleted (`nft flush ruleset`), nothing
leaves directly either, but the answers go through the tunnel, SSH's
alone excepted: its rules hold without nftables. IPv6 to the uplink's
own prefix is then held no more; beyond it, nothing goes. A strict
reverse path filter (`rp_filter = 1`) needs the marks of what comes in
on an uplink; the loose one (`2`, systemd's default) needs nothing. A
connection older than the tunnel takes the mark with its next packet
from outside; SSH's needs none.

### The gateway

- Forwarding is turned on where it is off, interface by interface
  (`net.ipv4.conf.IFNAME.forwarding`), once the gateway's rules are in
  place: on the served `wg-NAME`, where the clients' packets come in,
  and on the uplinks, where their answers do (IPv4 forwards by the
  interface a packet came in on); nowhere else. An uplink not there yet
  under its name (at boot, before the network) gets it once the network
  is up, before the gateway has clients. `net.ipv4.ip_forward`, the
  switch of all, stays as it is: software that forwards (Docker,
  Kubernetes) turns that one on. The role records what it turned on,
  until the next boot, by the interface's index, name and hardware
  address: renamed (udev, at boot), it keeps its index and address; an
  interface given the index since, of another name and address, is not
  the role's. While that switch is off, it turns off what it turned on,
  and that alone, first, before the rules go: on an interface no longer
  served or no uplink any more, and everywhere when the last client
  goes. While it is on, everything forwards for someone else.
- Its table `inet ofzhur-wireguard`, never the firewall's: the clients'
  connections out of the other interfaces, masqueraded, the TCP MSS
  clamped to the route's MTU. Nothing from one WireGuard interface to
  another: the isolation holds, no client reaches through the gateway a
  host it has no tunnel to, and networks stay apart. Nothing conntrack
  does not know (invalid, untracked). Into the mesh, the answers to the
  clients and what leaves as the gateway itself (its own, its containers
  masqueraded), never the internet. From other peers, new connections
  only to what is addressed to the gateway (DNAT, a published port). The
  chains accept what they do not drop: other software's decide the rest.
- Its routing rules (`prohibit`, at `wireguard_tunnel_priority`): nothing
  from a served `wg-NAME` to the networks of the gateway, also without
  that table. The internet is kept out of the mesh by the table alone.
- A client takes every address from its gateway (`0.0.0.0/0`), also as
  a former client that has not run yet: its isolation is the gateway's
  table and rules, and its forwarding.
- Docker drops forwarded traffic of others (the policy of `FORWARD`): the
  gateway lets its clients through `DOCKER-USER`, after the rules others
  put there (before Docker's `RETURN` at its end), also once Docker has
  started after the interface (a drop-in of `docker.service`, on every
  gateway). Into Docker's own bridges (`docker0`, `br-*`) Docker decides:
  a client reaches the gateway's containers at their published ports
  alone. With Docker's nftables backend, or another firewall that drops
  forwarded traffic, `wg-NAME` is to be let through there.

### Reboots and changes

`/etc/wireguard/tunnel.sh`, written by the role, puts a host's part in
place at every run, and at boot without one:

- `ofzhur-wireguard-tunnel.service`, early, before the network: the
  rules, the table `inet ofzhur-wireguard`, the tunnel's table through
  `ofzhur-closed`. A tunneled host is closed from the start.
- The unit of an interface of the tunnel (a client's, those a gateway
  serves), `wg-quick@wg-NAME`, by a drop-in
  (`/etc/systemd/system/wg-quick@wg-NAME.service.d/ofzhur-wireguard.conf`):
  before the interface comes up, the network up by then, the uplink's
  MTU on `ofzhur-closed`; once it is up, the route through it, a
  gateway's forwarding on it and on the uplinks. A failed script leaves
  the interface up, and the tunnel closed.

Not wg-quick's `PostUp`: wg-quick's own AppArmor profile (Ubuntu 26.04,
wherever the package `apparmor` is installed) lets it run its own tools
alone, no shell, and the tunnel would stay closed until the next run.
systemd runs the drop-in outside that profile. An interface brought up
by hand (`wg-quick up`) gets its route at the next run.

It changes only what differs, the new in place before the old goes, and
restarts nothing; a second run changes nothing, check mode tells and
changes nothing. systemd-networkd, which removes the routing
rules of others when it starts, keeps the tunnel's on a tunneled host
(a drop-in, `ManageForeignRoutingPolicyRules=no`).

Without `wireguard_tunnel`, or on a gateway without clients, all of it
goes: rules, table, marks, `FwMark`, `AllowedIPs`, the guard, the IPv6
block, `ofzhur-wireguard-tunnel.service`, the drop-ins, the forwarding
the role turned on. A tunneled host's traffic goes directly before its
interfaces lose the mark; a gateway forwards no more before its rules
go.

After setting or removing a tunnel, run the role on the host and its
gateway, or the whole fleet: a client's traffic gets through once its
gateway ran, and goes directly once it ran itself.

## Variables

| Variable | Default | |
|---|---|---|
| `wireguard_networks` | ump's | The host's networks, `{NAME: {address, cidr}}`. See [Networks](#networks). |
| `wireguard_isolation` | `[]` | The Ansible groups that isolate their hosts, for the whole inventory. See [Isolation](#isolation). |
| `wireguard_groups` | its Ansible groups of `wireguard_isolation` | The host's groups, a list or a mapping of networks to lists. See [Isolation](#isolation). |
| `wireguard_ports` | `{}` | Listen ports, `{NAME: PORT}`. See [Ports](#ports). |
| `wireguard_firewall` | `true` | Announce the ports and the policies of the interfaces to `ofzhur.ansible.firewall`; `false` withdraws them. |
| `wireguard_tunnel` | none | The gateway of the host. See [Tunnel](#tunnel). |
| `wireguard_tunnel_direct` | `[]` | IPv4 networks a tunneled host reaches directly. |
| `wireguard_tunnel_mark`, `_table`, `_priority` | `0x2000`, `32000`, `32000` | The mark, the routing table and the first rule's priority of a tunneled host (a gateway's rules: that one). |

They go into the inventory (`group_vars`, `host_vars`): what the other
hosts see of a host is its inventory variables and cached facts, not the
play's variables or a role's parameters, which fail the run. A wrong
type fails it too (`meta/argument_specs.yml`, also shown by
`ansible-doc -t role ofzhur.ansible.wireguard`).

Platforms: Ubuntu, Debian, Arch Linux, with WireGuard in the kernel
(Linux 5.6 or later); tested on Ubuntu 24.04 and Debian 13. A tunnel
needs nftables, installed where missing (`apt`, `pacman`). Modules:
`ansible.builtin` only.
