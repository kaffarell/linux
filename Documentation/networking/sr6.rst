.. SPDX-License-Identifier: GPL-2.0

===========================================
SRv6 L2 Tunnel Device (sr6) Documentation
===========================================

The sr6 device is a virtual Ethernet tunnel device that encapsulates L2
frames in IPv6 with a Segment Routing Header (SRH) for transmission over
an SRv6 network. It is designed for use with a remote seg6local L2
decapsulation behavior such as End.DT2U or End.DX2, providing
point-to-point and statically configured multipoint L2 VPN services over
an IPv6 backbone.

The End.DT2U and End.DX2 behaviors are defined in RFC 8986 (SRv6 Network
Programming).

Design
------

An sr6 device creates a point-to-point L2 tunnel between two SRv6
routers (PE routers). Each PE has an sr6 device configured with a
segment list that defines the SRv6 path to the remote PE, and a local
SID that handles incoming tunneled traffic.

On the transmit side, the sr6 device receives L2 frames from the bridge
(or directly, in standalone mode) and encapsulates each frame in an outer
IPv6 packet with an SRH containing the configured segments. The next
header of the SRH is set to 143 (IPPROTO_ETHERNET) to indicate an
Ethernet payload. The outer packet is then routed toward the first SID
in the segment list through the IPv6 underlay.

The encapsulated packet on the wire looks like this::

    +----------+-----+----------+----------+---------+
    | IPv6 hdr | SRH | Eth hdr  | IP hdr   | Payload |
    +----------+-----+----------+----------+---------+
     \_______ _______/ \______________ ______________/
             v                        v
       outer encap              inner frame

The inner L2 frame is carried unchanged. The outer IPv6 destination
address is set to the first SID in the segment list.

In reduced mode the SRH is shorter, and can be missing altogether, as
described in Encapsulation mode below. The SRH can also carry an HMAC
TLV, requested with the ``hmac`` parameter.

If the segment list contains intermediate SIDs (e.g., End functions on
transit routers), the packet traverses them before reaching the final
SID at the remote PE.

On the receive side, the remote PE has a local SID configured with an
L2 decapsulation behavior. End.DT2U can be used when the l2dev is a
bridge port: the bridge provides MAC learning and forwards
the frame to the correct host. End.DX2 can be used instead for strict
point-to-point links where no bridge is involved. In both cases, the
behavior strips the outer IPv6 header and SRH, recovers the original L2
frame and delivers it to the target L2 device.

The example deployment places hosts, a bridge and an sr6 device on each
PE router::

    cafe::1/64                                  cafe::2/64
   10.0.0.1/24                                10.0.0.2/24
   +--------+                                  +--------+
   |  hs-1  |                                  |  hs-2  |
   +---+----+                                  +----+---+
       |                                            |
   +---+------------------+      +------------------+---+
   |   |           rt-1   |      |   rt-2           |   |
   | +-+----------------+ |      | +-+----------------+ |
   | |       br0        | |      | |       br0        | |
   | +--------+---------+ |      | +--------+---------+ |
   | |veth-hs | sr6-0   | |      | |veth-hs | sr6-0   | |
   | +--------+---------+ |      | +--------+---------+ |
   |                      |      |                      |
   | eth0 (fcf0::1)       |      |       eth0 (fcf0::2) |
   +---+------------------+      +------------------+---+
       |                                            |
       +============================================+
                SRv6 underlay (IPv6 network)

The hosts share an L2 overlay domain through the bridge and the sr6
tunnel. The tunnel carries any Ethernet traffic, including IPv4, IPv6,
ARP, and other L2 protocols. The hosts are unaware of the encapsulation.
The underlay is the IPv6 operator network that interconnects the PE
routers and carries the SRv6-encapsulated traffic.

Forwarding database
~~~~~~~~~~~~~~~~~~~

The device keeps every SRv6 policy in its forwarding database (FDB). A
policy describes one remote PE: the SRH with its full segment list, the
encapsulation mode and an optional FIB table. Each one has its own route
cache. There is no other device-wide forwarding state.

The FDB is keyed by destination MAC::

    00:00:00:00:00:00 -> [remote X, remote Y]
    00:11:22:33:44:55 -> [remote Z]

A unicast MAC has exactly one remote. The all-zeros entry can hold several.
A frame uses the entry of its destination MAC or, if there is none, the
all-zeros entry, and is sent to every remote of that entry. Without either,
it is dropped and counted in tx_dropped. An exact match is never retried
through the all-zeros entry, not even when its route lookup fails.

Broadcast, multicast and unknown unicast frames therefore reach every
remote of the all-zeros entry. There is no learning, ageing, VLAN key or
per-group multicast entry. Remote MACs are installed by userspace. The
receive side is unchanged: End.DT2U delivers to the bridge, which learns
the MAC of the inner source on the sr6 port.

A remote is identified within its entry by its SRH and its table. The
same SID list can thus appear twice in one entry, with different tables.
The mode is policy data and does not take part in the identity.

``ip link`` configures the all-zeros entry: creating a device with
``segs`` installs its only remote, and changing it replaces that remote.
When the all-zeros entry has several remotes, ``ip link`` refuses the
change, since it cannot tell which one to replace. The device does not
report the policy as a link property; ``bridge fdb`` shows it.

FDB netlink interface
~~~~~~~~~~~~~~~~~~~~~

Use RTM_NEWNEIGH, RTM_DELNEIGH and RTM_GETNEIGH with AF_BRIDGE, the sr6
ifindex and NTF_SELF. NDA_LLADDR carries a unicast or the all-zeros MAC.
NDA_SR6 is a nested attribute that carries the policy:

 * NDA_SR6_SRH: the ``struct ipv6_sr_hdr`` and the full segment array, in
   the same layout as IFLA_SR6_SRH. Both modes take the full list; the
   reduced encoding is done at transmit time.
 * NDA_SR6_MODE: ``enum sr6_encap_mode``. Omitted means full.
 * NDA_SR6_TABLE: FIB table for the route to the first SID. Omitted or
   zero means the routing context inherited from the device.
 * NDA_SR6_OLD_REMOTE: nested NDA_SR6_SRH and NDA_SR6_TABLE that select
   the remote to replace.

A request describes a complete policy: an omitted mode or table takes its
default and is not copied from the remote being replaced. Replacing a
remote without a table therefore clears its table.

The operations are:

 * NLM_F_CREATE adds an entry. With NLM_F_EXCL, an existing entry is an
   error.
 * NLM_F_APPEND adds a remote to the all-zeros entry, creating it with
   NLM_F_CREATE.
 * NLM_F_REPLACE replaces the remote of an entry that has only one.
   With NDA_SR6_OLD_REMOTE, it replaces the selected remote of the
   all-zeros entry.
 * RTM_DELNEIGH with an NDA_SR6 selector removes that remote, and without
   one removes the whole entry. A selector must carry the table when it
   targets a remote with an explicit table.
 * RTM_DELNEIGH with NLM_F_BULK flushes the FDB. NDA_NDM_STATE_MASK
   restricts the flush to entries whose masked state matches ndm_state.
 * RTM_GETNEIGH returns the first remote of an entry. A dump returns one
   message per remote.

Each added, replaced or removed remote is reported to RTNLGRP_NEIGH,
including changes made through ``ip link`` and device removal. A
replacement that keeps the identity is reported as RTM_NEWNEIGH only;
one that changes it first reports the old remote as removed.

Entries require NUD_PERMANENT or NUD_REACHABLE, optionally with NUD_NOARP.
Other neighbor flags and attributes and VLAN keys are refused.

This is a proposed UAPI; ``tools/testing/selftests/net/sr6_fdb.py`` uses
raw rtnetlink and does not depend on iproute2 support for it.

Writers are serialized by RTNL. Transmit reads the FDB under RCU, and an
update publishes a complete new remote before the old one is freed after a
grace period.

Encapsulation mode
~~~~~~~~~~~~~~~~~~

RFC 8986 defines two SR headend behaviors for received Ethernet frames,
and the encapsulation mode selects the one the device applies:

 * ``full``: H.Encaps.L2. The pushed IPv6 header carries an SRH with
   the whole segment list.

 * ``reduced``: H.Encaps.L2.Red, an optimization of H.Encaps.L2. It
   reduces the length of the SRH by excluding the first SID, which is
   only placed in the Destination Address field of the pushed IPv6
   header. With more than one SID the SRH is 16 bytes shorter.

RFC 8986 allows the push of the SRH to be omitted when the segment list
contains one segment and there is no need for any flag, tag or TLV. The
device takes that option in reduced mode only. The Ethernet frame then
becomes the payload of a plain outer IPv6 packet, with no SRH and the
next header set to 143.

The mode belongs to each remote, so remotes with different modes can share
a device. A policy that leaves it out uses the full mode.

Post-encap SID route lookup
~~~~~~~~~~~~~~~~~~~~~~~~~~~

After the encapsulation the kernel looks up the route for the first
SID, that is the outer IPv6 destination of the encapsulated packet.
This post-encap SID route lookup uses the FIB table of the current
routing context. By default that is the main table, resolved through
the standard fib rules.

When sr6 is enslaved to a VRF device, directly or through its bridge,
it inherits the VRF routing context and resolves the encapsulated
packet through the VRF table. SID reachability routes must be present
in that table.

Alternatively, a policy can carry a table parameter that specifies a
FIB table for direct lookup, bypassing fib rules entirely. This is
useful when SID routes live in a dedicated table separate from host
routes. The table belongs to each remote, and a table of zero is the
same as no table.

The two mechanisms can be combined: if a table parameter is set and sr6
is also in a VRF, the explicit table parameter takes precedence.
Changes of the device's master hierarchy reset the route cache of every
remote.

In summary, four configurations are possible::

  Config        VRF context   sr6 table   SID route in
  +------------+--------------+------------+--------------+
  | plain      | no           | -          | main         |
  | VRF        | yes          | -          | VRF table    |
  | table      | no           | X          | table X      |
  | VRF+table  | yes          | X          | table X      |
  +------------+--------------+------------+--------------+

The VRF context column indicates whether sr6 inherits a VRF routing
domain from its master hierarchy (e.g., a bridge enslaved to a VRF).

Each configuration determines where the SID reachability route must be
installed:

 * plain: fib rules resolve the SID route from the main table. This
   applies to standalone sr6 without a bridge as well.

 * VRF: the SID route must be in the VRF table. If it is missing there,
   the lookup falls through the fib rules and can be resolved by the
   main table instead, so the VRF table should carry an unreachable
   default route that stops it.

 * table/VRF+table: sr6 does a direct lookup in the specified table,
   regardless of the VRF context.

Interfaces such as VLAN sub-interfaces, macvlan and ipvlan can be
created on top of an sr6 device. Packets sent on them are encapsulated
by the sr6 device below, and the encapsulated packets are routed in the
routing context of that sr6 device, not in the one of the interface they
were sent on::

    ip link add sr6-0 type sr6 mode full segs fc00:2::d20
    ip link set sr6-0 up
    ip link add vrf-red type vrf table 100
    ip link set vrf-red up
    ip link add link sr6-0 name sr6-0.100 type vlan id 100
    ip link set sr6-0.100 master vrf-red
    ip link set sr6-0.100 up
    ip addr add 10.0.0.1/24 dev sr6-0.100
    ping -I sr6-0.100 10.0.0.2

Here sr6-0 is created with no table parameter and is not enslaved to any
VRF, so the post-encap SID route lookup for the traffic towards 10.0.0.2
is done in the main table, and not in vrf-red, which is the routing
context of sr6-0.100 alone.

MTU handling
~~~~~~~~~~~~

The sr6 device computes its MTU to account for the encapsulation
overhead (IPv6 header + SRH + inner Ethernet header). The overhead
depends on the number of segments and on the encapsulation mode, since
the reduced one leaves one segment out of the SRH::

    full       overhead = 40 (IPv6) + 8 + 16*num_segs (SRH) + 14 (Eth)
                        = 62 + 16*num_segs

    reduced    overhead = 40 (IPv6) + 8 + 16*(num_segs-1) (SRH) + 14 (Eth)
                        = 46 + 16*num_segs        (num_segs > 1)

               with a single segment and no HMAC, no SRH is pushed:
               overhead = 40 (IPv6) + 14 (Eth) = 54

The formulas above assume an SRH with no HMAC. The overhead is taken
from the SRH as configured, so an HMAC adds its own 40 bytes, and in
reduced mode with a single segment the HMAC keeps the SRH in place.

For a single segment the overhead is 78 bytes with ``full``, giving a
default MTU of 1422 (1500 - 78), and 54 bytes with ``reduced``, giving
1446.

A long segment list drives the MTU down. Below the IPv6 minimum of 1280,
IPv6 does not come up on the device, while IPv4 keeps working, and the
computed default never goes under the Ethernet minimum of 68.

The maximum MTU and the needed headroom follow the largest encoded
overhead among all the remotes in the FDB, and are recomputed after every
FDB change. A device created without a remote starts with the default MTU
for a single SID in the full mode.

An FDB update never changes the current MTU. A remote whose overhead does
not fit the current MTU within the maximum outer packet size is refused;
lower the MTU first.

``ip link`` changes recompute the MTU as the default for the largest
overhead among the new policy and the remaining remotes. An MTU given in
the same command is used instead, so a user who wants to keep one has to
pass it again::

    ip link set dev sr6-0 mtu 9000 type sr6 mode full \
        segs fc00:3::e,fc00:2::d20

The needed headroom is only a hint: the encapsulation expands each skb as
its remote requires. Configure the MTU for the smallest underlay path MTU
and the largest overhead among the remotes, since the End.DT2U receive
path does not reassemble outer fragments.

Limitations
~~~~~~~~~~~

Remotes can be added, replaced and removed on a live device, without
recreating it. The device cannot be moved between network namespaces.

Usage
-----

1. Create an sr6 device with a single-segment path::

    ip link add sr6-0 type sr6 mode full segs fc00:2::d20
    ip link set sr6-0 up

2. Create an sr6 device with a three-segment path::

    ip link add sr6-0 type sr6 mode full \
        segs fc00:3::e,fc00:1::e,fc00:2::d20

   The segment list is specified from the first SID to the last. Here
   the last SID is the End.DT2U function at the remote PE.

3. Create an sr6 device with the reduced encapsulation::

    ip link add sr6-0 type sr6 mode reduced \
        segs fc00:3::e,fc00:1::e,fc00:2::d20

   The SRH carries fc00:1::e and fc00:2::d20 only, while fc00:3::e is
   in the outer destination address.

4. Create an sr6 device with an explicit FIB table::

    ip link add sr6-0 type sr6 mode full segs fc00:2::d20 table 200

5. Create an sr6 device whose SRH carries an HMAC TLV::

    ip link add sr6-0 type sr6 mode full segs fc00:2::d20 hmac 1

   The key with that ID is not needed to create the device, but the
   device cannot transmit until it is configured with ``ip sr hmac``.
   The TLV adds 40 bytes to the SRH, and therefore to the overhead.

6. Replace the policy of an existing device::

    ip link set dev sr6-0 type sr6 mode full segs fc00:3::e,fc00:2::d20

   The command replaces the only remote of the all-zeros FDB entry, or
   creates it. The device keeps forwarding while the policy is replaced,
   and the new list need not have the same length as the old one.

   The command describes the whole policy. A mode left out is the full
   one, a table left out is the inherited routing context, and an HMAC
   TLV is carried only when ``hmac`` is passed again::

    ip link set dev sr6-0 type sr6 mode reduced \
        segs fc00:3::e,fc00:2::d20 table 200 hmac 1

7. Create an sr6 device with no remote and add remotes through the FDB.
   The commands below use the proposed ``bridge fdb`` syntax of iproute2::

    ip link add sr6-0 type sr6
    bridge fdb add 00:00:00:00:00:00 dev sr6-0 self permanent \
        segs fc00:2::d20
    bridge fdb append 00:00:00:00:00:00 dev sr6-0 self permanent \
        segs fc00:3::d20 mode reduced
    bridge fdb add 02:00:00:00:00:02 dev sr6-0 self permanent \
        segs fc00:2::d20 table 200

   Broadcast, multicast and unknown unicast frames go to both PEs of the
   all-zeros entry, while frames to 02:00:00:00:00:02 go to the PE behind
   fc00:2::d20 through table 200.

8. Show the remotes::

    bridge fdb show dev sr6-0

   The device does not report a policy in ``ip -d link show``.

9. Delete an sr6 device::

    ip link delete sr6-0

Setting up an L2 VPN
--------------------

This example creates a point-to-point L2 VPN between two PE routers
using sr6 and End.DT2U. Each router has a host connected to a bridge,
and the sr6 device provides the tunnel.

The underlay addresses are fcf0::1 (rt-1) and fcf0::2 (rt-2) on a
shared link. The SRv6 SID locator is fcff::/16. The overlay hosts use
cafe::/64 and 10.0.0.0/24.

On rt-1::

    # enable forwarding
    sysctl -w net.ipv6.conf.all.forwarding=1

    # dummy device required as dev argument for seg6local routes
    ip link add dum0 type dummy
    ip link set dum0 up

    # create sr6 device with path to rt-2
    ip link add sr6-0 type sr6 mode full segs fcff:2::d20
    ip link set sr6-0 up

    # create bridge and enslave both host-facing interface and sr6
    ip link add br0 type bridge
    ip link set br0 up
    ip link set veth-hs master br0
    ip link set sr6-0 master br0

    # SID reachability route toward rt-2
    ip -6 route add fcff:2::/32 via fcf0::2

    # local SID table: direct all fcff::/16 to the localsid table
    ip -6 rule add to fcff::/16 lookup 90 prio 999

    # install local End.DT2U SID
    ip -6 route add fcff:1::d20 table 90 \
        encap seg6local action End.DT2U l2dev sr6-0 dev dum0

On rt-2, the configuration is symmetric with addresses and SIDs swapped.

Standalone mode
~~~~~~~~~~~~~~~

An sr6 device can also operate outside a bridge. In this mode, IP
addresses are assigned directly to the sr6 device and it works as a
point-to-point L3 interface over the SRv6 L2 tunnel::

    # remove from bridge
    ip link set sr6-0 nomaster

    # assign overlay addresses directly
    ip addr add cafe::1/64 dev sr6-0
    ip addr add 10.0.0.1/24 dev sr6-0

The End.DT2U behavior accepts both bridge ports and sr6 devices as
valid l2dev targets, so no changes to the remote SID are needed.

VRF integration
~~~~~~~~~~~~~~~

When the bridge is enslaved to a VRF, sr6 inherits the VRF routing
context for the post-encap SID route lookup. Those routes must be in
the VRF table::

    # create VRF and enslave the bridge
    ip link add vrf-vpn type vrf table 100
    ip link set vrf-vpn up
    ip link set br0 master vrf-vpn

    # move SID reachability route to VRF table
    ip -6 route del fcff:2::/32
    ip -6 route add fcff:2::/32 via fcf0::2 table 100

If the bridge is later removed from the VRF, subsequent packets are
routed through the main table again.

The table parameter can be used together with a VRF. In that case the
explicit table takes precedence for the post-encap SID route lookup::

    # sr6 uses table 200 regardless of the VRF
    ip link set sr6-0 type sr6 mode full segs fcff:2::d20 table 200

Integrated Routing and Bridging (IRB)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When the bridge has an IP address and is enslaved to a VRF, it can act
as an L3 gateway for the L2 overlay. Traffic arriving through the sr6
tunnel can be forwarded at L3 by the VRF to hosts on other subnets
attached to the same VRF. This is known as IRB (Integrated Routing and
Bridging) and allows L2 VPN traffic to be routed without leaving the
PE router.

In the following topology, rt-2 acts as the IRB gateway. Its bridge
has address 10.0.0.254/24 and serves as the L3 gateway for the overlay
subnet. hs-1 uses 10.0.0.254 as its default gateway::

                       SRv6 underlay
              rt-1 =================== rt-2
               |                        |
             [br0]                 [vrf-vpn]
             /    \                /       \
        veth-hs  sr6-0       [br0]      veth-extra
           |                  / \       10.99.0.1/24
         hs-1            sr6-0  veth-hs     |
      10.0.0.1/24                  |      hs-extra
      gw: .254                   hs-2    10.99.0.2/24
                              10.0.0.2/24

                        br0 on rt-2: 10.0.0.254/24

Packet flow from hs-1 (10.0.0.1) to hs-extra (10.99.0.2)::

    hs-1: send to gw 10.0.0.254, dst MAC = MAC of rt-2 br0
      |
      | L2 frame
      v
    rt-1 br0: forward to sr6-0
      |
      v
    rt-1 sr6-0: encapsulate in IPv6 + SRH
      |
      | SRv6 underlay
      v
    rt-2 End.DT2U: decapsulate, deliver to sr6-0
      |
      v
    rt-2 br0: dst MAC = own (10.0.0.254), deliver to L3
      |
      v
    rt-2 VRF: route 10.99.0.0/24 via veth-extra
      |
      | L3 forward
      v
    hs-extra: receive

Configuration on rt-2::

    # IRB forwards at L3, so IPv4 forwarding is required as well
    sysctl -w net.ipv4.conf.all.forwarding=1

    # assign a gateway address to the bridge
    ip addr add 10.0.0.254/24 dev br0

    # attach extra interface to the same VRF
    ip link set veth-extra master vrf-vpn
    ip addr add 10.99.0.1/24 dev veth-extra

The gateway in this example sits on one PE, so a host attached to
another PE crosses the tunnel to reach it and be routed. RFC 9135
section 4.1 describes the other arrangement, where every PE for a
subnet carries the same anycast default gateway address and routes for
the hosts attached to it. That arrangement is not covered here.

Kernel configuration
--------------------

The sr6 device requires the following Kconfig options::

    CONFIG_IPV6_SEG6_LWTUNNEL=y
    CONFIG_IPV6_SR6=y    (or =m for module)

When built as a module, it is named sr6.

The ``hmac`` parameter additionally requires CONFIG_IPV6_SEG6_HMAC=y.
Without it the TLV is still pushed, but the HMAC is never computed.
