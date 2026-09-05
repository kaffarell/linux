.. SPDX-License-Identifier: GPL-2.0

SRv6 L2 device
==============

The ``srl2`` rtnetlink device encapsulates Ethernet frames in IPv6 with an
SRH. The interface-level ``IFLA_SRL2_SRH`` binary attribute is an optional
default policy. Without it the device operates solely on its private FDB.
Existing point-to-point configurations retain their default policy.

Static unicast FDB
------------------

Use RTM_NEWNEIGH / RTM_DELNEIGH with AF_BRIDGE, the srl2 ifindex and
NTF_SELF. NDA_LLADDR identifies a nonzero unicast Ethernet destination.
NDA_SRL2_SRH carries the same binary ``struct ipv6_sr_hdr`` and segment
array as IFLA_SRL2_SRH, including any validated SRH TLVs. Segment zero is
the final SID; ``first_segment`` identifies the initial active SID.
The kernel validates and copies the entire attribute.

NDA_SRL2_SRH is a device-specific neighbor attribute, analogous to
NDA_DST for VXLAN, rather than an activity-control flag under
NDA_FDB_EXT_ATTRS. This experimental UAPI needs upstream review before
iproute2 syntax is established. The selftest uses raw rtnetlink and
does not require a modified iproute2.

Each MAC has exactly one policy and an independent route cache. Writers
are serialized by RTNL. Transmit lookup uses an RCU-protected rhashtable;
replacement publishes a complete new entry and cache before retiring the
old entry after a grace period.

* NLM_F_CREATE | NLM_F_EXCL adds a new entry and rejects duplicates.
* NLM_F_REPLACE replaces an existing entry; adding NLM_F_CREATE also allows
  creation when the MAC is absent. Every add/replace requires an SRH.
* Delete takes a MAC and optionally an SRH. An SRH-qualified delete must
  match the installed policy exactly.
* RTM_GETNEIGH supports individual get and multipart dump. Responses and
  RTNLGRP_NEIGH add/replace/delete notifications include the SRH, MAC,
  state, ifindex and NTF_SELF.

Entries require NUD_PERMANENT or NUD_REACHABLE (optionally NUD_NOARP).
They never age or learn. Other neighbor flags, VLAN keys, multicast/zero
MACs, remote attributes and NLM_F_APPEND are unsupported.

An exact destination-MAC match overrides the default policy. A miss,
including broadcast or multicast, uses the interface-level policy if
present, or increments tx_dropped otherwise. There is no flood list,
replication, or dynamic learning. Receive delivery continues to use
End.DT2U.

MTU and lifetime
----------------

The device MTU describes the inner L3 payload. The initial MTU reserves
Ethernet, outer IPv6 and default SRH overhead against a 1500-byte
underlay (a one-SID SRH when there is no default). Policies with larger
overheads increase needed_headroom and lower max_mtu. These limits do
not shrink back on delete. An installation that cannot accommodate the
current MTU within the maximum outer packet size fails; lower the MTU
first. The current MTU is not silently changed by FDB operations.

needed_headroom is only a hint: seg6_do_srh_encap() uses skb_cow_head()
for each actual SRH length. Configure the inner MTU for the smallest
underlay path MTU and largest policy overhead to avoid outer fragmentation:
the existing End.DT2U receive path does not reassemble outer fragments.
Route changes invalidate each policy's dst_cache through the standard
IPv6 route-cookie checks.

Device teardown removes all entries. RCU callbacks own all remaining
policy resources without referencing the device. Module exit waits for
these callbacks before unloading their code.
