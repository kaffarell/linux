#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# author: Andrea Mayer <andrea.mayer@uniroma2.it>
#
# This script tests the SRv6 L2 VPN data path using the sr6 virtual
# Ethernet device for L2 frame encapsulation and the End.DT2U behavior
# (RFC 8986, Section 4.11) for decapsulation. The key components are:
#
#   i) The sr6 device encapsulates L2 frames received from a connected
#      host into an outer IPv6 packet steered along a SID List,
#      initiating the L2 VPN tunnel;
#
#  ii) The SRv6 End.DT2U behavior decapsulates the tunneled L2 frame
#      and delivers it to the sr6 device on the remote side.
#
# Four SRv6 routers (rt-1..rt-4) form a full-mesh IPv6 underlay. Each
# router connects one host via a bridge with an sr6 device as port.
# Two independent L2 VPNs carry traffic between host pairs:
#
#   VPN 1: hs-1 (rt-1) <-> hs-2 (rt-2)
#   VPN 2: hs-3 (rt-3) <-> hs-4 (rt-4)
#
#
#              cafe::1                                cafe::2
#             10.0.0.1                               10.0.0.2
#            +--------+                             +--------+
#            |  hs-1  |                             |  hs-2  |
#            +---+----+                             +----+---+
#                |                                       |
#          +-----+------+                         +------+-----+
#          |  veth-hs   |  fcf0:0:1:2::/64        |  veth-hs   |
#          |    br0     +-------------------------+    br0     |
#          |   sr6-0    |                         |   sr6-0    |
#          |   rt-1     |                         |   rt-2     |
#          |  (plain)   |                         |   (VRF)    |
#          +-----+------+                         +------+-----+
#                |       .                       .       |
#                |  fcf0:0:1:3::              .          |
#                |             .           .             |
#                |                .     .                |
#   fcf0:0:1:4:: |                   .                   | fcf0:0:2:3::
#                |                .     .                |
#                |             .           .             |
#                |  fcf0:0:2:4::              .          |
#                |       .                       .       |
#          +-----+------+                         +------+-----+
#          |  veth-hs   |  fcf0:0:3:4::/64        |  veth-hs   |
#          |    br0     +-------------------------+    br0     |
#          |   sr6-0    |                         |   sr6-0    |
#          |   rt-4     |                         |   rt-3     |
#          |(VRF+table) |                         |  (table)   |
#          +-----+------+                         +------+-----+
#                |                                       |
#            +---+----+                             +----+---+
#            |  hs-4  |                             |  hs-3  |
#            +--------+                             +--------+
#              cafe::4                                cafe::3
#             10.0.0.4                               10.0.0.3
#
# Every fcf0:0:x:y::/64 network interconnects the SRv6 routers rt-x
# with rt-y in the IPv6 operator network.
#
# Local SID table
# ===============
#
# Each SRv6 router rt-x is configured with a Local SID table (table 90)
# containing local SIDs for transit and decapsulation:
#
#   Local SID table for SRv6 router rt-x
#   +-----------------------------------------------------------+
#   |fcff:x::e   is associated with the SRv6 End behavior       |
#   |fcff:x::d20 is associated with the SRv6 End.DT2U behavior  |
#   +-----------------------------------------------------------+
#
# The fcff::/16 prefix is reserved by the operator for implementing SRv6
# VPN services. A fib rule at priority 999 directs all fcff::/16 traffic
# to the localsid table for local SID processing.
#
# SRv6 L2 encapsulation
# =====================
#
# Each router's sr6-0 device encapsulates L2 frames into an outer IPv6
# packet, with the segment list carried in a Segment Routing Header
# (SRH). Segment lists of different lengths are used to test both direct
# paths and paths through transit routers:
#
#   VPN 1: rt-1 segs fcff:2::d20                        (reduced)
#          rt-2 segs fcff:4::e,fcff:1::d20              (full)
#   VPN 2: rt-3 segs fcff:1::e,fcff:4::d20              (full)
#          rt-4 segs fcff:2::e,fcff:1::e,fcff:3::d20    (reduced)
#
# In reduced mode the first SID is not written in the SRH, since the
# outer IPv6 destination address carries it anyway, and no SRH is pushed
# at all when that SID is the only one. rt-1 has a single SID and so
# pushes no SRH, while the SRH that rt-4 pushes, without the first of its
# three SIDs, is processed by the transit routers rt-2 and rt-1.
#
# Post-encap routing
# ==================
#
# After encapsulation, sr6 must route the outer IPv6 packet toward the
# first SID. The SID reachability routes (fcff:y::/32 via <next-hop>)
# are initially installed in the main routing table. Each router uses a
# different configuration for the post-encap route lookup:
#
#   rt-1 (plain)     The SID reachability route stays in the main table.
#                    Fib rules resolve it normally.
#
#   rt-2 (VRF)       The SID reachability route for the first SID is
#                    moved from the main table to the VRF table (100)
#                    and a blackhole is added in the main table. sr6
#                    inherits the VRF routing context because the
#                    bridge is enslaved to the VRF.
#
#   rt-3 (table)     The SID reachability route is moved from the main
#                    table to a dedicated encap table (200). sr6 is
#                    created with "table 200" and does a direct table
#                    lookup, bypassing fib rules.
#
#   rt-4 (VRF+table) The SID reachability route is moved from the main
#                    table to a dedicated encap table (200). The VRF
#                    table has a blackhole for the first SID. sr6 is
#                    created with "table 200", which takes precedence
#                    over the VRF routing context.
#
# Summary:
#
#   router   bridge in VRF   sr6 table   route in       blackhole in
#   +--------+---------------+------------+--------------+--------------+
#   | rt-1   | no            | -          | main         | -            |
#   | rt-2   | yes           | -          | VRF (100)    | main         |
#   | rt-3   | no            | 200        | encap (200)  | -            |
#   | rt-4   | yes           | 200        | encap (200)  | VRF (100)    |
#   +--------+---------------+------------+--------------+--------------+
#
# Data path
# =========
#
# TX: the host sends an L2 frame which the bridge forwards to sr6-0.
# sr6-0 encapsulates it in an outer IPv6 packet and routes it toward the
# first SID. Each transit router processes its End SID and forwards the
# packet to the next hop in the segment list.
#
# RX: at the final SID, End.DT2U decapsulates the inner L2 frame,
# delivering it on sr6-0. The bridge then forwards the frame to the
# destination host.
#

source lib.sh

readonly DUMMY_DEVNAME="dum0"
readonly SR6_DEVNAME="sr6-0"
readonly RT2HS_DEVNAME="veth-hs"
readonly BRIDGE_DEVNAME="br0"
readonly HS_VETH_NAME="veth0"
readonly LOCALSID_TABLE_ID=90
readonly VRF_TABLE_ID=100
readonly VRF_DEVNAME="vrf-${VRF_TABLE_ID}"
readonly SR6_FIB_TABLE_ID=200
readonly IPv6_RT_NETWORK=fcf0:0
readonly IPv6_HS_NETWORK=cafe
readonly IPv4_HS_NETWORK=10.0.0
readonly VPN_LOCATOR_SERVICE=fcff
readonly END_FUNC=0e
readonly DT2U_FUNC=0d20
readonly DT2U_BAD_FUNC=0d21
readonly PING_CPU_PIN=0
# the base the device subtracts the encapsulation overhead from
readonly ETH_DATA_LEN=1500

PING_TIMEOUT_SEC=4
PAUSE_ON_FAIL=${PAUSE_ON_FAIL:=no}

ROUTERS=''
HOSTS=''

SETUP_ERR=1

ret=${ksft_skip}
nsuccess=0
nfail=0

log_test()
{
	local rc="$1"
	local expected="$2"
	local msg="$3"

	if [ "${rc}" -eq "${expected}" ]; then
		nsuccess=$((nsuccess+1))
		printf "\n    TEST: %-60s  [ OK ]\n" "${msg}"
	else
		ret=1
		nfail=$((nfail+1))
		printf "\n    TEST: %-60s  [FAIL]\n" "${msg}"
		if [ "${PAUSE_ON_FAIL}" = "yes" ]; then
			echo
			echo "hit enter to continue, 'q' to quit"
			read a
			[ "$a" = "q" ] && exit 1
		fi
	fi
}

print_log_test_results()
{
	printf "\nTests passed: %3d\n" "${nsuccess}"
	printf "Tests failed: %3d\n"   "${nfail}"

	if [ "${ret}" -ne 1 ]; then
		ret=0
	fi
}

log_section()
{
	echo
	echo "################################################################################"
	echo "TEST SECTION: $*"
	echo "################################################################################"
}

test_command_or_ksft_skip()
{
	local cmd="$1"

	if [ ! -x "$(command -v "${cmd}")" ]; then
		echo "SKIP: Could not run test without \"${cmd}\" tool";
		exit "${ksft_skip}"
	fi
}

get_rtname()
{
	local rtid="$1"

	echo "rt_${rtid}"
}

get_hsname()
{
	local hsid="$1"

	echo "hs_${hsid}"
}

nsname_rt()
{
	eval echo "\${$(get_rtname "$1")}"
}

nsname_hs()
{
	eval echo "\${$(get_hsname "$1")}"
}

create_router()
{
	local rtid="$1"
	local nsname

	nsname="$(get_rtname "${rtid}")"
	setup_ns "${nsname}"
}

create_host()
{
	local hsid="$1"
	local nsname

	nsname="$(get_hsname "${hsid}")"
	setup_ns "${nsname}"
}

cleanup()
{
	cleanup_all_ns

	if [ "${SETUP_ERR}" -ne 0 ]; then
		echo "SKIP: Setting up the testing environment failed"
		exit "${ksft_skip}"
	fi

	exit "${ret}"
}

# Create veth pairs between a router and its neighbors.
# args:
#  $1 - router ID
#  $2 - space-separated neighbor IDs
add_link_rt_pairs()
{
	local rt="$1"
	local rt_neighs="$2"
	local neigh
	local nsname
	local neigh_nsname

	nsname=$(nsname_rt "${rt}")

	for neigh in ${rt_neighs}; do
		neigh_nsname=$(nsname_rt "${neigh}")

		ip link add "veth-rt-${rt}-${neigh}" netns "${nsname}" \
			type veth peer name "veth-rt-${neigh}-${rt}" \
			netns "${neigh_nsname}"
	done
}

# Echoes the /64 prefix for the link between rt and neigh.
# args:
#  $1 - router ID
#  $2 - neighbor router ID
get_network_prefix()
{
	local rt="$1"
	local neigh="$2"
	local p="${rt}"
	local q="${neigh}"

	if [ "${p}" -gt "${q}" ]; then
		p="${q}"; q="${rt}"
	fi

	echo "${IPv6_RT_NETWORK}:${p}:${q}"
}

# Setup the basic networking for a router.
# args:
#  $1 - router ID
#  $2 - space-separated neighbor IDs
setup_rt_networking()
{
	local rt="$1"
	local rt_neighs="$2"
	local nsname
	local net_prefix
	local devname
	local neigh

	nsname=$(nsname_rt "${rt}")

	for neigh in ${rt_neighs}; do
		devname="veth-rt-${rt}-${neigh}"

		net_prefix="$(get_network_prefix "${rt}" "${neigh}")"

		ip -netns "${nsname}" addr \
			add "${net_prefix}::${rt}/64" dev "${devname}" nodad

		ip -netns "${nsname}" link set "${devname}" up
	done

	ip -netns "${nsname}" link add "${DUMMY_DEVNAME}" type dummy

	ip -netns "${nsname}" link set "${DUMMY_DEVNAME}" up
	ip -netns "${nsname}" link set lo up

	ip netns exec "${nsname}" sysctl -wq net.ipv6.conf.all.accept_dad=0
	ip netns exec "${nsname}" sysctl -wq net.ipv6.conf.default.accept_dad=0
	ip netns exec "${nsname}" sysctl -wq net.ipv6.conf.all.forwarding=1
	ip netns exec "${nsname}" sysctl -wq net.ipv4.ip_forward=1
}

# Set up SID reachability routes, the End behavior, and the fib rule
# for the localsid table. SID reachability routes are installed in the
# main table (normal forwarding). The localsid table (90) contains
# local SIDs: the End behavior for transit and the End.DT2U (installed
# separately in each setup_bridge_* function).
# args:
#  $1 - router ID
#  $2 - space-separated neighbor IDs
setup_rt_local_sids()
{
	local rt="$1"
	local rt_neighs="$2"
	local net_prefix
	local devname
	local nsname
	local neigh

	nsname=$(nsname_rt "${rt}")

	for neigh in ${rt_neighs}; do
		devname="veth-rt-${rt}-${neigh}"

		net_prefix="$(get_network_prefix "${rt}" "${neigh}")"

		ip -netns "${nsname}" -6 route \
			add "${VPN_LOCATOR_SERVICE}:${neigh}::/32" \
			via "${net_prefix}::${neigh}" dev "${devname}"
	done

	ip -netns "${nsname}" -6 route \
		add "${VPN_LOCATOR_SERVICE}:${rt}::${END_FUNC}" \
		table "${LOCALSID_TABLE_ID}" \
		encap seg6local action End dev "${DUMMY_DEVNAME}"

	ip -netns "${nsname}" -6 rule add \
		to "${VPN_LOCATOR_SERVICE}::/16" \
		lookup "${LOCALSID_TABLE_ID}" prio 999
}

# Set up a host connected to a router.
# args:
#  $1 - host ID
#  $2 - attached router ID
setup_hs()
{
	local hs="$1"
	local rt="$2"
	local hsname
	local rtname

	hsname=$(nsname_hs "${hs}")
	rtname=$(nsname_rt "${rt}")

	ip netns exec "${hsname}" sysctl -wq net.ipv6.conf.all.accept_dad=0
	ip netns exec "${hsname}" sysctl -wq net.ipv6.conf.default.accept_dad=0

	ip -netns "${hsname}" link add "${HS_VETH_NAME}" type veth \
		peer name "${RT2HS_DEVNAME}" netns "${rtname}"

	ip -netns "${hsname}" addr add "${IPv6_HS_NETWORK}::${hs}/64" \
		dev "${HS_VETH_NAME}" nodad
	ip -netns "${hsname}" addr add "${IPv4_HS_NETWORK}.${hs}/24" \
		dev "${HS_VETH_NAME}"

	ip -netns "${hsname}" link set "${HS_VETH_NAME}" up
	ip -netns "${hsname}" link set lo up

	ip -netns "${rtname}" link set "${RT2HS_DEVNAME}" up
}

# Create bridge, wire sr6-0 and veth-hs as ports.
# sr6-0 must already exist.
# args:
#  $1 - netns
__setup_bridge()
{
	local nsname="$1"

	ip -netns "${nsname}" link add "${BRIDGE_DEVNAME}" type bridge
	ip -netns "${nsname}" link set "${BRIDGE_DEVNAME}" up

	ip -netns "${nsname}" link set "${RT2HS_DEVNAME}" master \
		"${BRIDGE_DEVNAME}"
	ip -netns "${nsname}" link set "${SR6_DEVNAME}" master \
		"${BRIDGE_DEVNAME}"
}

# Add overlay IPs to the bridge and install the End.DT2U local SID.
# If a VRF is used, the bridge must already be enslaved to it so that
# the addresses are created in the correct routing context.
# args:
#  $1 - netns
#  $2 - local router ID
__setup_bridge_ips_and_sid()
{
	local nsname="$1"
	local rt="$2"

	local gw_id=$((200 + rt))

	ip -netns "${nsname}" addr add "${IPv6_HS_NETWORK}::${gw_id}/64" \
		dev "${BRIDGE_DEVNAME}" nodad
	ip -netns "${nsname}" addr \
		add "${IPv4_HS_NETWORK}.${gw_id}/24" dev "${BRIDGE_DEVNAME}"

	ip -netns "${nsname}" -6 route \
		add "${VPN_LOCATOR_SERVICE}:${rt}::${DT2U_FUNC}" \
		table "${LOCALSID_TABLE_ID}" \
		encap seg6local action End.DT2U l2dev "${SR6_DEVNAME}" \
		dev "${DUMMY_DEVNAME}"
}

# Expected MTU of an sr6 device, that is the Ethernet default less the
# encapsulation overhead, made of the 40 bytes of the outer IPv6 header,
# the SRH and the 14 bytes of the inner Ethernet header. With no TLV an
# SRH is 8 bytes plus 16 per SID.
# args:
#  $1 - encapsulation mode (full or reduced)
#  $2 - number of SIDs
sr6_expected_mtu()
{
	local mode="$1"
	local nsegs="$2"
	local srhlen=0

	if [ "${mode}" = "reduced" ]; then
		nsegs=$((nsegs - 1))
	fi

	if [ "${nsegs}" -gt 0 ]; then
		srhlen=$((8 + 16 * nsegs))
	fi

	echo $((ETH_DATA_LEN - 40 - srhlen - 14))
}

# Read the MTU of a device.
# args:
#  $1 - netns
#  $2 - device name
get_mtu()
{
	local nsname="$1"
	local devname="$2"

	ip -netns "${nsname}" -o link show "${devname}" | \
		sed -n 's/.*mtu \([0-9]\+\).*/\1/p'
}

# Create sr6 device and bring it up.
# args:
#  $1 - netns
#  $2 - transit router IDs (space-separated, empty for direct path)
#  $3 - remote router ID (decap endpoint)
#  $4 - FIB table for direct lookup (empty for none)
#  $5 - encapsulation mode (full or reduced)
__setup_sr6()
{
	local nsname="$1"
	local end_rts="$2"
	local remote_rt="$3"
	local table="$4"
	local mode="$5"
	local table_arg=""
	local segs=""
	local n

	if [ -n "${table}" ]; then
		table_arg="table ${table}"
	fi

	for n in ${end_rts}; do
		segs="${segs}${VPN_LOCATOR_SERVICE}:${n}::${END_FUNC},"
	done
	segs="${segs}${VPN_LOCATOR_SERVICE}:${remote_rt}::${DT2U_FUNC}"

	ip -netns "${nsname}" link add "${SR6_DEVNAME}" type sr6 \
		mode "${mode}" \
		segs "${segs}" \
		${table_arg}
	ip -netns "${nsname}" link set "${SR6_DEVNAME}" up
}

# Create VRF and enslave the bridge to it.
# args:
#  $1 - netns
__setup_vrf()
{
	local nsname="$1"

	ip -netns "${nsname}" link add "${VRF_DEVNAME}" type vrf \
		table "${VRF_TABLE_ID}"
	ip -netns "${nsname}" link set "${VRF_DEVNAME}" up
	ip -netns "${nsname}" link set "${BRIDGE_DEVNAME}" master \
		"${VRF_DEVNAME}"
}

# Move the SID reachability route from the main table to target_table.
# args:
#  $1 - netns
#  $2 - local router ID
#  $3 - remote router ID
#  $4 - destination FIB table ID
__move_sid_route()
{
	local nsname="$1"
	local rt="$2"
	local remote_rt="$3"
	local target_table="$4"
	local net_prefix
	local devname

	net_prefix="$(get_network_prefix "${rt}" "${remote_rt}")"
	devname="veth-rt-${rt}-${remote_rt}"

	ip -netns "${nsname}" -6 route \
		del "${VPN_LOCATOR_SERVICE}:${remote_rt}::/32"

	ip -netns "${nsname}" -6 route \
		add "${VPN_LOCATOR_SERVICE}:${remote_rt}::/32" \
		table "${target_table}" \
		via "${net_prefix}::${remote_rt}" dev "${devname}"
}

# Post-encap routing uses fib rules (default behavior).
# args:
#  $1 - local router ID
#  $2 - remote router ID
#  $3 - transit router IDs (space-separated)
#  $4 - encapsulation mode (full or reduced)
setup_bridge_plain()
{
	local rt="$1"
	local remote_rt="$2"
	local end_rts="$3"
	local mode="$4"
	local nsname

	nsname=$(nsname_rt "${rt}")

	__setup_sr6 "${nsname}" "${end_rts}" "${remote_rt}" "" "${mode}"
	__setup_bridge "${nsname}"
	__setup_bridge_ips_and_sid "${nsname}" "${rt}"
}

# Bridge in VRF; sr6 inherits the VRF routing context via l3mdev.
# The SID reachability route for the first SID is moved to the VRF
# table and a blackhole is installed in the main table to verify that
# sr6 uses the VRF context and not the main table for the post-encap
# lookup.
# args:
#  $1 - local router ID
#  $2 - remote router ID
#  $3 - transit router IDs (space-separated)
#  $4 - encapsulation mode (full or reduced)
setup_bridge_vrf()
{
	local rt="$1"
	local remote_rt="$2"
	local end_rts="$3"
	local mode="$4"
	local nsname
	local first_hop

	nsname=$(nsname_rt "${rt}")

	if [ -n "${end_rts}" ]; then
		first_hop="${end_rts%% *}"
	else
		first_hop="${remote_rt}"
	fi

	__setup_sr6 "${nsname}" "${end_rts}" "${remote_rt}" "" "${mode}"
	__setup_bridge "${nsname}"
	__setup_vrf "${nsname}"
	__setup_bridge_ips_and_sid "${nsname}" "${rt}"
	__move_sid_route "${nsname}" "${rt}" "${first_hop}" "${VRF_TABLE_ID}"

	ip -netns "${nsname}" -6 route \
		add blackhole "${VPN_LOCATOR_SERVICE}:${first_hop}::/32"
}

# sr6 with explicit FIB table; direct table lookup bypasses fib rules.
# The SID reachability route for the first SID is moved to the encap
# table.
# args:
#  $1 - local router ID
#  $2 - remote router ID
#  $3 - transit router IDs (space-separated)
#  $4 - encapsulation mode (full or reduced)
setup_bridge_table()
{
	local rt="$1"
	local remote_rt="$2"
	local end_rts="$3"
	local mode="$4"
	local nsname
	local first_hop

	nsname=$(nsname_rt "${rt}")

	if [ -n "${end_rts}" ]; then
		first_hop="${end_rts%% *}"
	else
		first_hop="${remote_rt}"
	fi

	__setup_sr6 "${nsname}" "${end_rts}" "${remote_rt}" \
		"${SR6_FIB_TABLE_ID}" "${mode}"
	__setup_bridge "${nsname}"
	__setup_bridge_ips_and_sid "${nsname}" "${rt}"
	__move_sid_route "${nsname}" "${rt}" "${first_hop}" "${SR6_FIB_TABLE_ID}"
}

# Bridge in VRF and sr6 with explicit table. The VRF table has a
# blackhole for the first SID; the explicit table has the correct
# route. The table parameter must take precedence over VRF context.
# args:
#  $1 - local router ID
#  $2 - remote router ID
#  $3 - transit router IDs (space-separated)
#  $4 - encapsulation mode (full or reduced)
setup_bridge_vrf_table()
{
	local rt="$1"
	local remote_rt="$2"
	local end_rts="$3"
	local mode="$4"
	local nsname
	local first_hop

	nsname=$(nsname_rt "${rt}")

	if [ -n "${end_rts}" ]; then
		first_hop="${end_rts%% *}"
	else
		first_hop="${remote_rt}"
	fi

	__setup_sr6 "${nsname}" "${end_rts}" "${remote_rt}" \
		"${SR6_FIB_TABLE_ID}" "${mode}"
	__setup_bridge "${nsname}"
	__setup_vrf "${nsname}"
	__setup_bridge_ips_and_sid "${nsname}" "${rt}"

	ip -netns "${nsname}" -6 route \
		add blackhole "${VPN_LOCATOR_SERVICE}:${first_hop}::/32" \
		table "${VRF_TABLE_ID}"

	__move_sid_route "${nsname}" "${rt}" "${first_hop}" "${SR6_FIB_TABLE_ID}"
}

setup()
{
	local i

	# create routers
	ROUTERS="1 2 3 4"; readonly ROUTERS
	for i in ${ROUTERS}; do
		create_router "${i}"
	done

	# create hosts
	HOSTS="1 2 3 4"; readonly HOSTS
	for i in ${HOSTS}; do
		create_host "${i}"
	done

	# set up the links for connecting routers (full mesh)
	add_link_rt_pairs 1 "2 3 4"
	add_link_rt_pairs 2 "3 4"
	add_link_rt_pairs 3 "4"

	# set up the basic connectivity of routers and routes required for
	# reachability of SIDs.
	setup_rt_networking 1 "2 3 4"
	setup_rt_networking 2 "1 3 4"
	setup_rt_networking 3 "1 2 4"
	setup_rt_networking 4 "1 2 3"

	# set up the hosts connected to routers
	setup_hs 1 1
	setup_hs 2 2
	setup_hs 3 3
	setup_hs 4 4

	# set up SID reachability routes and fib rules
	setup_rt_local_sids 1 "2 3 4"
	setup_rt_local_sids 2 "1 3 4"
	setup_rt_local_sids 3 "1 2 4"
	setup_rt_local_sids 4 "1 2 3"

	# VPN 1: hs-1 (rt-1, plain) <-> hs-2 (rt-2, VRF)
	setup_bridge_plain 1 2 "" reduced
	setup_bridge_vrf 2 1 4 full

	# VPN 2: hs-3 (rt-3, table) <-> hs-4 (rt-4, VRF+table)
	setup_bridge_table 3 4 1 full
	setup_bridge_vrf_table 4 3 "2 1" reduced

	# testing environment was set up successfully
	SETUP_ERR=0
}

check_rt_connectivity()
{
	local rtsrc="$1"
	local rtdst="$2"
	local prefix
	local rtsrc_nsname

	rtsrc_nsname=$(nsname_rt "${rtsrc}")

	prefix="$(get_network_prefix "${rtsrc}" "${rtdst}")"

	ip netns exec "${rtsrc_nsname}" ping -c 1 -W "${PING_TIMEOUT_SEC}" \
		"${prefix}::${rtdst}" >/dev/null 2>&1
}

check_and_log_rt_connectivity()
{
	local rtsrc="$1"
	local rtdst="$2"

	check_rt_connectivity "${rtsrc}" "${rtdst}"
	log_test $? 0 "Routers connectivity: rt-${rtsrc} -> rt-${rtdst}"
}

check_hs_ipv6_connectivity()
{
	local hssrc="$1"
	local hsdst="$2"
	local cpu="$3"
	local hssrc_nsname
	local pin=""

	if [ -n "${cpu}" ]; then
		pin="taskset -c ${cpu}"
	fi

	hssrc_nsname=$(nsname_hs "${hssrc}")

	ip netns exec "${hssrc_nsname}" ${pin} \
		ping -c 1 -W "${PING_TIMEOUT_SEC}" \
		"${IPv6_HS_NETWORK}::${hsdst}" >/dev/null 2>&1
}

check_hs_ipv4_connectivity()
{
	local hssrc="$1"
	local hsdst="$2"
	local cpu="$3"
	local hssrc_nsname
	local pin=""

	if [ -n "${cpu}" ]; then
		pin="taskset -c ${cpu}"
	fi

	hssrc_nsname=$(nsname_hs "${hssrc}")

	ip netns exec "${hssrc_nsname}" ${pin} \
		ping -c 1 -W "${PING_TIMEOUT_SEC}" \
		"${IPv4_HS_NETWORK}.${hsdst}" >/dev/null 2>&1
}

check_and_log_hs2gw_connectivity()
{
	local hssrc="$1"

	local gw_id=$((200 + hssrc))

	check_hs_ipv6_connectivity "${hssrc}" "${gw_id}"
	log_test $? 0 "IPv6 Hosts connectivity: hs-${hssrc} -> gw"

	check_hs_ipv4_connectivity "${hssrc}" "${gw_id}"
	log_test $? 0 "IPv4 Hosts connectivity: hs-${hssrc} -> gw"
}

check_and_log_hs_ipv6_connectivity()
{
	local hssrc="$1"
	local hsdst="$2"

	check_hs_ipv6_connectivity "${hssrc}" "${hsdst}"
	log_test $? 0 "IPv6 Hosts connectivity: hs-${hssrc} -> hs-${hsdst}"
}

check_and_log_hs_ipv4_connectivity()
{
	local hssrc="$1"
	local hsdst="$2"

	check_hs_ipv4_connectivity "${hssrc}" "${hsdst}"
	log_test $? 0 "IPv4 Hosts connectivity: hs-${hssrc} -> hs-${hsdst}"
}

check_and_log_hs_connectivity()
{
	local hssrc="$1"
	local hsdst="$2"

	check_and_log_hs_ipv4_connectivity "${hssrc}" "${hsdst}"
	check_and_log_hs_ipv6_connectivity "${hssrc}" "${hsdst}"
}

check_and_log_hs_ipv6_isolation()
{
	local hssrc="$1"
	local hsdst="$2"

	check_hs_ipv6_connectivity "${hssrc}" "${hsdst}"
	log_test $? 1 "IPv6 Hosts isolation: hs-${hssrc} -X-> hs-${hsdst}"
}

check_and_log_hs_ipv4_isolation()
{
	local hssrc="$1"
	local hsdst="$2"

	check_hs_ipv4_connectivity "${hssrc}" "${hsdst}"
	log_test $? 1 "IPv4 Hosts isolation: hs-${hssrc} -X-> hs-${hsdst}"
}

check_and_log_hs_isolation()
{
	local hssrc="$1"
	local hsdst="$2"

	check_and_log_hs_ipv4_isolation "${hssrc}" "${hsdst}"
	check_and_log_hs_ipv6_isolation "${hssrc}" "${hsdst}"
}

# Ping from a host to a remote router's bridge IP through the L2 VPN.
# args:
#  $1 - source host ID
#  $2 - destination router ID
check_and_log_hs2rt_connectivity()
{
	local hssrc="$1"
	local rtdst="$2"
	local gw_id=$((200 + rtdst))

	check_hs_ipv6_connectivity "${hssrc}" "${gw_id}"
	log_test $? 0 "IPv6 VPN connectivity: hs-${hssrc} -> rt-${rtdst}"

	check_hs_ipv4_connectivity "${hssrc}" "${gw_id}"
	log_test $? 0 "IPv4 VPN connectivity: hs-${hssrc} -> rt-${rtdst}"
}

check_rt_vpn_ipv6_connectivity()
{
	local rtsrc="$1"
	local dst_id="$2"
	local rtsrc_nsname

	rtsrc_nsname=$(nsname_rt "${rtsrc}")

	ip netns exec "${rtsrc_nsname}" ping -c 1 -W "${PING_TIMEOUT_SEC}" \
		-I "${BRIDGE_DEVNAME}" \
		"${IPv6_HS_NETWORK}::${dst_id}" >/dev/null 2>&1
}

check_rt_vpn_ipv4_connectivity()
{
	local rtsrc="$1"
	local dst_id="$2"
	local rtsrc_nsname

	rtsrc_nsname=$(nsname_rt "${rtsrc}")

	ip netns exec "${rtsrc_nsname}" ping -c 1 -W "${PING_TIMEOUT_SEC}" \
		-I "${BRIDGE_DEVNAME}" \
		"${IPv4_HS_NETWORK}.${dst_id}" >/dev/null 2>&1
}

# Ping from a router's bridge to the remote router's bridge IP through
# the L2 VPN. Uses -I br0 to ensure the VRF routing context is used
# when the bridge is enslaved to a VRF.
# args:
#  $1 - source router ID
#  $2 - destination router ID
check_and_log_rt_vpn_connectivity()
{
	local rtsrc="$1"
	local rtdst="$2"
	local gw_id=$((200 + rtdst))

	check_rt_vpn_ipv6_connectivity "${rtsrc}" "${gw_id}"
	log_test $? 0 "IPv6 VPN connectivity: rt-${rtsrc} -> rt-${rtdst}"

	check_rt_vpn_ipv4_connectivity "${rtsrc}" "${gw_id}"
	log_test $? 0 "IPv4 VPN connectivity: rt-${rtsrc} -> rt-${rtdst}"
}

router_tests()
{
	local i
	local j

	log_section "IPv6 routers connectivity test"

	for i in ${ROUTERS}; do
		for j in ${ROUTERS}; do
			if [ "${i}" -eq "${j}" ]; then
				continue
			fi

			check_and_log_rt_connectivity "${i}" "${j}"
		done
	done
}

host2gateway_tests()
{
	local hs

	log_section "IPv4/IPv6 connectivity test among hosts and gateways"

	for hs in ${HOSTS}; do
		check_and_log_hs2gw_connectivity "${hs}"
	done
}

host_vpn_tests()
{
	log_section "SRv6 sr6 L2 VPN: plain (rt-1) <-> VRF (rt-2)"

	check_and_log_hs_connectivity 1 2
	check_and_log_hs_connectivity 2 1
}

host_vpn_fib_table_tests()
{
	log_section "SRv6 sr6 L2 VPN: table (rt-3) <-> VRF+table (rt-4)"

	check_and_log_hs_connectivity 3 4
	check_and_log_hs_connectivity 4 3
}

host_vpn_remote_gw_tests()
{
	log_section "SRv6 sr6 L2 VPN: host to remote gateway"

	check_and_log_hs2rt_connectivity 1 2
	check_and_log_hs2rt_connectivity 2 1

	check_and_log_hs2rt_connectivity 3 4
	check_and_log_hs2rt_connectivity 4 3
}

rt_vpn_tests()
{
	log_section "SRv6 sr6 L2 VPN: router to router"

	check_and_log_rt_vpn_connectivity 1 2
	check_and_log_rt_vpn_connectivity 2 1

	check_and_log_rt_vpn_connectivity 3 4
	check_and_log_rt_vpn_connectivity 4 3
}

host_vpn_isolation_tests()
{
	local l1="1 2"
	local l2="3 4"
	local tmp
	local i
	local j
	local k

	log_section "SRv6 sr6 L2 VPN isolation test"

	for k in 0 1; do
		for i in ${l1}; do
			for j in ${l2}; do
				check_and_log_hs_isolation "${i}" "${j}"
			done
		done

		tmp="${l1}"; l1="${l2}"; l2="${tmp}"
	done
}

# Test that sr6 handles implicit routing context changes.
# rt-1 starts in plain mode (no VRF). We enslave its bridge to a VRF,
# which changes the l3mdev context inherited by sr6, then restore
# plain mode, verifying connectivity at each step.
# All pings are pinned to the same CPU so that the per-CPU dst_cache
# slot populated by the first ping is the one used by subsequent pings.
rt1_vrf_context_change_tests()
{
	local rt=1
	local remote_rt=2
	local nsname
	local net_prefix
	local devname

	log_section "SRv6 sr6 VRF context change (rt-1)"

	nsname=$(nsname_rt "${rt}")
	net_prefix="$(get_network_prefix "${rt}" "${remote_rt}")"
	devname="veth-rt-${rt}-${remote_rt}"

	# baseline: rt-1 is plain, connectivity populates the dst_cache
	check_hs_ipv6_connectivity "${rt}" "${remote_rt}" "${PING_CPU_PIN}"
	log_test $? 0 "IPv6 before VRF change: hs-${rt} -> hs-${remote_rt}"

	check_hs_ipv4_connectivity "${rt}" "${remote_rt}" "${PING_CPU_PIN}"
	log_test $? 0 "IPv4 before VRF change: hs-${rt} -> hs-${remote_rt}"

	# enslave bridge to a new VRF and move the SID route there
	__setup_vrf "${nsname}"
	__move_sid_route "${nsname}" "${rt}" "${remote_rt}" "${VRF_TABLE_ID}"

	check_hs_ipv6_connectivity "${rt}" "${remote_rt}" "${PING_CPU_PIN}"
	log_test $? 0 "IPv6 after bridge enslaved to VRF: hs-${rt} -> hs-${remote_rt}"

	check_hs_ipv4_connectivity "${rt}" "${remote_rt}" "${PING_CPU_PIN}"
	log_test $? 0 "IPv4 after bridge enslaved to VRF: hs-${rt} -> hs-${remote_rt}"

	# restore plain mode: re-add route to main before leaving the VRF
	# so that the fresh lookup after cache reset finds the route
	ip -netns "${nsname}" -6 route \
		add "${VPN_LOCATOR_SERVICE}:${remote_rt}::/32" \
		via "${net_prefix}::${remote_rt}" dev "${devname}"

	ip -netns "${nsname}" link set "${BRIDGE_DEVNAME}" nomaster

	ip -netns "${nsname}" -6 route \
		del "${VPN_LOCATOR_SERVICE}:${remote_rt}::/32" \
		table "${VRF_TABLE_ID}"
	ip -netns "${nsname}" link del "${VRF_DEVNAME}"

	check_hs_ipv6_connectivity "${rt}" "${remote_rt}" "${PING_CPU_PIN}"
	log_test $? 0 "IPv6 after restoring plain mode: hs-${rt} -> hs-${remote_rt}"

	check_hs_ipv4_connectivity "${rt}" "${remote_rt}" "${PING_CPU_PIN}"
	log_test $? 0 "IPv4 after restoring plain mode: hs-${rt} -> hs-${remote_rt}"
}

device_creation_error_tests()
{
	local mtu
	local tns

	log_section "SRv6 sr6 device creation errors"

	if ! setup_ns tns; then
		log_test 1 0 "setup netns for creation error tests"
		return
	fi

	! ip -netns "${tns}" link add sr6-bad type sr6 mode full 2>/dev/null
	log_test $? 0 "Reject sr6 without segs"

	! ip -netns "${tns}" link add sr6-bad type sr6 segs fc00::1 2>/dev/null
	log_test $? 0 "Reject sr6 without encap mode"

	! ip -netns "${tns}" link add sr6-bad type sr6 mode full \
		segs fc00::1 table 0 2>/dev/null
	log_test $? 0 "Reject sr6 with fib_table=0"

	! ip -netns "${tns}" link add sr6-bad mtu 65500 type sr6 mode full \
		segs fc00::1 2>/dev/null
	log_test $? 0 "Reject sr6 with MTU above the encapsulation limit"

	ip -netns "${tns}" link add sr6-ok type sr6 mode full segs fc00::1
	log_test $? 0 "Accept sr6 with valid segs"

	ip -netns "${tns}" link add sr6-tbl type sr6 mode full \
		segs fc00::2 table 100
	log_test $? 0 "Accept sr6 with valid fib_table"

	ip -netns "${tns}" link add sr6-red type sr6 mode reduced \
		segs fc00::1,fc00::2,fc00::3
	log_test $? 0 "Accept sr6 with reduced encap mode"

	mtu="$(get_mtu "${tns}" sr6-red)"
	log_test "${mtu}" "$(sr6_expected_mtu reduced 3)" \
		"Reduced encap with three SIDs: MTU accounts for one SID less"

	ip -netns "${tns}" link add sr6-red1 type sr6 mode reduced \
		segs fc00::1
	log_test $? 0 "Accept sr6 with reduced encap mode and one SID"

	mtu="$(get_mtu "${tns}" sr6-red1)"
	log_test "${mtu}" "$(sr6_expected_mtu reduced 1)" \
		"Reduced encap with one SID: MTU accounts for no SRH"

	cleanup_ns "${tns}"
}

sr6_encap_mode_tests()
{
	local mtu

	log_section "SRv6 sr6 encapsulation mode"

	mtu="$(get_mtu "$(nsname_rt 1)" "${SR6_DEVNAME}")"
	log_test "${mtu}" "$(sr6_expected_mtu reduced 1)" \
		"rt-1 reduced encap, one SID: MTU accounts for no SRH"

	mtu="$(get_mtu "$(nsname_rt 4)" "${SR6_DEVNAME}")"
	log_test "${mtu}" "$(sr6_expected_mtu reduced 3)" \
		"rt-4 reduced encap, three SIDs: MTU accounts for one SID less"

	mtu="$(get_mtu "$(nsname_rt 2)" "${SR6_DEVNAME}")"
	log_test "${mtu}" "$(sr6_expected_mtu full 2)" \
		"rt-2 full encap, two SIDs: MTU accounts for the whole SRH"

	mtu="$(get_mtu "$(nsname_rt 3)" "${SR6_DEVNAME}")"
	log_test "${mtu}" "$(sr6_expected_mtu full 2)" \
		"rt-3 full encap, two SIDs: MTU accounts for the whole SRH"
}

l2dev_error_tests()
{
	local rt=2
	local nsname

	log_section "SRv6 End.DT2U l2dev error paths"

	nsname=$(nsname_rt "${rt}")

	! ip -netns "${nsname}" -6 route \
		add "${VPN_LOCATOR_SERVICE}:${rt}::${DT2U_BAD_FUNC}" \
		table "${LOCALSID_TABLE_ID}" \
		encap seg6local action End.DT2U l2dev "${DUMMY_DEVNAME}" \
		dev "${DUMMY_DEVNAME}" 2>/dev/null
	log_test $? 0 "Reject End.DT2U with an l2dev out of a bridge and not sr6"

	check_hs_ipv6_connectivity 1 2
	log_test $? 0 "IPv6 baseline: hs-1 -> hs-2"

	ip -netns "${nsname}" link set "${SR6_DEVNAME}" down

	check_hs_ipv6_connectivity 1 2
	log_test $? 1 "IPv6 l2dev down: hs-1 -X-> hs-2"

	ip -netns "${nsname}" link set "${SR6_DEVNAME}" up
	sleep 1

	check_hs_ipv6_connectivity 1 2
	log_test $? 0 "IPv6 l2dev restored: hs-1 -> hs-2"

	ip -netns "${nsname}" link set "${SR6_DEVNAME}" nomaster

	check_hs_ipv6_connectivity 1 2
	log_test $? 1 "IPv6 l2dev out of the bridge: hs-1 -X-> hs-2"

	ip -netns "${nsname}" link set "${SR6_DEVNAME}" master \
		"${BRIDGE_DEVNAME}"
	sleep 1

	check_hs_ipv6_connectivity 1 2
	log_test $? 0 "IPv6 l2dev re-added to bridge: hs-1 -> hs-2"
}

sr6_standalone_tests()
{
	local rt=1
	local nsname

	log_section "SRv6 sr6 standalone (no bridge)"

	nsname=$(nsname_rt "${rt}")

	ip -netns "${nsname}" link set "${SR6_DEVNAME}" nomaster

	ip -netns "${nsname}" addr add "${IPv6_HS_NETWORK}::99/64" \
		dev "${SR6_DEVNAME}" nodad
	ip -netns "${nsname}" addr add "${IPv4_HS_NETWORK}.99/24" \
		dev "${SR6_DEVNAME}"

	# The bridge still has an overlay IPv4 address (10.0.0.201/24) from
	# the setup, creating a 10.0.0.0/24 route via br0 that competes
	# with the one via sr6-0. Remove the bridge route so that replies
	# from the standalone sr6 go through sr6_xmit, not the bridge.
	ip -netns "${nsname}" route del "${IPv4_HS_NETWORK}.0/24" \
		dev "${BRIDGE_DEVNAME}" 2>/dev/null || true
	sleep 1

	check_hs_ipv6_connectivity 2 99
	log_test $? 0 "IPv6 standalone sr6: hs-2 -> sr6 on rt-1"

	check_hs_ipv4_connectivity 2 99
	log_test $? 0 "IPv4 standalone sr6: hs-2 -> sr6 on rt-1"

	ip -netns "${nsname}" addr del "${IPv6_HS_NETWORK}::99/64" \
		dev "${SR6_DEVNAME}" 2>/dev/null
	ip -netns "${nsname}" addr del "${IPv4_HS_NETWORK}.99/24" \
		dev "${SR6_DEVNAME}" 2>/dev/null
	ip -netns "${nsname}" link set "${SR6_DEVNAME}" master \
		"${BRIDGE_DEVNAME}"
	# Restore the IPv4 route via bridge deleted before standalone tests
	ip -netns "${nsname}" route add "${IPv4_HS_NETWORK}.0/24" \
		dev "${BRIDGE_DEVNAME}" 2>/dev/null || true
	sleep 1

	check_hs_ipv6_connectivity 1 2
	log_test $? 0 "IPv6 after restoring bridge: hs-1 -> hs-2"
}

test_dummy_dev_or_ksft_skip()
{
	local tns

	if ! setup_ns tns; then
		echo "SKIP: Cannot set up netns for testing dummy dev support"
		exit "${ksft_skip}"
	fi

	modprobe dummy &>/dev/null || true
	if ! ip -netns "${tns}" link add "${DUMMY_DEVNAME}" type dummy; then
		echo "SKIP: dummy dev not supported"
		cleanup_ns "${tns}"
		exit "${ksft_skip}"
	fi

	cleanup_ns "${tns}"
}

test_sr6_dev_or_ksft_skip()
{
	local tns

	if ! setup_ns tns; then
		echo "SKIP: Cannot set up netns for testing sr6 dev support"
		exit "${ksft_skip}"
	fi

	modprobe sr6 &>/dev/null || true
	if ! ip -netns "${tns}" link add sr6-test type sr6 mode full \
		segs fc00::1; then
		echo "SKIP: sr6 dev not supported"
		cleanup_ns "${tns}"
		exit "${ksft_skip}"
	fi

	cleanup_ns "${tns}"
}

test_vrf_dev_or_ksft_skip()
{
	local tns

	if ! setup_ns tns; then
		echo "SKIP: Cannot set up netns for testing VRF support"
		exit "${ksft_skip}"
	fi

	if ! ip -netns "${tns}" link add vrf-test type vrf table 9999; then
		echo "SKIP: VRF dev not supported"
		cleanup_ns "${tns}"
		exit "${ksft_skip}"
	fi

	cleanup_ns "${tns}"
}

test_iproute2_supp_or_ksft_skip()
{
	if ! ip route help 2>&1 | grep -qo "End.DT2U"; then
		echo "SKIP: Missing SRv6 End.DT2U support in iproute2"
		exit "${ksft_skip}"
	fi

	if ! ip link help sr6 2>&1 | grep -qo "sr6"; then
		echo "SKIP: Missing sr6 link type support in iproute2"
		exit "${ksft_skip}"
	fi
}

if [ "$(id -u)" -ne 0 ]; then
	echo "SKIP: Need root privileges"
	exit "${ksft_skip}"
fi

# required programs to carry out this selftest
test_command_or_ksft_skip ip
test_command_or_ksft_skip ping
test_command_or_ksft_skip sysctl
test_command_or_ksft_skip grep
test_command_or_ksft_skip taskset

test_iproute2_supp_or_ksft_skip
test_dummy_dev_or_ksft_skip
test_sr6_dev_or_ksft_skip
test_vrf_dev_or_ksft_skip

set -e
trap cleanup EXIT

setup
set +e

router_tests
sr6_encap_mode_tests
host2gateway_tests
host_vpn_tests
host_vpn_fib_table_tests
host_vpn_remote_gw_tests
rt_vpn_tests
host_vpn_isolation_tests
rt1_vrf_context_change_tests
device_creation_error_tests
l2dev_error_tests
sr6_standalone_tests

print_log_test_results
