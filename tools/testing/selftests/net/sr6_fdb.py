#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""sr6 FDB tests; raw rtnetlink avoids requiring new iproute2 syntax."""

import contextlib
import ctypes
import errno
import os
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback

# include/uapi/linux/{rtnetlink,neighbour,if_link,seg6_local,lwtunnel}.h
NEWLINK, DELLINK, GETLINK = 16, 17, 18
NEWNEIGH, DELNEIGH, GETNEIGH = 28, 29, 30
REQUEST, ACK, ECHO = 1, 4, 8
REPLACE, EXCL, CREATE, APPEND = 0x100, 0x200, 0x400, 0x800
DUMP = 0x300
NDA_LLADDR, NDA_SR6 = 2, 18
SR6_SRH, SR6_MODE, SR6_TABLE, SR6_OLD = 1, 2, 3, 4
IFLA_SR6_SRH, IFLA_SR6_FIB_TABLE, IFLA_SR6_ENCAP_MODE = 1, 2, 3
FULL, REDUCED = 0, 1
SELF, REACHABLE, PERMANENT = 2, 0x02, 0x80
NESTED = 0x8000
ETH_P_TEST = 0x88B5
LOCAL_MAC = bytes.fromhex("020000000010")
MACS = [bytes.fromhex(f"02000000000{i}") for i in range(1, 4)]
ZERO = bytes(6)
BCAST = b"\xff" * 6


def attr(kind, data):
    length = len(data) + 4
    return struct.pack("=HH", length, kind) + data + bytes(-length % 4)


def attrs(data):
    result = {}
    while data:
        length, kind = struct.unpack_from("=HH", data)
        assert 4 <= length <= len(data), "invalid netlink attribute"
        result[kind & ~NESTED] = data[4:length]
        data = data[(length + 3) & ~3:]
    return result


def u32(value):
    return struct.pack("=I", value)


def sr6(policy=None, mode=None, table=None, old=None, old_table=None):
    data = b""
    if policy is not None:
        data += attr(SR6_SRH, policy)
    if mode is not None:
        data += attr(SR6_MODE, bytes([mode]))
    if table is not None:
        data += attr(SR6_TABLE, u32(table))
    if old is not None:
        sel = attr(SR6_SRH, old)
        if old_table is not None:
            sel += attr(SR6_TABLE, u32(old_table))
        data += attr(SR6_OLD | NESTED, sel)
    return attr(NDA_SR6 | NESTED, data)


def remote(msg):
    """Return (mac, srh, mode, table) of an FDB message."""
    data = attrs(msg[12:])
    pol = attrs(data[NDA_SR6])
    table = struct.unpack("=I", pol[SR6_TABLE])[0] if SR6_TABLE in pol else 0
    return data[NDA_LLADDR], pol[SR6_SRH], pol[SR6_MODE][0], table


def link_policy(link):
    data = attrs(attrs(link[18]).get(2, b""))  # IFLA_LINKINFO, INFO_DATA
    if not data:
        return None
    table = data.get(IFLA_SR6_FIB_TABLE)
    return (data[IFLA_SR6_SRH], data[IFLA_SR6_ENCAP_MODE][0],
            struct.unpack("=I", table)[0] if table else 0)


def srh(*sids):
    count = len(sids)
    return (struct.pack("=BBBBBBH", 0, 2 * count, 4, count - 1,
                        count - 1, 0, 0) +
            b"".join(socket.inet_pton(socket.AF_INET6, sid)
                     for sid in reversed(sids)))


def ip(*args):
    try:
        return subprocess.check_output(["ip", *map(str, args)],
                                       stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"ip {' '.join(map(str, args))}: {error.output}") from error


@contextlib.contextmanager
def netns(name):
    original = os.open("/proc/self/ns/net", os.O_RDONLY)
    target = os.open(f"/run/netns/{name}", os.O_RDONLY)
    libc = ctypes.CDLL(None, use_errno=True)

    def enter(fd):
        if libc.setns(fd, 0):
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))

    try:
        enter(target)
        yield
    finally:
        enter(original)
        os.close(target)
        os.close(original)


class Netlink:
    def __init__(self, groups=0):
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
        self.sock.bind((0, groups))
        self.sock.setsockopt(270, 12, 1)  # SOL_NETLINK, NETLINK_GET_STRICT_CHK
        self.sock.settimeout(3)
        self.seq = 0

    def close(self):
        self.sock.close()

    def request(self, kind, payload, flags=0):
        self.seq += 1
        self.sock.send(struct.pack("=IHHII", 16 + len(payload), kind,
                                   REQUEST | ACK | flags, self.seq, 0) + payload)
        result = []
        while True:
            for kind, seq, msg in self.receive():
                assert seq == self.seq, "unexpected netlink sequence"
                if kind == 2:
                    code = struct.unpack_from("=i", msg)[0]
                    if code:
                        raise OSError(-code, os.strerror(-code))
                    return result
                if kind == 3:
                    code = struct.unpack_from("=i", msg)[0]
                    if code:
                        raise OSError(-code, os.strerror(-code))
                    return result
                result.append((kind, msg))

    def receive(self):
        data = self.sock.recv(65536)
        result = []
        while data:
            length, kind, flags, seq, _ = struct.unpack_from("=IHHII", data)
            assert not flags & 0x10, "interrupted netlink dump"
            result.append((kind, seq, data[16:length]))
            data = data[(length + 3) & ~3:]
        return result

    def link(self, name, policy=None, mtu=None, mode=None, table=None,
             change=False, echo=False):
        data = b""
        if mode is not None:
            data += attr(IFLA_SR6_ENCAP_MODE, bytes([mode]))
        if policy is not None:
            data += attr(IFLA_SR6_SRH, policy)
        if table is not None:
            data += attr(IFLA_SR6_FIB_TABLE, u32(table))
        info = attr(1, b"sr6\0") + attr(2 | NESTED, data)
        msg = bytes(16) + attr(3, name.encode() + b"\0") + attr(18 | NESTED, info)
        if mtu is not None:
            msg += attr(4, u32(mtu))
        reply = self.request(NEWLINK, msg, (0 if change else CREATE | EXCL) |
                             (ECHO if echo else 0))
        if echo:
            return reply
        return socket.if_nametoindex(name)

    def getlink(self, index):
        msg = struct.pack("=BBHiII", 0, 0, 0, index, 0, 0)
        return attrs(self.request(GETLINK, msg)[0][1][16:])

    def fdb(self, kind, index, mac=None, policy=None, flags=0,
            state=PERMANENT, ndflags=SELF, extra=b"", **kwargs):
        msg = struct.pack("=BBHiHBB", socket.AF_BRIDGE, 0, 0, index,
                          state, ndflags, 0)
        if mac is not None:
            msg += attr(NDA_LLADDR, mac)
        if policy is not None or kwargs:
            msg += sr6(policy, **kwargs)
        return self.request(kind, msg + extra, flags)

    def remotes(self, index):
        return sorted(remote(msg) for _, msg in self.dump(index))

    def dump(self, index):
        return self.fdb(GETNEIGH, index, flags=DUMP, state=0, ndflags=0)

    def mtu(self, index):
        return struct.unpack("=I", self.getlink(index)[4])[0]

    def link_policy(self, index):
        """Return (srh, mode, table) from IFLA_SR6_*, or None."""
        return link_policy(self.getlink(index))

    def tx_dropped(self, index):
        msg = struct.pack("=BBHiII", 0, 0, 0, index, 0, 0)
        reply = self.request(GETLINK, msg)
        stats = attrs(reply[0][1][16:])[23]  # IFLA_STATS64
        return struct.unpack_from("=Q", stats, 7 * 8)[0]

    def dt2u(self, sid, index):
        msg = struct.pack("=BBBBBBBBI", socket.AF_INET6, 128, 0, 0,
                          254, 4, 0, 1, 0)
        msg += attr(1, socket.inet_pton(socket.AF_INET6, sid))
        msg += attr(4, u32(socket.if_nametoindex("dummy0")))
        msg += attr(21, struct.pack("=H", 7))  # LWTUNNEL_ENCAP_SEG6_LOCAL
        msg += attr(22 | NESTED, attr(1, u32(17)) + attr(12, u32(index)))
        self.request(24, msg, CREATE | EXCL)


def expect_error(code, func, *args, **kwargs):
    codes = code if isinstance(code, tuple) else (code,)
    try:
        func(*args, **kwargs)
    except OSError as error:
        assert error.errno in codes, f"expected errno {code}, got {error}"
    else:
        raise AssertionError(f"expected errno {code}, request succeeded")


class Fixture:
    def __init__(self, cpus):
        self.cpus = cpus
        self.names = []
        self.sockets = []
        self.policies = [srh(f"fc00:{i}::d") for i in range(1, 4)]
        self.serial = 0

    def setup(self):
        for i in range(4):
            name = f"sr6-fdb-{os.getpid()}-{i}"
            ip("netns", "add", name)
            self.names.append(name)
            ip("-n", name, "link", "set", "lo", "up")
            ip("-n", name, "link", "add", "dummy0", "type", "dummy")
            ip("-n", name, "link", "set", "dummy0", "up")
            with netns(name):
                nl = Netlink()
                self.sockets.append(nl)
                index = nl.link("tun")
                nl.dt2u(f"fc00:{i}::d", index)
                if i:
                    nl.dt2u("fc00:99::d", index)
                if not i:
                    self.nl, self.index = nl, index
                    self.flood = nl.link("flood", self.policies[0])
                    self.monitor = Netlink(1 << 2)  # RTNLGRP_NEIGH
                    self.sockets.append(self.monitor)
                mac = LOCAL_MAC if not i else MACS[i - 1]
                ip("link", "set", "tun", "address", mac.hex(":"), "up")
                packet = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                       socket.htons(ETH_P_TEST))
                packet.bind(("tun", 0))
                self.sockets.append(packet)
                if not i:
                    self.tx = packet
                    self.rx = []
                    ip("link", "set", "flood", "up")
                    self.flood_tx = socket.socket(socket.AF_PACKET,
                                                  socket.SOCK_RAW,
                                                  socket.htons(ETH_P_TEST))
                    self.flood_tx.bind(("flood", 0))
                    self.sockets.append(self.flood_tx)
                else:
                    self.rx.append(packet)
                    nl.fdb(NEWNEIGH, index, LOCAL_MAC, srh("fc00:0::d"),
                           CREATE | EXCL)
                ip("addr", "add", f"192.0.2.{i or 100}/24", "dev", "tun")
                if i:
                    ip("neigh", "replace", "192.0.2.100", "dev", "tun",
                       "lladdr", LOCAL_MAC.hex(":"), "nud", "permanent")
                for setting in ("all.forwarding", "all.seg6_enabled",
                                "default.seg6_enabled"):
                    with open("/proc/sys/net/ipv6/conf/" +
                              setting.replace(".", "/"), "w") as out:
                        out.write("1")
        for i in range(1, 4):
            root, pe = self.names[0], self.names[i]
            ip("-n", root, "link", "add", f"v{i}", "type", "veth",
               "peer", "name", "underlay", "netns", pe)
            for ns, dev, host in ((root, f"v{i}", 1), (pe, "underlay", 2)):
                ip("-n", ns, "link", "set", dev, "mtu", 9000, "up")
                ip("-n", ns, "addr", "add", f"2001:db8:{i}::{host}/64",
                   "dev", dev, "nodad")
            ip("-n", root, "-6", "route", "add", f"fc00:{i}::/64",
               "via", f"2001:db8:{i}::2", "dev", f"v{i}")
            ip("-n", pe, "-6", "route", "add", "fc00:0::/64",
               "via", f"2001:db8:{i}::1", "dev", "underlay")
            ip("-n", root, "neigh", "replace", f"192.0.2.{i}", "dev", "tun",
               "lladdr", MACS[i - 1].hex(":"), "nud", "permanent")
            # Warm underlay neighbors to make negative delivery checks reliable.
            subprocess.run(["ip", "netns", "exec", root, "ping", "-6",
                            "-c", "1", "-W", "2", f"2001:db8:{i}::2"],
                           check=True, stdout=subprocess.DEVNULL)

    def close(self):
        for sock in reversed(self.sockets):
            sock.close()
        for name in reversed(self.names):
            ip("netns", "del", name)

    def add(self, mac, policy, flags=CREATE | EXCL, **kwargs):
        return self.nl.fdb(NEWNEIGH, self.index, mac, policy, flags,
                           **kwargs)

    def frame(self, mac, size=100):
        self.serial += 1
        return (mac + LOCAL_MAC + struct.pack("!H", ETH_P_TEST) +
                struct.pack("!I", self.serial) + bytes(size - 4))

    def delivery(self, mac, target, size=100, flood=False, tx=None):
        """Send a frame and check which PEs receive it. target is None for
        none, an index, or a set of indexes for replicated frames."""
        frame = self.frame(mac, size)
        if tx is None:
            tx = self.flood_tx if flood else self.tx
        tx.send(frame)
        if target is None:
            expected = []
        elif isinstance(target, int):
            expected = [target]
        else:
            expected = sorted(target)
        received = []
        deadline = time.monotonic() + (0.2 if target is None else 1)
        while time.monotonic() < deadline:
            ready, _, _ = select.select(self.rx, [], [],
                                        max(0, deadline - time.monotonic()))
            for sock in ready:
                data = sock.recv(65536)
                if data == frame:
                    received.append(self.rx.index(sock))
            if len(received) >= len(expected) and expected:
                deadline = min(deadline, time.monotonic() + 0.05)
        assert sorted(received) == expected, received
        return frame

    @contextlib.contextmanager
    def tunnel(self, name="extra", **kwargs):
        with netns(self.names[0]):
            index = self.nl.link(name, **kwargs)
        try:
            with netns(self.names[0]):
                ip("link", "set", name, "up")
                with socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                   socket.htons(ETH_P_TEST)) as tx:
                    tx.bind((name, 0))
                    yield index, tx
        finally:
            ip("-n", self.names[0], "link", "del", name)

    def test_forwarding(self):
        for mac, policy in zip(MACS, self.policies):
            self.add(mac, policy)
        for i, mac in enumerate(MACS):
            self.delivery(mac, i)
            subprocess.run(["ip", "netns", "exec", self.names[0], "ping",
                            "-c", "1", "-W", "2", f"192.0.2.{i + 1}"],
                           check=True, stdout=subprocess.DEVNULL)

    def test_bridge(self):
        root = self.names[0]
        ip("-n", root, "link", "add", "br0", "type", "bridge")
        try:
            ip("-n", root, "link", "set", "br0", "address",
               LOCAL_MAC.hex(":"), "up")
            ip("-n", root, "addr", "del", "192.0.2.100/24", "dev", "tun")
            ip("-n", root, "link", "set", "tun", "master", "br0")
            ip("-n", root, "addr", "add", "192.0.2.100/24", "dev", "br0")
            for i, mac in enumerate(MACS, 1):
                ip("-n", root, "neigh", "replace", f"192.0.2.{i}",
                   "dev", "br0", "lladdr", mac.hex(":"), "nud", "permanent")
                subprocess.run(["ip", "netns", "exec", root, "bridge", "fdb",
                                "replace", mac.hex(":"), "dev", "tun",
                                "master", "static"], check=True)
                subprocess.run(["ip", "netns", "exec", root, "ping", "-c",
                                "1", "-W", "2", f"192.0.2.{i}"],
                               check=True, stdout=subprocess.DEVNULL)
        finally:
            ip("-n", root, "link", "set", "tun", "nomaster")
            ip("-n", root, "link", "del", "br0")
            ip("-n", root, "addr", "replace", "192.0.2.100/24", "dev", "tun")

    def test_replace_delete(self):
        self.delivery(MACS[0], 0)  # Warm the old per-CPU cache.
        self.add(MACS[0], self.policies[1], REPLACE)
        self.delivery(MACS[0], 1)
        expect_error(errno.ENOENT, self.nl.fdb, DELNEIGH, self.index,
                     MACS[0], self.policies[0])
        self.nl.fdb(DELNEIGH, self.index, MACS[0], self.policies[1])
        self.delivery(MACS[0], None)
        self.add(MACS[0], self.policies[0], CREATE | REPLACE)

    def test_misses(self):
        # Without an all-zeros entry, any miss is dropped.
        dropped = self.nl.tx_dropped(self.index)
        for mac in (bytes.fromhex("02000000ffff"), BCAST,
                    bytes.fromhex("333300000001")):
            self.delivery(mac, None)
        assert self.nl.tx_dropped(self.index) >= dropped + 3
        # ip link created the flood device with one all-zeros remote.
        for mac in (bytes.fromhex("02000000ffff"), BCAST,
                    bytes.fromhex("333300000001")):
            self.delivery(mac, 0, flood=True)
        # A unicast entry overrides the all-zeros entry, and its removal
        # restores the fallback.
        self.nl.fdb(NEWNEIGH, self.flood, MACS[1], self.policies[1], CREATE)
        self.delivery(MACS[1], 1, flood=True)
        self.nl.fdb(DELNEIGH, self.flood, MACS[1])
        self.delivery(MACS[1], 0, flood=True)

    def test_flood(self):
        # Append remotes to the all-zeros entry and replicate to each.
        for policy in self.policies[1:]:
            self.nl.fdb(NEWNEIGH, self.flood, ZERO, policy, APPEND)
        expect_error(errno.EEXIST, self.nl.fdb, NEWNEIGH, self.flood, ZERO,
                     self.policies[1], APPEND)
        self.delivery(BCAST, {0, 1, 2}, flood=True)
        self.delivery(MACS[2], {0, 1, 2}, flood=True)
        # A unicast entry still selects a single remote.
        self.nl.fdb(NEWNEIGH, self.flood, MACS[0], self.policies[0], CREATE)
        self.delivery(MACS[0], 0, flood=True)
        self.nl.fdb(DELNEIGH, self.flood, MACS[0])
        # Replacing without a selector is ambiguous, through both APIs.
        expect_error(errno.EINVAL, self.nl.fdb, NEWNEIGH, self.flood, ZERO,
                     self.policies[0], REPLACE)
        with netns(self.names[0]):
            expect_error(errno.EINVAL, self.nl.link, "flood",
                         self.policies[0], change=True)
        # Replace a remote selected by its old policy.
        new = srh("fc00:1::d", "fc00:1::d")
        expect_error(errno.ENOENT, self.nl.fdb, NEWNEIGH, self.flood, ZERO,
                     new, REPLACE, old=srh("fc00:9::d"))
        expect_error(errno.EEXIST, self.nl.fdb, NEWNEIGH, self.flood, ZERO,
                     self.policies[1], REPLACE, old=self.policies[2])
        self.nl.fdb(NEWNEIGH, self.flood, ZERO, new, REPLACE,
                    old=self.policies[2])
        self.delivery(BCAST, {0, 1}, flood=True)
        assert [r[1] for r in self.nl.remotes(self.flood)] == \
            sorted([self.policies[0], self.policies[1], new])
        # A selector that misses the table does not match.
        expect_error(errno.ENOENT, self.nl.fdb, DELNEIGH, self.flood, ZERO,
                     new, table=100)
        # Delete one remote, then the whole entry.
        self.nl.fdb(DELNEIGH, self.flood, ZERO, new)
        self.delivery(BCAST, {0, 1}, flood=True)
        self.nl.fdb(DELNEIGH, self.flood, ZERO)
        assert self.nl.remotes(self.flood) == []
        self.delivery(BCAST, None, flood=True)
        # With one remote left, link set replaces it again.
        with netns(self.names[0]):
            self.nl.link("flood", self.policies[0], change=True)
        self.delivery(BCAST, 0, flood=True)
        assert self.nl.remotes(self.flood) == \
            [(ZERO, self.policies[0], FULL, 0)]

    def check_link_create(self):
        # The core announces a new device once, after newlink() installed
        # the policy, and echoes that announcement to the requester.
        policy = srh(*([f"fc00:1::{i + 1:x}" for i in range(8)]))
        links = Netlink(1 << 0)  # RTNLGRP_LINK
        try:
            reply = self.nl.link("echo", policy, mode=REDUCED, table=9,
                                 echo=True)
            index = socket.if_nametoindex("echo")
            announced = []
            while select.select([links.sock], [], [], 0.2)[0]:
                announced += [msg for kind, _, msg in links.receive()
                              if kind == NEWLINK and
                              struct.unpack_from("=i", msg, 4)[0] == index]
            current = self.nl.getlink(index)
            for msg in [m for k, m in reply if k == NEWLINK] + announced:
                link = attrs(msg[16:])
                assert link[51] == current[51]  # IFLA_MAX_MTU
                assert link_policy(link) == (policy, REDUCED, 9)
            assert len(announced) == 1, announced
            assert len([k for k, _ in reply if k == NEWLINK]) == 1, reply
            ip("link", "del", "echo")
        finally:
            links.close()

    def test_identity(self):
        # Identical SID lists in different tables are distinct remotes, and
        # the mode is policy data, not identity.
        p = self.policies[1]
        self.nl.fdb(NEWNEIGH, self.flood, ZERO, p, APPEND, table=100)
        # An append sets the state of the entry, as a replace does.
        self.nl.fdb(NEWNEIGH, self.flood, ZERO, p, APPEND, state=REACHABLE)
        assert {struct.unpack_from("=H", msg, 8)[0]
                for _, msg in self.nl.dump(self.flood)} == {REACHABLE}
        expect_error(errno.EEXIST, self.nl.fdb, NEWNEIGH, self.flood, ZERO,
                     p, APPEND, mode=REDUCED)
        assert len(self.nl.remotes(self.flood)) == 3
        # Replace and append together are ambiguous, with or without a
        # selector.
        expect_error(errno.EINVAL, self.nl.fdb, NEWNEIGH, self.flood, ZERO,
                     self.policies[2], REPLACE | APPEND)
        expect_error(errno.EINVAL, self.nl.fdb, NEWNEIGH, self.flood, ZERO,
                     self.policies[2], REPLACE | APPEND, old=p)
        # Mode changes in place, identity (SRH, table) is kept.
        self.nl.fdb(NEWNEIGH, self.flood, ZERO, p, REPLACE, mode=REDUCED,
                    table=100, old=p, old_table=100)
        assert (ZERO, p, REDUCED, 100) in self.nl.remotes(self.flood)
        assert {struct.unpack_from("=H", msg, 8)[0]
                for _, msg in self.nl.dump(self.flood)} == {PERMANENT}
        # Omitting the table clears it, which collides here.
        expect_error(errno.EEXIST, self.nl.fdb, NEWNEIGH, self.flood, ZERO,
                     p, REPLACE, old=p, old_table=100)
        self.nl.fdb(DELNEIGH, self.flood, ZERO, p)
        # Replacing with omitted mode and table installs the defaults.
        self.nl.fdb(NEWNEIGH, self.flood, ZERO, p, REPLACE, old=p,
                    old_table=100)
        assert (ZERO, p, FULL, 0) in self.nl.remotes(self.flood)
        self.nl.fdb(DELNEIGH, self.flood, ZERO, p)
        assert self.nl.remotes(self.flood) == \
            [(ZERO, self.policies[0], FULL, 0)]
        self.delivery(BCAST, 0, flood=True)

    def test_validation(self):
        missing = bytes.fromhex("02000000ffff")
        with netns(self.names[0]):
            expect_error(errno.EINVAL, self.nl.link, "badmtu",
                         self.policies[0], mtu=65500)
            # Mode and table describe a policy, which needs an SRH.
            expect_error(errno.EINVAL, self.nl.link, "nosrh", mode=FULL)
            expect_error(errno.EINVAL, self.nl.link, "nosrh", table=100)
            expect_error(errno.ERANGE, self.nl.link, "badsrh", bytes(8))
            expect_error(errno.EINVAL, self.nl.link, "badsrh", bytes(24))
            index = self.nl.link("empty")
            assert self.nl.dump(index) == []
            assert self.nl.mtu(index) == 1422
            assert self.nl.link_policy(index) is None
            ip("link", "del", "empty")
            # A link policy is an FDB remote, explicit table zero included.
            index = self.nl.link("mtucheck", self.policies[0], mtu=1400,
                                 table=0)
            assert self.nl.remotes(index) == \
                [(ZERO, self.policies[0], FULL, 0)]
            assert self.nl.mtu(index) == 1400
            assert self.nl.link_policy(index) == (self.policies[0], FULL, 0)
            ip("link", "del", "mtucheck")
            self.check_link_create()
        expect_error(errno.EEXIST, self.add, MACS[0], self.policies[0])
        expect_error(errno.EEXIST, self.add, MACS[0], self.policies[1], CREATE)
        expect_error(errno.ENOENT, self.add, missing, self.policies[0], REPLACE)
        expect_error(errno.ENOENT, self.nl.fdb, DELNEIGH, self.index, missing)
        expect_error(errno.ENOENT, self.nl.fdb, DELNEIGH, self.index,
                     MACS[0], self.policies[1])
        expect_error(errno.ENOENT, self.nl.fdb, GETNEIGH, self.index, missing,
                     state=0)
        # Too short for the attribute policy: ERANGE, else EINVAL.
        bad_srh = (errno.EINVAL, errno.ERANGE)
        expect_error(bad_srh, self.nl.fdb, DELNEIGH, self.index,
                     MACS[0], bytes(8))
        expect_error(errno.EINVAL, self.add, missing, self.policies[0],
                     CREATE | APPEND)
        expect_error(errno.EINVAL, self.add, MACS[0], self.policies[1],
                     CREATE | APPEND)
        expect_error(errno.EINVAL, self.nl.fdb, NEWNEIGH, self.index,
                     MACS[0], self.policies[1], CREATE,
                     old=self.policies[0])
        for mac in (b"\xff" * 6, bytes.fromhex("333300000001")):
            expect_error(errno.EINVAL, self.add, mac, self.policies[0])
        for policy in (None, b"", bytes(8), bytes(24), self.policies[0][:-1],
                       self.policies[0] + bytes(8),
                       self.policies[0][:3] + b"\x02" + self.policies[0][4:],
                       self.policies[0][:4] + b"\xff" + self.policies[0][5:]):
            expect_error(bad_srh, self.add, missing, policy)
        expect_error(bad_srh, self.add, missing, self.policies[0],
                     mode=2)
        # Strict nested parsing: unknown or non-nested attributes fail.
        msg = struct.pack("=BBHiHBB", socket.AF_BRIDGE, 0, 0, self.index,
                          PERMANENT, SELF, 0) + attr(NDA_LLADDR, missing)
        for bad in (attr(NDA_SR6, attr(SR6_SRH, self.policies[0])),
                    attr(NDA_SR6 | NESTED, attr(SR6_SRH, self.policies[0]) +
                         attr(9, u32(0)))):
            expect_error(errno.EINVAL, self.nl.request, NEWNEIGH, msg + bad,
                         CREATE)
        expect_error(errno.EINVAL, self.nl.fdb, NEWNEIGH, self.index,
                     missing, self.policies[0], CREATE, state=4)
        expect_error(errno.EOPNOTSUPP, self.nl.fdb, NEWNEIGH, self.index,
                     missing, self.policies[0], CREATE, ndflags=SELF | 0x10)
        for extra in (attr(5, struct.pack("=H", 1)), attr(1, bytes(16)),
                      attr(13, u32(1)), attr(15, u32(1))):
            expect_error(errno.EOPNOTSUPP, self.nl.fdb, NEWNEIGH, self.index,
                         missing, self.policies[0], CREATE, extra=extra)
        self.delivery(MACS[0], 0)

        # An exact match with no route must not use the all-zeros entry.
        self.nl.fdb(NEWNEIGH, self.flood, missing, srh("fc99::d"), CREATE)
        try:
            self.delivery(missing, None, flood=True)
            ip("-n", self.names[0], "-6", "route", "add", "fc99::d/128",
               "dev", "flood")
            try:
                self.delivery(missing, None, flood=True)  # Recursive route.
            finally:
                ip("-n", self.names[0], "-6", "route", "del", "fc99::d/128")
        finally:
            self.nl.fdb(DELNEIGH, self.flood, missing)

    def fdb_events(self):
        # RTNLGRP_NEIGH also carries IP neighbor events.
        return [(kind, msg) for kind, _, msg in self.monitor.receive()
                if msg[0] == socket.AF_BRIDGE]

    def events(self, count):
        result = []
        while len(result) < count:
            for kind, msg in self.fdb_events():
                result.append((kind, remote(msg),
                               struct.unpack_from("=i", msg, 4)[0], msg[10]))
        extra = []
        while select.select([self.monitor.sock], [], [], 0.1)[0]:
            extra += [(k, remote(m)) for k, m in self.fdb_events()]
        assert not extra, (result, extra)
        return result

    def test_dump_get_notify(self):
        # Drain notifications from earlier cases.
        while select.select([self.monitor.sock], [], [], 0)[0]:
            self.monitor.receive()
        mac = bytes.fromhex("020000001111")
        p0, p1, p2 = self.policies
        # A replacement that changes the identity reports the old remote as
        # deleted. One that keeps it, such as a mode change, does not.
        for kind, policy, flags, kwargs, expected in (
                (NEWNEIGH, p0, CREATE, {},
                 [(NEWNEIGH, (mac, p0, FULL, 0))]),
                (NEWNEIGH, p2, REPLACE, {},
                 [(DELNEIGH, (mac, p0, FULL, 0)),
                  (NEWNEIGH, (mac, p2, FULL, 0))]),
                (NEWNEIGH, p2, REPLACE, {"mode": REDUCED},
                 [(NEWNEIGH, (mac, p2, REDUCED, 0))]),
                (DELNEIGH, p2, 0, {},
                 [(DELNEIGH, (mac, p2, REDUCED, 0))])):
            self.nl.fdb(kind, self.index, mac, policy, flags, **kwargs)
            got = self.events(len(expected))
            assert [(k, r) for k, r, _, _ in got] == expected, got
            assert all(i == self.index and f == SELF for _, _, i, f in got)
        # Link helpers report through the FDB as well.
        with netns(self.names[0]):
            self.nl.link("flood", p1, mode=REDUCED, change=True)
        assert [(k, r) for k, r, _, _ in self.events(2)] == \
            [(DELNEIGH, (ZERO, p0, FULL, 0)),
             (NEWNEIGH, (ZERO, p1, REDUCED, 0))]
        # A link change keeps the mode it leaves out.
        with netns(self.names[0]):
            self.nl.link("flood", p0, change=True)
        assert [(k, r) for k, r, _, _ in self.events(2)] == \
            [(DELNEIGH, (ZERO, p1, REDUCED, 0)),
             (NEWNEIGH, (ZERO, p0, REDUCED, 0))]
        with netns(self.names[0]):
            self.nl.link("flood", p0, mode=FULL, change=True)
        self.events(1)
        # Appending and deleting a single remote is reported per remote.
        self.nl.fdb(NEWNEIGH, self.flood, ZERO, p1, APPEND, table=7)
        assert [(k, r) for k, r, _, _ in self.events(1)] == \
            [(NEWNEIGH, (ZERO, p1, FULL, 7))]
        self.nl.fdb(DELNEIGH, self.flood, ZERO)
        assert sorted((k, r) for k, r, _, _ in self.events(2)) == \
            [(DELNEIGH, (ZERO, p0, FULL, 0)), (DELNEIGH, (ZERO, p1, FULL, 7))]
        with netns(self.names[0]):
            self.nl.link("flood", p0, change=True)
        self.events(1)

        # Force several dump messages, including a multi-remote entry, and
        # retain exact SRH bytes for comparison. Notifications would overflow
        # the monitor, which later cases do not use.
        self.monitor.close()
        self.sockets.remove(self.monitor)
        entries = {(m, p, FULL, 0) for m, p in zip(MACS, self.policies)}
        for i in range(300):
            mac = bytes.fromhex("02000100") + struct.pack("!H", i)
            self.add(mac, self.policies[i % 3])
            entries.add((mac, self.policies[i % 3], FULL, 0))
        for i in range(100):
            policy = srh(f"fc00:5::{i + 1:x}")
            self.nl.fdb(NEWNEIGH, self.index, ZERO, policy, CREATE | APPEND,
                        mode=i % 2, table=i % 3)
            entries.add((ZERO, policy, i % 2, i % 3))
        dumped = [remote(msg) for kind, msg in self.nl.dump(self.index)
                  if kind == NEWNEIGH]
        assert len(dumped) == len(set(dumped)), "duplicate dump entry"
        assert set(dumped) == entries
        for mac in MACS:
            reply = self.nl.fdb(GETNEIGH, self.index, mac, state=0)
            assert len(reply) == 1
            assert remote(reply[0][1]) in entries
        self.nl.fdb(DELNEIGH, self.index, ZERO)
        for mac in {e[0] for e in entries} - set(MACS) - {ZERO}:
            self.nl.fdb(DELNEIGH, self.index, mac)

    def test_route_change(self):
        with netns(self.names[2]):
            nl = Netlink()
            try:
                nl.dt2u("fc00:1::d", socket.if_nametoindex("tun"))
            finally:
                nl.close()
        self.delivery(MACS[0], 0)
        ip("-n", self.names[0], "-6", "route", "add", "fc00:1::d/128",
           "via", "2001:db8:2::2", "dev", "v2")
        self.delivery(MACS[0], 1)
        ip("-n", self.names[0], "-6", "route", "del", "fc00:1::d/128")
        self.delivery(MACS[0], 0)

    def test_long_srh(self):
        # Alternate PEs so successive End actions do not hit the local
        # lwtunnel recursion limit before the final decapsulation.
        for i in (1, 2):
            pe = self.names[i]
            ip("-n", pe, "-6", "route", "add", f"fc00:{i}::e/128",
               "encap", "seg6local", "action", "End", "dev", "dummy0")
            ip("-n", pe, "-6", "route", "add", "fc00::/16",
               "via", f"2001:db8:{i}::1", "dev", "underlay")
        policy = srh(*([f"fc00:{i % 2 + 1}::e" for i in range(15)] +
                       ["fc00:1::d"]))
        self.add(MACS[0], policy, REPLACE)
        self.delivery(MACS[0], 0, size=1422)
        # End.DT2U does not reassemble outer fragments. Fit the inner frame
        # exactly into the smaller PMTU, accounting for this policy's SRH.
        ip("-n", self.names[0], "link", "set", "v1", "mtu", "1500")
        inner_mtu = 1500 - 40 - len(policy) - 14
        ip("-n", self.names[0], "link", "set", "tun", "mtu", inner_mtu)
        try:
            self.delivery(MACS[0], 0, size=inner_mtu)
        finally:
            ip("-n", self.names[0], "link", "set", "v1", "mtu", "9000")
            ip("-n", self.names[0], "link", "set", "tun", "mtu", "1422")
        self.add(MACS[0], self.policies[0], REPLACE)

        # A longer policy must not silently reduce an explicitly set MTU.
        maximum = srh(*(["fc00:1::e"] * 126 + ["fc00:1::d"]))
        ip("-n", self.names[0], "link", "set", "tun", "mtu", "65000")
        try:
            expect_error(errno.EINVAL, self.add, MACS[0], maximum, REPLACE)
        finally:
            ip("-n", self.names[0], "link", "set", "tun", "mtu", "1422")
        self.delivery(MACS[0], 0)
        self.add(MACS[0], maximum, REPLACE)
        reply = self.nl.fdb(GETNEIGH, self.index, MACS[0], state=0)
        assert remote(reply[0][1])[1] == maximum
        self.add(MACS[0], self.policies[0], REPLACE)

    def test_reduced(self):
        pe = self.names[1]
        ip("-n", pe, "-6", "route", "add", "fc00:1::f/128",
           "encap", "seg6local", "action", "End", "dev", "dummy0")
        try:
            with self.tunnel() as (index, tx):
                policies = [self.policies[0], srh("fc00:1::f", "fc00:1::d")]
                for mac, policy in zip(MACS, policies):
                    self.nl.fdb(NEWNEIGH, index, mac, policy, CREATE,
                                mode=REDUCED)
                    self.delivery(mac, 0, size=1422, tx=tx)
                # End can modify the headers shared with a queued packet
                # socket clone. After checking delivery, stop the two-SID
                # probe before End so capture sees the original wire bytes.
                ip("-n", pe, "-6", "route", "replace", "blackhole",
                   "fc00:1::f/128")
                with netns(pe):
                    capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                            socket.htons(0x86DD))
                    capture.bind(("underlay", 0))
                with capture:
                    capture.settimeout(2)
                    for mac, policy in zip(MACS, policies):
                        frame = self.frame(mac, size=1422)
                        tx.send(frame)
                        deadline = time.monotonic() + 2
                        while True:
                            assert time.monotonic() < deadline, "no outer packet"
                            packet = capture.recv(65536)
                            if packet.endswith(frame):
                                break
                        outer = packet[14:]
                        assert outer[24:40] == policy[-16:], outer[:64].hex()
                        if mac == MACS[0]:
                            assert outer[6] == 143  # Single SID: no SRH.
                            assert outer[40:] == frame
                        else:
                            assert outer[6] == 43
                            # Two configured SIDs become one encoded SID;
                            # segments_left still includes the outer DA.
                            assert outer[40:45] == bytes([143, 2, 4, 1, 0]), \
                                outer[:64].hex()
                            assert outer[48:64] == policy[8:24]
                            assert outer[64:] == frame
                ip("-n", pe, "-6", "route", "replace", "fc00:1::f/128",
                   "encap", "seg6local", "action", "End", "dev", "dummy0")
                # Mode is per remote: a full remote next to reduced ones.
                self.nl.fdb(NEWNEIGH, index, MACS[0], self.policies[1],
                            REPLACE)
                assert remote(self.nl.fdb(GETNEIGH, index, MACS[0],
                                          state=0)[0][1])[2] == FULL
                self.delivery(MACS[0], 1, tx=tx)
                self.delivery(MACS[1], 0, tx=tx)
                self.nl.fdb(DELNEIGH, index, MACS[0])
                self.delivery(MACS[0], None, tx=tx)
        finally:
            ip("-n", pe, "-6", "route", "del", "fc00:1::f/128")

    def test_policy_mtu(self):
        # Admission must account for the encoded SRH, not the supplied full
        # list. No jumbo packet transmission is needed here.
        one = self.policies[0]
        two = srh("fc00:1::e", "fc00:1::d")
        tagged = one[:6] + b"\x00\x01" + one[8:]
        with self.tunnel() as (index, _):
            assert self.nl.mtu(index) == 1422
        with self.tunnel(policy=one, mode=REDUCED) as (index, _):
            assert self.nl.mtu(index) == 1446
        for mode in (FULL, REDUCED):
            for policy in (one, two, tagged):
                encoded = len(policy)
                if mode == REDUCED:
                    encoded = 0 if policy == one else 24
                limit = 65535 - 40 - 14 - encoded
                with self.tunnel(mtu=limit) as (index, _):
                    self.nl.fdb(NEWNEIGH, index, MACS[0], policy, CREATE,
                                mode=mode)
                    assert self.nl.mtu(index) == limit
                    reply = self.nl.fdb(GETNEIGH, index, MACS[0], state=0)
                    assert remote(reply[0][1])[1:3] == (policy, mode)
                    # Add, append and replace must reject a policy exceeding
                    # the current MTU, leaving the existing entry untouched.
                    longer = srh("fc00:1::e", "fc00:2::e", "fc00:1::d")
                    for mac, flags in ((MACS[0], REPLACE), (MACS[1], CREATE),
                                       (ZERO, CREATE | APPEND)):
                        expect_error(errno.EINVAL, self.nl.fdb, NEWNEIGH,
                                     index, mac, longer, flags, mode=mode)
                    reply = self.nl.fdb(GETNEIGH, index, MACS[0], state=0)
                    assert remote(reply[0][1])[1:3] == (policy, mode)
                    # A full-mode replacement is longer than reduced.
                    if mode == REDUCED and encoded < len(policy):
                        expect_error(errno.EINVAL, self.nl.fdb, NEWNEIGH,
                                     index, MACS[0], policy, REPLACE)
        # The maximum follows the longest remote, both ways.
        with self.tunnel() as (index, _):
            ip("-n", self.names[0], "link", "set", "extra", "mtu", 1000)
            long = srh(*(["fc00:1::e"] * 30 + ["fc00:1::d"]))
            self.nl.fdb(NEWNEIGH, index, MACS[0], long, CREATE)
            try:
                ip("-n", self.names[0], "link", "set", "extra", "mtu",
                   65535 - 40 - 14 - len(one))
            except RuntimeError:
                pass
            else:
                raise AssertionError("MTU above the longest remote accepted")
            self.nl.fdb(DELNEIGH, index, MACS[0])
            self.nl.fdb(NEWNEIGH, index, MACS[1], one, CREATE)
            ip("-n", self.names[0], "link", "set", "extra", "mtu",
               65535 - 40 - 14 - len(one))
            assert self.nl.mtu(index) == 65535 - 40 - 14 - len(one)

    @contextlib.contextmanager
    def routing_domains(self):
        root = self.names[0]
        vrfs, tables, defaults = [], [], []
        try:
            for name, table in (("red", 100), ("blue", 200)):
                ip("-n", root, "link", "add", name, "type", "vrf",
                   "table", table)
                vrfs.append(name)
                ip("-n", root, "link", "set", name, "up")
                ip("-n", root, "-6", "route", "add", "unreachable",
                   "default", "table", table, "metric", 4278198272)
                defaults.append(table)
            for table, peer in ((254, 1), (100, 2), (200, 3)):
                ip("-n", root, "-6", "route", "add", "fc00:99::d/128",
                   "table", table, "via", f"2001:db8:{peer}::2",
                   "dev", f"v{peer}", "onlink")
                tables.append(table)
            yield
        finally:
            for table in tables:
                ip("-n", root, "-6", "route", "del", "fc00:99::d/128",
                   "table", table)
            for table in defaults:
                ip("-n", root, "-6", "route", "del", "unreachable",
                   "default", "table", table, "metric", 4278198272)
            for name in reversed(vrfs):
                ip("-n", root, "link", "del", name)

    def test_fib_table(self):
        root = self.names[0]
        sid = srh("fc00:99::d")
        with self.routing_domains():
            for mode in (FULL, REDUCED):
                with self.tunnel() as (index, tx):
                    self.nl.fdb(NEWNEIGH, index, MACS[0], sid, CREATE,
                                mode=mode, table=200)
                    self.delivery(MACS[0], 2, tx=tx)  # Main would select PE1.
                    ip("-n", root, "link", "set", "extra", "master", "red")
                    # VRF attachment cycles the port down/up; consume the
                    # resulting AF_PACKET error before testing the new route.
                    assert tx.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) in (
                        0, errno.ENETDOWN)
                    self.delivery(MACS[0], 2, tx=tx)  # VRF would select PE2.
                    ip("-n", root, "-6", "route", "replace", "fc00:99::d/128",
                       "table", 200, "via", "2001:db8:2::2", "dev", "v2",
                       "onlink")
                    try:
                        self.delivery(MACS[0], 1, tx=tx)
                    finally:
                        ip("-n", root, "-6", "route", "replace",
                           "fc00:99::d/128", "table", 200, "via",
                           "2001:db8:3::2", "dev", "v3", "onlink")
                    self.delivery(MACS[0], 2, tx=tx)
                    # Replacing without a table returns to the VRF context.
                    self.nl.fdb(NEWNEIGH, index, MACS[0], sid, REPLACE,
                                mode=mode)
                    self.delivery(MACS[0], 1, tx=tx)
                # Missing explicit table must not fall back to the main FIB.
                with self.tunnel() as (index, tx):
                    self.nl.fdb(NEWNEIGH, index, MACS[0], sid, CREATE,
                                mode=mode, table=300)
                    self.delivery(MACS[0], None, tx=tx)
            # The same SID list in two tables reaches two PEs.
            with self.tunnel() as (index, tx):
                self.nl.fdb(NEWNEIGH, index, ZERO, sid, CREATE)
                self.nl.fdb(NEWNEIGH, index, ZERO, sid, APPEND, table=100)
                self.nl.fdb(NEWNEIGH, index, ZERO, sid, APPEND, table=200)
                self.delivery(BCAST, {0, 1, 2}, tx=tx)
                self.nl.fdb(DELNEIGH, index, ZERO, sid, table=100)
                self.delivery(BCAST, {0, 2}, tx=tx)
            # ip link sets the table of the all-zeros remote.
            with self.tunnel(policy=sid, table=200) as (index, tx):
                self.delivery(BCAST, 2, tx=tx)
                with netns(root):
                    self.nl.link("extra", sid, table=100, change=True)
                self.delivery(BCAST, 1, tx=tx)
                # An omitted table is kept, and table 0 clears it.
                with netns(root):
                    self.nl.link("extra", sid, change=True)
                self.delivery(BCAST, 1, tx=tx)
                assert self.nl.link_policy(index) == (sid, FULL, 100)
                with netns(root):
                    self.nl.link("extra", sid, table=0, change=True)
                self.delivery(BCAST, 0, tx=tx)
                assert self.nl.link_policy(index) == (sid, FULL, 0)

    def check_vrf_cache(self, bridge):
        root = self.names[0]
        with self.routing_domains():
            if bridge:
                ip("-n", root, "link", "add", "br-cache", "type", "bridge")
            try:
                for mode in (FULL, REDUCED):
                    with self.tunnel() as (index, tx):
                        for mac in MACS[:2]:
                            self.nl.fdb(NEWNEIGH, index, mac, srh("fc00:99::d"),
                                        CREATE, mode=mode)
                        upper = "extra"
                        if bridge:
                            upper = "br-cache"
                            ip("-n", root, "link", "set", upper, "up")
                            ip("-n", root, "link", "set", "extra", "master",
                               upper)
                        # Routes never change here. Warm both policy caches,
                        # then only alter the device's master hierarchy.
                        for master, target in ((None, 0), ("red", 1),
                                               ("blue", 2), (None, 0)):
                            args = ("master", master) if master else ("nomaster",)
                            ip("-n", root, "link", "set", upper, *args)
                            assert tx.getsockopt(socket.SOL_SOCKET,
                                                 socket.SO_ERROR) in (
                                0, errno.ENETDOWN)
                            for mac in MACS[:2]:
                                self.delivery(mac, target, tx=tx)
                        if bridge:
                            ip("-n", root, "link", "set", upper, "master", "red")
                            for mac in MACS[:2]:
                                self.delivery(mac, 1, tx=tx)
                            ip("-n", root, "link", "set", "extra", "nomaster")
                            for mac in MACS[:2]:
                                self.delivery(mac, 0, tx=tx)
                            ip("-n", root, "link", "set", upper, "nomaster")
            finally:
                if bridge:
                    ip("-n", root, "link", "del", "br-cache")

    def test_vrf_cache(self):
        self.check_vrf_cache(bridge=False)

    def test_bridge_vrf_cache(self):
        self.check_vrf_cache(bridge=True)

    def test_churn_teardown(self):
        stop = threading.Event()
        errors = []

        def traffic():
            # The main thread is pinned for dst_cache warm-up. Forward from
            # another CPU so policy replacement races with transmission.
            others = self.cpus - {min(self.cpus)}
            if others:
                os.sched_setaffinity(0, others)
            frame = self.frame(MACS[0])
            flood = self.frame(BCAST)
            try:
                while not stop.wait(0.001):
                    self.tx.send(frame)
                    self.flood_tx.send(flood)
            except OSError as error:
                errors.append(error)

        worker = threading.Thread(target=traffic)
        worker.start()
        try:
            for i in range(100):
                self.add(MACS[0], self.policies[i % 3], CREATE | REPLACE)
                self.nl.fdb(DELNEIGH, self.index, MACS[0])
                # Replicate while remotes are appended, replaced and removed.
                p = self.policies[1 + i % 2]
                self.nl.fdb(NEWNEIGH, self.flood, ZERO, p, APPEND)
                self.nl.fdb(NEWNEIGH, self.flood, ZERO, p, REPLACE,
                            mode=REDUCED, old=p)
                self.nl.fdb(DELNEIGH, self.flood, ZERO, p)
            # Leave populated entries for unregister and namespace teardown.
            self.add(MACS[0], self.policies[0])
            for p in self.policies[1:]:
                self.nl.fdb(NEWNEIGH, self.flood, ZERO, p, APPEND)
        finally:
            stop.set()
            worker.join()
        assert not errors, errors
        # The churn traffic may fill the receive queues. Drain them so the
        # check below cannot lose its frame to an overflow.
        while ready := select.select(self.rx, [], [], 0.1)[0]:
            for sock in ready:
                sock.recv(65536)
        self.delivery(BCAST, {0, 1, 2}, flood=True)
        ip("-n", self.names[0], "link", "del", "tun")
        with netns(self.names[0]):
            index = self.nl.link("tun")
        assert self.nl.dump(index) == []


def main():
    print("TAP version 13", flush=True)
    if os.geteuid() or any(not shutil.which(tool)
                          for tool in ("ip", "ping", "bridge")):
        print("1..0 # SKIP root, ip, ping and bridge are required")
        return 4
    # dst_cache is per-CPU: keep warm-up and verification on the same CPU.
    cpus = os.sched_getaffinity(0)
    os.sched_setaffinity(0, {min(cpus)})
    fixture = Fixture(cpus)
    failures = 0
    try:
        try:
            fixture.setup()
        except OSError as error:
            if error.errno in (errno.EOPNOTSUPP, errno.ENODEV):
                print("1..0 # SKIP kernel lacks sr6 FDB or End.DT2U")
                return 4
            raise
        tests = [fixture.test_forwarding, fixture.test_bridge,
                 fixture.test_replace_delete,
                 fixture.test_misses, fixture.test_flood,
                 fixture.test_identity, fixture.test_validation,
                 fixture.test_dump_get_notify, fixture.test_route_change,
                 fixture.test_long_srh, fixture.test_reduced,
                 fixture.test_policy_mtu, fixture.test_fib_table,
                 fixture.test_vrf_cache, fixture.test_bridge_vrf_cache,
                 fixture.test_churn_teardown]
        print(f"1..{len(tests)}", flush=True)
        for number, test in enumerate(tests, 1):
            try:
                test()
                print(f"ok {number} - {test.__name__}", flush=True)
            except Exception as error:
                failures += 1
                print(f"not ok {number} - {test.__name__}: {error}", flush=True)
                for line in traceback.format_exc().splitlines():
                    print(f"# {line}", flush=True)
    finally:
        fixture.close()
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
