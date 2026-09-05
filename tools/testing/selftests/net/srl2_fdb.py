#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
"""Static srl2 FDB tests; raw rtnetlink avoids requiring new iproute2 syntax."""

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

# include/uapi/linux/{rtnetlink,neighbour,srl2,seg6_local,lwtunnel}.h
NEWLINK, DELLINK, GETLINK = 16, 17, 18
NEWNEIGH, DELNEIGH, GETNEIGH = 28, 29, 30
REQUEST, ACK, REPLACE, EXCL, CREATE, APPEND = 1, 4, 0x100, 0x200, 0x400, 0x800
DUMP = 0x300
NDA_LLADDR, NDA_SRL2_SRH = 2, 18
SELF, PERMANENT = 2, 0x80
NESTED = 0x8000
ETH_P_TEST = 0x88B5
LOCAL_MAC = bytes.fromhex("020000000010")
MACS = [bytes.fromhex(f"02000000000{i}") for i in range(1, 4)]


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

    def link(self, name, policy=None, mtu=None):
        info = attr(1, b"srl2\0")
        if policy is not None:
            info += attr(2 | NESTED, attr(1, policy))
        msg = bytes(16) + attr(3, name.encode() + b"\0") + attr(18 | NESTED, info)
        if mtu is not None:
            msg += attr(4, u32(mtu))
        self.request(NEWLINK, msg, CREATE | EXCL)
        return socket.if_nametoindex(name)

    def fdb(self, kind, index, mac=None, policy=None, flags=0,
            state=PERMANENT, ndflags=SELF, extra=b""):
        msg = struct.pack("=BBHiHBB", socket.AF_BRIDGE, 0, 0, index,
                          state, ndflags, 0)
        if mac is not None:
            msg += attr(NDA_LLADDR, mac)
        if policy is not None:
            msg += attr(NDA_SRL2_SRH, policy)
        return self.request(kind, msg + extra, flags)

    def dump(self, index):
        return self.fdb(GETNEIGH, index, flags=DUMP, state=0, ndflags=0)

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
    try:
        func(*args, **kwargs)
    except OSError as error:
        assert error.errno == code, f"expected errno {code}, got {error}"
    else:
        raise AssertionError(f"expected errno {code}, request succeeded")


class Fixture:
    def __init__(self):
        self.names = []
        self.sockets = []
        self.policies = [srh(f"fc00:{i}::d") for i in range(1, 4)]
        self.serial = 0

    def setup(self):
        for i in range(4):
            name = f"srl2-fdb-{os.getpid()}-{i}"
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
                if not i:
                    self.nl, self.index = nl, index
                    self.legacy = nl.link("legacy", self.policies[0])
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
                    ip("link", "set", "legacy", "up")
                    self.legacy_tx = socket.socket(socket.AF_PACKET,
                                                   socket.SOCK_RAW,
                                                   socket.htons(ETH_P_TEST))
                    self.legacy_tx.bind(("legacy", 0))
                    self.sockets.append(self.legacy_tx)
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
            root, remote = self.names[0], self.names[i]
            ip("-n", root, "link", "add", f"v{i}", "type", "veth",
               "peer", "name", "underlay", "netns", remote)
            for ns, dev, host in ((root, f"v{i}", 1), (remote, "underlay", 2)):
                ip("-n", ns, "link", "set", dev, "mtu", 9000, "up")
                ip("-n", ns, "addr", "add", f"2001:db8:{i}::{host}/64",
                   "dev", dev, "nodad")
            ip("-n", root, "-6", "route", "add", f"fc00:{i}::/64",
               "via", f"2001:db8:{i}::2", "dev", f"v{i}")
            ip("-n", remote, "-6", "route", "add", "fc00:0::/64",
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

    def add(self, mac, policy, flags=CREATE | EXCL):
        return self.nl.fdb(NEWNEIGH, self.index, mac, policy, flags)

    def frame(self, mac, size=100):
        self.serial += 1
        return (mac + LOCAL_MAC + struct.pack("!H", ETH_P_TEST) +
                struct.pack("!I", self.serial) + bytes(size - 4))

    def delivery(self, mac, target, size=100, legacy=False):
        frame = self.frame(mac, size)
        (self.legacy_tx if legacy else self.tx).send(frame)
        received = []
        deadline = time.monotonic() + (0.2 if target is None else 1)
        while time.monotonic() < deadline:
            ready, _, _ = select.select(self.rx, [], [],
                                        max(0, deadline - time.monotonic()))
            for sock in ready:
                data = sock.recv(65536)
                if data == frame:
                    received.append(self.rx.index(sock))
            if received and target is not None:
                deadline = min(deadline, time.monotonic() + 0.05)
        assert received == ([] if target is None else [target]), received

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
        dropped = self.nl.tx_dropped(self.index)
        for mac in (bytes.fromhex("02000000ffff"), bytes(6),
                    bytes.fromhex("ffffffffffff"), bytes.fromhex("333300000001")):
            self.delivery(mac, None)
            self.delivery(mac, 0, legacy=True)
        assert self.nl.tx_dropped(self.index) >= dropped + 4
        self.nl.fdb(NEWNEIGH, self.legacy, MACS[1], self.policies[1], CREATE)
        self.delivery(MACS[1], 1, legacy=True)
        self.nl.fdb(DELNEIGH, self.legacy, MACS[1])
        self.delivery(MACS[1], 0, legacy=True)

    def test_validation(self):
        missing = bytes.fromhex("02000000ffff")
        with netns(self.names[0]):
            expect_error(errno.EINVAL, self.nl.link, "badmtu",
                         self.policies[0], mtu=65500)
            expect_error(errno.EINVAL, self.nl.link, "badsrh", bytes(8))
            index = self.nl.link("mtucheck", self.policies[0], mtu=1400)
            assert self.nl.dump(index) == []
            ip("link", "del", "mtucheck")
        expect_error(errno.EEXIST, self.add, MACS[0], self.policies[0])
        expect_error(errno.EEXIST, self.add, MACS[0], self.policies[1], CREATE)
        expect_error(errno.ENOENT, self.add, missing, self.policies[0], REPLACE)
        expect_error(errno.ENOENT, self.nl.fdb, DELNEIGH, self.index, missing)
        expect_error(errno.ENOENT, self.nl.fdb, GETNEIGH, self.index, missing,
                     state=0)
        expect_error(errno.EINVAL, self.nl.fdb, DELNEIGH, self.index,
                     MACS[0], bytes(8))
        expect_error(errno.EOPNOTSUPP, self.add, missing, self.policies[0],
                     CREATE | APPEND)
        for mac in (bytes(6), b"\xff" * 6, bytes.fromhex("333300000001")):
            expect_error(errno.EINVAL, self.add, mac, self.policies[0])
        for policy in (None, b"", bytes(8), bytes(24), self.policies[0][:-1],
                       self.policies[0] + bytes(8),
                       self.policies[0][:3] + b"\x02" + self.policies[0][4:],
                       self.policies[0][:4] + b"\xff" + self.policies[0][5:]):
            expect_error(errno.EINVAL, self.add, missing, policy)
        expect_error(errno.EINVAL, self.nl.fdb, NEWNEIGH, self.index,
                     missing, self.policies[0], CREATE, state=4)
        expect_error(errno.EOPNOTSUPP, self.nl.fdb, NEWNEIGH, self.index,
                     missing, self.policies[0], CREATE, ndflags=SELF | 0x10)
        for extra in (attr(5, struct.pack("=H", 1)), attr(1, bytes(16)),
                      attr(13, u32(1)), attr(15, u32(1))):
            expect_error(errno.EOPNOTSUPP, self.nl.fdb, NEWNEIGH, self.index,
                         missing, self.policies[0], CREATE, extra=extra)
        self.delivery(MACS[0], 0)

        # An exact match with no route must not use the legacy fallback.
        self.nl.fdb(NEWNEIGH, self.legacy, missing, srh("fc99::d"), CREATE)
        try:
            self.delivery(missing, None, legacy=True)
            ip("-n", self.names[0], "-6", "route", "add", "fc99::d/128",
               "dev", "legacy")
            try:
                self.delivery(missing, None, legacy=True)  # Recursive route.
            finally:
                ip("-n", self.names[0], "-6", "route", "del", "fc99::d/128")
        finally:
            self.nl.fdb(DELNEIGH, self.legacy, missing)

    def test_dump_get_notify(self):
        # Drain notifications from earlier cases.
        while select.select([self.monitor.sock], [], [], 0)[0]:
            self.monitor.receive()
        mac = bytes.fromhex("020000001111")
        for kind, policy, flags in ((NEWNEIGH, self.policies[0], CREATE),
                                    (NEWNEIGH, self.policies[2], REPLACE),
                                    (DELNEIGH, self.policies[2], 0)):
            self.nl.fdb(kind, self.index, mac, policy, flags)
            events = self.monitor.receive()
            assert len(events) == 1, events
            event, _, msg = events[0]
            assert event == kind
            assert attrs(msg[12:])[NDA_SRL2_SRH] == policy
            assert attrs(msg[12:])[NDA_LLADDR] == mac
            assert struct.unpack_from("=i", msg, 4)[0] == self.index
            assert msg[10] == SELF
        # Force several dump messages, retaining exact SRH bytes for comparison.
        entries = {mac: policy for mac, policy in zip(MACS, self.policies)}
        for i in range(300):
            mac = bytes.fromhex("02000100") + struct.pack("!H", i)
            entries[mac] = self.policies[i % 3]
            self.add(mac, entries[mac])
        dumped = {}
        for kind, msg in self.nl.dump(self.index):
            assert kind == NEWNEIGH
            data = attrs(msg[12:])
            mac = data[NDA_LLADDR]
            assert mac not in dumped, "duplicate dump entry"
            dumped[mac] = data[NDA_SRL2_SRH]
        assert dumped == entries
        for mac in MACS:
            reply = self.nl.fdb(GETNEIGH, self.index, mac, state=0)
            assert len(reply) == 1
            assert attrs(reply[0][1][12:])[NDA_SRL2_SRH] == entries[mac]
        for mac in entries.keys() - set(MACS):
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
            remote = self.names[i]
            ip("-n", remote, "-6", "route", "add", f"fc00:{i}::e/128",
               "encap", "seg6local", "action", "End", "dev", "dummy0")
            ip("-n", remote, "-6", "route", "add", "fc00::/16",
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
        assert attrs(reply[0][1][12:])[NDA_SRL2_SRH] == maximum
        self.add(MACS[0], self.policies[0], REPLACE)

    def test_churn_teardown(self):
        stop = threading.Event()
        errors = []

        def traffic():
            frame = self.frame(MACS[0])
            try:
                while not stop.wait(0.001):
                    self.tx.send(frame)
            except OSError as error:
                errors.append(error)

        worker = threading.Thread(target=traffic)
        worker.start()
        try:
            for i in range(100):
                self.add(MACS[0], self.policies[i % 3], CREATE | REPLACE)
                self.nl.fdb(DELNEIGH, self.index, MACS[0])
            # Leave populated entries for unregister and namespace teardown.
            self.add(MACS[0], self.policies[0])
        finally:
            stop.set()
            worker.join()
        assert not errors, errors
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
    fixture = Fixture()
    failures = 0
    try:
        try:
            fixture.setup()
        except OSError as error:
            if error.errno in (errno.EOPNOTSUPP, errno.ENODEV):
                print("1..0 # SKIP kernel lacks srl2 or End.DT2U")
                return 4
            raise
        tests = [fixture.test_forwarding, fixture.test_bridge,
                 fixture.test_replace_delete,
                 fixture.test_misses, fixture.test_validation,
                 fixture.test_dump_get_notify, fixture.test_route_change,
                 fixture.test_long_srh, fixture.test_churn_teardown]
        print(f"1..{len(tests)}", flush=True)
        for number, test in enumerate(tests, 1):
            try:
                test()
                print(f"ok {number} - {test.__name__}", flush=True)
            except Exception as error:
                failures += 1
                print(f"not ok {number} - {test.__name__}: {error}", flush=True)
    finally:
        fixture.close()
    return bool(failures)


if __name__ == "__main__":
    sys.exit(main())
