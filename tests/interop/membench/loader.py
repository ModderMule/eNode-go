#!/usr/bin/env python3
"""eD2K publish loader for the Lugdunum eserver memory measurement.

Workload generator is a byte-for-byte port of examples/loadgen.rs from the Rust
ed2k-server (splitmix64 `mix`, make_name, hash derivation, owner = i % clients).

Each client gets its own source IPv4 (added to eth0), logs in with
OP_LOGINREQUEST, publishes its files with zlib-packed OP_OFFERFILES, then stays
connected and drains whatever the server sends until /out/stop appears.
"""
import argparse
import asyncio
import json
import os
import socket
import struct
import subprocess
import sys
import time
import zlib

M64 = 0xFFFFFFFFFFFFFFFF


def mix(z):
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return z ^ (z >> 31)


def make_name(name_idx, kw_vocab):
    s = mix(name_idx ^ 0x9E3779B97F4A7C15)
    toks = []
    for _ in range(7):
        s = mix(s)
        toks.append("w%d" % (s % kw_vocab))
    return " ".join(toks) + ".bin"


def file_entry(i, unique_names, kw_vocab):
    h0 = mix(i)
    h1 = mix(i ^ 0xA5A5A5A55A5A5A5A)
    fhash = struct.pack("<QQ", h0, h1)
    name = make_name(i % unique_names, kw_vocab).encode()
    size = (h1 % 4_000_000_000) + 1
    # hash, clientID, port (0xFBFBFBFB/0xFBFB = "complete file" marker eMule
    # sends to zlib-capable servers), tag count, FT_FILENAME, FT_FILESIZE
    return (fhash + struct.pack("<IHI", 0xFBFBFBFB, 0xFBFB, 2)
            + struct.pack("<BHBH", 0x02, 1, 0x01, len(name)) + name
            + struct.pack("<BHBI", 0x03, 1, 0x02, size))


def userhash(c):
    h = bytearray(struct.pack("<QQ", mix(c), mix(c ^ 0x5151515151515151)))
    h[5] = 14
    h[14] = 111
    return bytes(h)


def client_ip(c):
    return "10.77.%d.%d" % (16 + c // 250, 1 + c % 250)


def ip_index(ip):
    a = ip.split(".")
    return (int(a[2]) - 16) * 250 + int(a[3]) - 1


def tag_str(tid, v):
    v = v.encode()
    return struct.pack("<BHBH", 0x02, 1, tid, len(v)) + v


def tag_int(tid, v):
    return struct.pack("<BHBI", 0x03, 1, tid, v)


def frame(op, body, packed=False):
    if packed:
        z = zlib.compress(body, 6)
        return struct.pack("<BIB", 0xD4, len(z) + 1, op) + z
    return struct.pack("<BIB", 0xE3, len(body) + 1, op) + body


class St:
    connected = 0     # sockets currently open and logged in
    logged = 0
    published = 0     # clients that finished sending all offers
    files_sent = 0
    dropped = 0       # connections closed by the server
    failed = 0
    highid = 0
    lowid = 0
    msgs = {}
    backdoor = 0
    drops = []


async def read_frame(r):
    hdr = await r.readexactly(5)
    proto, size = struct.unpack("<BI", hdr)
    data = await r.readexactly(size)
    op, payload = data[0], data[1:]
    if proto == 0xD4:
        payload = zlib.decompress(payload)
    return op, payload


async def backdoor(reader, writer, args):
    """Answer the server's HighID connect-back with OP_HELLOANSWER."""
    try:
        St.backdoor += 1
        c = ip_index(writer.get_extra_info("sockname")[0])
        try:
            await asyncio.wait_for(reader.read(4096), 10)
        except asyncio.TimeoutError:
            pass
        tags = tag_str(0x01, "emule_user_%07d" % c) + tag_int(0x11, 0x3C)
        body = (userhash(c) + socket.inet_aton(client_ip(c)) + struct.pack("<H", 4662)
                + struct.pack("<I", 2) + tags
                + socket.inet_aton(args.host) + struct.pack("<H", args.port))
        writer.write(frame(0x4C, body))
        await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()


async def run_client(c, args, sem, unique_names, kw_vocab):
    async with sem:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(args.host, args.port, local_addr=(client_ip(c), 0),
                                        limit=1 << 20), 120)
        except Exception as e:
            St.failed += 1
            St.drops.append((c, "connect: %r" % e))
            return
        try:
            tags = [tag_str(0x01, "emule_user_%07d" % c), tag_int(0x11, 0x3C),
                    tag_int(0x20, 0x0001 | 0x0008 | 0x0010 | 0x0100),  # zlib, newtags, unicode, largefiles
                    tag_int(0xFB, (50 << 10))]                          # eMule 0.50a
            body = userhash(c) + struct.pack("<IH", 0, 4662) + struct.pack("<I", len(tags)) + b"".join(tags)
            w.write(frame(0x01, body))
            await w.drain()
            cid = None
            while cid is None:
                op, p = await asyncio.wait_for(read_frame(r), 180)
                if op == 0x40:
                    cid = struct.unpack_from("<I", p, 0)[0]
                elif op == 0x38:
                    m = p[2:].decode("utf-8", "replace").strip()[:100]
                    St.msgs[m] = St.msgs.get(m, 0) + 1
            St.logged += 1
            St.connected += 1
            if cid < 0x01000000:
                St.lowid += 1
            else:
                St.highid += 1
            idxs = list(range(c, args.files, args.clients))
            for off in range(0, len(idxs), args.batch):
                chunk = idxs[off:off + args.batch]
                body = struct.pack("<I", len(chunk)) + b"".join(
                    file_entry(i, unique_names, kw_vocab) for i in chunk)
                w.write(frame(0x15, body, packed=True))
                await w.drain()
                St.files_sent += len(chunk)
            St.published += 1
        except Exception as e:
            St.failed += 1
            St.drops.append((c, "setup: %r" % e))
            w.close()
            return
    # stay connected; drain pings / messages
    try:
        while True:
            op, p = await read_frame(r)
            if op == 0x38:
                m = p[2:].decode("utf-8", "replace").strip()[:100]
                St.msgs[m] = St.msgs.get(m, 0) + 1
    except Exception as e:
        St.connected -= 1
        St.dropped += 1
        St.drops.append((c, "dropped t=%d: %r" % (time.time(), e)))


def snapshot(t0, args):
    return dict(t=round(time.time() - t0, 1), target_clients=args.clients, target_files=args.files,
                logged=St.logged, connected=St.connected, published=St.published,
                files_sent=St.files_sent, dropped=St.dropped, failed=St.failed,
                highid=St.highid, lowid=St.lowid, backdoor_conns=St.backdoor,
                msgs=St.msgs, drops=St.drops[:20])


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=4661)
    ap.add_argument("--files", type=int, required=True)
    ap.add_argument("--clients", type=int, required=True)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--batch", type=int, default=100000, help="files per OP_OFFERFILES")
    ap.add_argument("--highid", type=int, default=1, help="listen on 4662 to pass the connect-back")
    ap.add_argument("--out", default="/out")
    args = ap.parse_args()

    unique_names = max(1, args.files * 70 // 100)
    kw_vocab = max(1, args.files * 72 // 100)
    print("loader: files=%d clients=%d unique_names=%d kw_vocab=%d sample=%r" % (
        args.files, args.clients, unique_names, kw_vocab, make_name(0, kw_vocab)), flush=True)

    batch = "".join("addr add %s/16 dev eth0\n" % client_ip(c) for c in range(args.clients))
    subprocess.run(["ip", "-batch", "-"], input=batch.encode(), check=True)

    if args.highid:
        await asyncio.start_server(lambda r, w: backdoor(r, w, args), "0.0.0.0", 4662, backlog=4096)

    t0 = time.time()
    sem = asyncio.Semaphore(args.concurrency)
    tasks = [asyncio.create_task(run_client(c, args, sem, unique_names, kw_vocab))
             for c in range(args.clients)]
    stop = os.path.join(args.out, "stop")
    status = os.path.join(args.out, "status.json")
    last = 0
    while not os.path.exists(stop):
        await asyncio.sleep(2)
        snap = snapshot(t0, args)
        with open(status + ".tmp", "w") as f:
            json.dump(snap, f)
        os.replace(status + ".tmp", status)
        if time.time() - last > 30:
            last = time.time()
            s = dict(snap)
            s.pop("drops")
            print(json.dumps(s), flush=True)
    print("FINAL " + json.dumps(snapshot(t0, args)), flush=True)
    for t in tasks:
        t.cancel()


if __name__ == "__main__":
    asyncio.run(main())
