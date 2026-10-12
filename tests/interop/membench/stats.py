#!/usr/bin/env python3
"""Read eserver's nbuser stats line (TCP 5656; dumped on connect)."""
import socket, sys
s = socket.create_connection((sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 5656), timeout=60)
s.settimeout(60)
buf = b""
try:
    while True:
        c = s.recv(65536)
        if not c:
            break
        buf += c
        if buf.endswith(b"\n"):
            break
except socket.timeout:
    pass
sys.stdout.write(buf.decode("latin-1"))
