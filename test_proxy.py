#!/usr/bin/env python3
"""
test_proxy.py - pretend to be roblox. send a normal, unsplit ClientHello at the
local splitter and see whether the handshake survives.

proxy.py must already be running.
"""
import socket, sys, time
from diag import client_hello, read_reply

HOSTS = ["www.roblox.com", "apis.roblox.com", "gamejoin.roblox.com",
         "clientsettings.roblox.com", "discord.com", "gateway.discord.gg",
         "cdn.discordapp.com"]


def direct(host, timeout=8):
    """straight at the real server, no splitter - this is what roblox does today"""
    from diag import dns_doh
    _rc, ips = dns_doh(host)
    if not ips:
        return "no_ip"
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ips[0], 443))
        s.sendall(client_hello(host))
        return read_reply(s)
    except ConnectionResetError:
        return "RST"
    except socket.timeout:
        return "drop"
    except Exception as e:
        return "err(%s)" % type(e).__name__
    finally:
        s.close()


def through_proxy(host, timeout=12):
    s = socket.socket()
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect(("127.0.0.1", 443))
        s.sendall(client_hello(host))
        r = read_reply(s)
        return "%s %dms" % (r, (time.time() - t0) * 1000)
    except ConnectionResetError:
        return "RST"
    except socket.timeout:
        return "drop"
    except Exception as e:
        return "err(%s)" % type(e).__name__
    finally:
        s.close()


def main():
    print("%-30s %-14s %-20s" % ("host", "direct", "through splitter"))
    print("-" * 66)
    bad = 0
    for h in HOSTS:
        d = direct(h)
        p = through_proxy(h)
        if not p.startswith("TLS_OK"):
            bad += 1
        print("%-30s %-14s %-20s" % (h, d, p))
    print()
    print("all %d got through" % len(HOSTS) if not bad else "%d of %d FAILED" % (bad, len(HOSTS)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
