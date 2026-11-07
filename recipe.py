#!/usr/bin/env python3
"""
recipe.py - the DPI box reassembles TCP but not TLS records.
find the exact record-split recipe that gets through, every time, on every host.

run with VPN OFF. no admin needed.
"""
import socket, struct, time, sys
from diag import client_hello, read_reply, dns_doh

HOSTS = ["www.roblox.com", "apis.roblox.com", "gamejoin.roblox.com",
         "clientsettings.roblox.com", "assetdelivery.roblox.com",
         "discord.com", "gateway.discord.gg", "cdn.discordapp.com",
         "example.com"]

TRIALS = 3


def rec(payload):
    """wrap a handshake-payload slice in its own TLS record"""
    return b"\x16\x03\x01" + struct.pack(">H", len(payload)) + payload


def sni_span(ch, host):
    """byte range of the hostname inside the handshake payload ch[5:]"""
    pl = ch[5:]
    i = pl.find(host.encode())
    return (i, i + len(host)) if i > 0 else (len(pl) // 2, len(pl) // 2)


# each recipe returns a list of (bytes_to_send, delay_after_seconds)

def r_whole(ch, host):
    return [(ch, 0)]

def r_half(ch, host):
    pl = ch[5:]
    h = len(pl) // 2
    return [(rec(pl[:h]), 0.12), (rec(pl[h:]), 0)]

def r_first1(ch, host):
    pl = ch[5:]
    return [(rec(pl[:1]), 0.12), (rec(pl[1:]), 0)]

def r_first5(ch, host):
    pl = ch[5:]
    return [(rec(pl[:5]), 0.12), (rec(pl[5:]), 0)]

def r_in_host(ch, host):
    pl = ch[5:]
    a, b = sni_span(ch, host)
    cut = a + max(1, (b - a) // 2)
    return [(rec(pl[:cut]), 0.12), (rec(pl[cut:]), 0)]

def r_before_host(ch, host):
    pl = ch[5:]
    a, _ = sni_span(ch, host)
    return [(rec(pl[:a]), 0.12), (rec(pl[a:]), 0)]

def r_host_isolated(ch, host):
    pl = ch[5:]
    a, b = sni_span(ch, host)
    return [(rec(pl[:a]), 0.10), (rec(pl[a:b]), 0.10), (rec(pl[b:]), 0)]

def r_host_perbyte(ch, host):
    pl = ch[5:]
    a, b = sni_span(ch, host)
    out = [(rec(pl[:a]), 0.08)]
    for i in range(a, b):
        out.append((rec(pl[i:i + 1]), 0.02))
    out.append((rec(pl[b:]), 0))
    return out

def r_chunk16(ch, host):
    pl = ch[5:]
    out = []
    for i in range(0, len(pl), 16):
        out.append((rec(pl[i:i + 16]), 0.02))
    return out

def r_chunk64(ch, host):
    pl = ch[5:]
    out = []
    for i in range(0, len(pl), 64):
        out.append((rec(pl[i:i + 64]), 0.02))
    return out

def r_in_host_nodelay(ch, host):
    pl = ch[5:]
    a, b = sni_span(ch, host)
    cut = a + max(1, (b - a) // 2)
    return [(rec(pl[:cut]) + rec(pl[cut:]), 0)]

def r_in_host_slow(ch, host):
    pl = ch[5:]
    a, b = sni_span(ch, host)
    cut = a + max(1, (b - a) // 2)
    return [(rec(pl[:cut]), 0.45), (rec(pl[cut:]), 0)]

RECIPES = [
    ("whole", r_whole),
    ("half", r_half),
    ("first1", r_first1),
    ("first5", r_first5),
    ("in-host", r_in_host),
    ("in-host-nodelay", r_in_host_nodelay),
    ("in-host-slow", r_in_host_slow),
    ("before-host", r_before_host),
    ("host-isolated", r_host_isolated),
    ("host-perbyte", r_host_perbyte),
    ("chunk16", r_chunk16),
    ("chunk64", r_chunk64),
]


def attempt(ip, host, builder, timeout=6):
    ch = client_hello(host)
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, 443))
    except Exception as e:
        return "TCP_fail(%s)" % type(e).__name__
    try:
        for blob, delay in builder(ch, host):
            s.sendall(blob)
            if delay:
                time.sleep(delay)
        return read_reply(s)
    except ConnectionResetError:
        return "RST"
    except socket.timeout:
        return "drop"
    except Exception as e:
        return "err(%s)" % type(e).__name__
    finally:
        s.close()


def main():
    ips = {}
    for h in HOSTS:
        _rc, a = dns_doh(h)
        ips[h] = a[0] if a else None
        if not ips[h]:
            print("no ip for %s - skipping" % h)

    w = 17
    print("recipe matrix - %d trials each, score = how many got TLS_OK\n" % TRIALS)
    header = "%-*s" % (w, "recipe") + "".join("%-10s" % h.split(".")[-2][:9] for h in HOSTS)
    print(header)
    print("-" * len(header))

    results = {}
    for name, builder in RECIPES:
        row = "%-*s" % (w, name)
        for h in HOSTS:
            if not ips[h]:
                row += "%-10s" % "-"
                continue
            ok = 0
            last = ""
            for _ in range(TRIALS):
                r = attempt(ips[h], h, builder)
                last = r
                if r == "TLS_OK":
                    ok += 1
            results[(name, h)] = ok
            cell = "%d/%d" % (ok, TRIALS) if ok else last[:9]
            row += "%-10s" % cell
        print(row)

    print("\nperfect recipes (TLS_OK on every blocked host, all trials):")
    blocked = [h for h in HOSTS if h != "example.com"]
    winners = []
    for name, _b in RECIPES:
        if all(results.get((name, h), 0) == TRIALS for h in blocked if ips[h]):
            winners.append(name)
            print("   %s" % name)
    if not winners:
        print("   none clean. best per-host score above - i tune from there.")


if __name__ == "__main__":
    main()
