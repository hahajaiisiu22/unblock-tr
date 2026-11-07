#!/usr/bin/env python3
"""
calibrate.py - find the cut that beats YOUR ISP, and remember it.

every country and every ISP runs a different filtering box. the cut that
wins here may lose somewhere else. this probes each one against the names
that are actually blocked on this connection and writes the winner into
settings.json, which the splitter reads on start.

  python calibrate.py

run it with the splitter OFF and the redirect OFF (quit the app first),
otherwise you are measuring the splitter instead of your ISP.
"""
import json, os, sys, socket, time
import proxy
from proxy import RECIPES, parse_sni
from diag import client_hello, read_reply, dns_doh

HERE = (os.path.dirname(os.path.abspath(sys.executable))
        if getattr(sys, "frozen", False)
        else os.path.dirname(os.path.abspath(__file__)))

TRIALS = 3
ORDER = ["in-host", "first1", "first5", "before-host", "host-isolated",
         "half", "chunk64", "chunk16", "none"]


def pick_hosts(limit=5):
    """a few names that are genuinely blocked right now, plus a control"""
    try:
        with open(os.path.join(HERE, "domains.json")) as f:
            d = json.load(f)
    except Exception:
        return [], None
    names = [n for g in d.values() for n in g]
    blocked = []
    for n in names:
        if len(blocked) >= limit:
            break
        _rc, ips = dns_doh(n)
        if not ips:
            continue
        if attempt(ips[0], n, "none") != "TLS_OK":
            blocked.append((n, ips[0]))
    return blocked, "example.com"


def attempt(ip, host, recipe, timeout=7):
    ch = client_hello(host)
    pl = ch[5:]
    _h, a, b = parse_sni(pl)
    blob = RECIPES[recipe](pl, a, b)
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, 443))
        s.sendall(blob)
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
    print("looking for names your connection actually blocks...")
    blocked, control = pick_hosts()
    if not blocked:
        print("\nnothing in domains.json is being blocked on this connection.")
        print("either you are on a VPN, the redirect is still installed, or you")
        print("are simply not censored here. nothing to calibrate.")
        return 1

    print("testing against %d blocked names: %s\n"
          % (len(blocked), ", ".join(h for h, _ in blocked)))

    _rc, cips = dns_doh(control)
    if cips and attempt(cips[0], control, "none") != "TLS_OK":
        print("control host %s is also failing - the connection itself is sick." % control)
        print("fix that first, these numbers would be meaningless.")
        return 1

    print("%-16s %-8s %s" % ("recipe", "score", "detail"))
    print("-" * 58)
    best, best_score = None, -1
    for recipe in ORDER:
        ok = 0
        detail = []
        for host, ip in blocked:
            hits = sum(1 for _ in range(TRIALS)
                       if attempt(ip, host, recipe) == "TLS_OK")
            ok += hits
            detail.append("%d" % hits)
        total = len(blocked) * TRIALS
        print("%-16s %-8s %s" % (recipe, "%d/%d" % (ok, total), " ".join(detail)))
        if ok > best_score:
            best, best_score = recipe, ok
        if ok == total and recipe != "none":
            break           # first perfect one in preference order wins

    total = len(blocked) * TRIALS
    print()
    if best == "none":
        print("nothing is blocked - no cut needed.")
        return 0
    if best_score < total:
        print("best is '%s' at %d/%d - not perfect." % (best, best_score, total))
        print("your ISP's box is tougher than the one this was built against.")
        print("open an issue with this table and the diag.py output.")
    else:
        print("winner: '%s' - %d/%d, every try." % (best, best_score, total))

    path = os.path.join(HERE, "settings.json")
    try:
        with open(path) as f:
            s = json.load(f)
    except Exception:
        s = {}
    s["recipe"] = best
    s["calibrated"] = time.strftime("%Y-%m-%d %H:%M")
    with open(path, "w") as f:
        json.dump(s, f, indent=2)
    print("saved to settings.json - the splitter picks it up on start.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
