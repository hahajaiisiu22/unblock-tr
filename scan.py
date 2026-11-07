#!/usr/bin/env python3
"""
scan.py - find every roblox/discord name the filter kills, from data.

talks straight to each name's real IP (via DoH, so our own hosts entries
can't trap it) and sends one normal ClientHello. killed = must be covered.

  python scan.py          just report
  python scan.py --add    report, then write the blocked ones into domains.json

safe to run with the hosts entries installed and the splitter running.
"""
import json, os, sys, socket, concurrent.futures as cf
from diag import client_hello, read_reply, dns_doh

HERE = (os.path.dirname(os.path.abspath(sys.executable))
        if getattr(sys, "frozen", False)
        else os.path.dirname(os.path.abspath(__file__)))

CANDIDATES = [
    # roblox web + client api surface
    "roblox.com", "www.roblox.com", "web.roblox.com", "m.roblox.com",
    "api.roblox.com", "apis.roblox.com", "auth.roblox.com", "users.roblox.com",
    "games.roblox.com", "gamejoin.roblox.com", "gameinternationalization.roblox.com",
    "clientsettings.roblox.com", "clientsettingscdn.roblox.com",
    "versioncompatibility.api.roblox.com", "ephemeralcounters.api.roblox.com",
    "assetdelivery.roblox.com", "assetgame.roblox.com", "avatar.roblox.com",
    "friends.roblox.com", "presence.roblox.com", "thumbnails.roblox.com",
    "thumbnailsfilter.roblox.com", "economy.roblox.com", "catalog.roblox.com",
    "inventory.roblox.com", "notifications.roblox.com", "realtime.roblox.com",
    "chat.roblox.com", "groups.roblox.com", "badges.roblox.com",
    "accountsettings.roblox.com", "accountinformation.roblox.com",
    "premiumfeatures.roblox.com", "metrics.roblox.com", "ecsv2.roblox.com",
    "abtesting.roblox.com", "locale.roblox.com", "contacts.roblox.com",
    "voice.roblox.com", "textfilter.roblox.com", "itemconfiguration.roblox.com",
    "develop.roblox.com", "publish.roblox.com", "trades.roblox.com",
    "followings.roblox.com", "points.roblox.com", "share.roblox.com",
    "privatemessages.roblox.com", "billing.roblox.com", "adconfiguration.roblox.com",
    "apis.rbxcdn.com", "setup.rbxcdn.com", "setup-cfly.rbxcdn.com",
    "rbxcdn.com", "www.rbxcdn.com", "tr.rbxcdn.com", "ec.rbxcdn.com",
    "images.rbxcdn.com", "static.rbxcdn.com",
    "c0.rbxcdn.com", "c1.rbxcdn.com", "c2.rbxcdn.com", "c3.rbxcdn.com",
    "c4.rbxcdn.com", "c5.rbxcdn.com", "c6.rbxcdn.com", "c7.rbxcdn.com",
    "t0.rbxcdn.com", "t1.rbxcdn.com", "t2.rbxcdn.com", "t3.rbxcdn.com",
    "t4.rbxcdn.com", "t5.rbxcdn.com", "t6.rbxcdn.com", "t7.rbxcdn.com",
    "rbxcdn.net", "roblox.qq.com",
    # discord
    "discord.com", "www.discord.com", "canary.discord.com", "ptb.discord.com",
    "status.discord.com", "updates.discord.com", "support.discord.com",
    "discordapp.com", "www.discordapp.com", "cdn.discordapp.com",
    "media.discordapp.net", "images-ext-1.discordapp.net",
    "images-ext-2.discordapp.net", "dl.discordapp.net", "router.discordapp.net",
    "discordapp.net", "gateway.discord.gg", "discord.gg",
    "remote-auth-gateway.discord.gg", "discord.media", "latency.discord.media",
    "discord.app", "discordstatus.com",
    # controls - these must come back open or the run is bad
    "example.com", "www.cloudflare.com", "www.google.com",
]

CONTROLS = {"example.com", "www.cloudflare.com", "www.google.com"}


def check(host):
    _rc, ips = dns_doh(host)
    if not ips:
        return host, "no_dns", None
    s = socket.socket()
    s.settimeout(7)
    try:
        s.connect((ips[0], 443))
        s.sendall(client_hello(host))
        return host, read_reply(s), ips[0]
    except ConnectionResetError:
        return host, "RST", ips[0]
    except socket.timeout:
        return host, "drop", ips[0]
    except Exception as e:
        return host, "err(%s)" % type(e).__name__, ips[0]
    finally:
        s.close()


def main():
    print("probing %d names (direct, no splitter)...\n" % len(CANDIDATES))
    results = {}
    with cf.ThreadPoolExecutor(max_workers=12) as ex:
        for host, verdict, ip in ex.map(check, CANDIDATES):
            results[host] = (verdict, ip)

    bad_control = [h for h in CONTROLS if results.get(h, ("", ""))[0] != "TLS_OK"]
    if bad_control:
        print("!! controls failed: %s" % ", ".join(bad_control))
        print("!! the connection itself is unhealthy - results below are not trustworthy\n")

    blocked, open_, dead = [], [], []
    for h in CANDIDATES:
        if h in CONTROLS:
            continue
        v, _ip = results[h]
        if v in ("RST", "drop"):
            blocked.append(h)
        elif v == "TLS_OK":
            open_.append(h)
        else:
            dead.append((h, v))

    print("BLOCKED - must go through the splitter (%d):" % len(blocked))
    for h in blocked:
        print("   %-42s %s" % (h, results[h][0]))
    print("\nopen already (%d):" % len(open_))
    for h in open_:
        print("   %s" % h)
    if dead:
        print("\nno answer / not a real host (%d):" % len(dead))
        for h, v in dead:
            print("   %-42s %s" % (h, v))

    path = os.path.join(HERE, "domains.json")
    with open(path) as f:
        cur = json.load(f)
    have = {n for g in cur.values() for n in g}
    missing = [h for h in blocked if h not in have]
    stale = sorted(have - set(blocked) - set(open_))

    print("\nblocked but NOT yet in domains.json (%d):" % len(missing))
    for h in missing:
        print("   %s" % h)
    if stale:
        print("\nin domains.json but no longer resolving (%d): %s"
              % (len(stale), ", ".join(stale)))

    if "--sync" in sys.argv or "--add" in sys.argv:
        if bad_control:
            print("\nrefusing to write domains.json - the controls failed, so the")
            print("blocked list is not trustworthy. fix the connection and rerun.")
            return 1
        new = {"roblox": sorted(h for h in blocked if "discord" not in h),
               "discord": sorted(h for h in blocked if "discord" in h)}
        dropped = sorted(have - set(blocked))
        with open(path, "w") as f:
            json.dump(new, f, indent=2)
            f.write("\n")
        print("\ndomains.json is now exactly the %d blocked names" % len(blocked))
        if missing:
            print("  added  (%d): %s" % (len(missing), ", ".join(missing)))
        if dropped:
            print("  dropped (%d, open or dead - no reason to detour them): %s"
                  % (len(dropped), ", ".join(dropped)))
        print("\nnow in the ADMIN window:  python hosts.py on")
    elif missing:
        print("\nrun  python scan.py --sync  to make the list match reality")
    return 0


if __name__ == "__main__":
    sys.exit(main())
