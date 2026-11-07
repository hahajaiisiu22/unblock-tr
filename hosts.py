#!/usr/bin/env python3
"""
hosts.py - point the roblox/discord names at the local splitter, or put them back.

needs an ADMIN terminal (the hosts file is protected).

  python hosts.py on      point every name in domains.json at 127.0.0.1
  python hosts.py off     remove our block, restore nothing else
  python hosts.py status  show what is currently in there
"""
import json, os, sys, time, shutil, ctypes

HERE = os.path.dirname(os.path.abspath(__file__))
HOSTS = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                     "System32", "drivers", "etc", "hosts")
BEGIN = "# >>> unblock begin >>>"
END = "# <<< unblock end <<<"


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def load_domains():
    with open(os.path.join(HERE, "domains.json")) as f:
        d = json.load(f)
    out = []
    for group in d.values():
        out.extend(group)
    seen, uniq = set(), []
    for n in out:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


def read_hosts():
    with open(HOSTS, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def strip_block(text):
    if BEGIN not in text:
        return text, False
    pre, rest = text.split(BEGIN, 1)
    if END in rest:
        _mid, post = rest.split(END, 1)
    else:
        post = ""
    cleaned = pre.rstrip("\r\n") + "\n" + post.lstrip("\r\n")
    return cleaned, True


def write_hosts(text):
    bak = HOSTS + ".unblock-backup"
    if not os.path.exists(bak):
        shutil.copy2(HOSTS, bak)
        print("backed up original ->", bak)
    tmp = HOSTS + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(text)
    os.replace(tmp, HOSTS)


def flush_dns():
    os.system("ipconfig /flushdns >nul 2>&1")


def cmd_on():
    names = load_domains()
    text, had = strip_block(read_hosts())
    block = [BEGIN, "# added %s - python hosts.py off  to remove" % time.strftime("%Y-%m-%d %H:%M")]
    for n in names:
        block.append("127.0.0.1\t%s" % n)
    block.append(END)
    write_hosts(text.rstrip("\r\n") + "\n" + "\n".join(block) + "\n")
    flush_dns()
    print("%s %d names -> 127.0.0.1" % ("replaced block with" if had else "added", len(names)))
    print("now start the splitter in another terminal:  python proxy.py")


def cmd_off():
    text, had = strip_block(read_hosts())
    if not had:
        print("nothing of ours in the hosts file")
        return
    write_hosts(text)
    flush_dns()
    print("removed. names resolve normally again.")


def cmd_status():
    text = read_hosts()
    if BEGIN not in text:
        print("not installed")
        return
    body = text.split(BEGIN, 1)[1].split(END, 1)[0]
    lines = [l for l in body.splitlines() if l.strip() and not l.startswith("#")]
    print("installed - %d names redirected:" % len(lines))
    for l in lines[:8]:
        print("   " + l.strip())
    if len(lines) > 8:
        print("   ... and %d more" % (len(lines) - 8))


def main():
    cmd = (sys.argv[1] if len(sys.argv) > 1 else "status").lower()
    if cmd not in ("on", "off", "status"):
        print(__doc__)
        return 2
    if cmd in ("on", "off") and not is_admin():
        print("this needs an ADMIN terminal.")
        print("open the start menu, type powershell, right-click -> run as administrator,")
        print("then:  cd %s   and run the same command again." % HERE)
        return 1
    {"on": cmd_on, "off": cmd_off, "status": cmd_status}[cmd]()
    return 0


if __name__ == "__main__":
    sys.exit(main())
