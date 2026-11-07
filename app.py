#!/usr/bin/env python3
"""
app.py - the tray app.

one window, numbered coloured switches, click one or press its number.
the X button hides it to the tray (show hidden icons) instead of quitting.
right-click the tray icon -> Exit to actually quit.

quitting always pulls the redirect back out, so the apps can never be
left pointing at a splitter that isn't running.
"""
import os, sys, time, json, ctypes, threading, subprocess, shutil

HERE = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False)
                                       else __file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import proxy
from proxy import Splitter

APP = "Unblock"
TASK = "UnblockSplitter"
SETTINGS = os.path.join(HERE, "settings.json")
HOSTS_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                          "System32", "drivers", "etc", "hosts")
BEGIN = "# >>> unblock begin >>>"
END = "# <<< unblock end <<<"

BG = "#0f1115"
PANEL = "#171a21"
EDGE = "#262b36"
TXT = "#e6e9ef"
DIM = "#7d8699"
GREEN = "#3ddc84"
RED = "#ff5f56"
AMBER = "#ffbd2e"
BLUE = "#5aa9ff"
PURPLE = "#c678dd"


# ------------------------------------------------------------------ admin

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def elevate():
    """relaunch ourselves through UAC and leave"""
    if getattr(sys, "frozen", False):
        exe, params = sys.executable, ""
    else:
        exe = sys.executable
        params = '"%s"' % os.path.abspath(__file__)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, HERE, 1)
    return rc > 32


# ------------------------------------------------------------------ hosts

def ensure_domains():
    """single-file exe: drop our bundled copy next to the exe on first run"""
    path = os.path.join(HERE, "domains.json")
    if os.path.exists(path):
        return path
    src = os.path.join(getattr(sys, "_MEIPASS", HERE), "domains.json")
    if os.path.exists(src) and os.path.abspath(src) != os.path.abspath(path):
        shutil.copy2(src, path)
    return path


def host_names():
    with open(ensure_domains()) as f:
        d = json.load(f)
    out, seen = [], set()
    for group in d.values():
        for n in group:
            if n not in seen:
                seen.add(n)
                out.append(n)
    return out


def _read():
    with open(HOSTS_PATH, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def _strip(text):
    if BEGIN not in text:
        return text, False
    pre, rest = text.split(BEGIN, 1)
    post = rest.split(END, 1)[1] if END in rest else ""
    return pre.rstrip("\r\n") + "\n" + post.lstrip("\r\n"), True


def _write(text):
    bak = HOSTS_PATH + ".unblock-backup"
    if not os.path.exists(bak):
        try:
            shutil.copy2(HOSTS_PATH, bak)
        except Exception:
            pass
    tmp = HOSTS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(text)
    os.replace(tmp, HOSTS_PATH)
    subprocess.run("ipconfig /flushdns", shell=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def redirect_is_on():
    try:
        return BEGIN in _read()
    except Exception:
        return False


def redirect_on():
    names = host_names()
    text, _ = _strip(_read())
    block = [BEGIN, "# %s - remove by quitting the app" % time.strftime("%Y-%m-%d %H:%M")]
    block += ["127.0.0.1\t%s" % n for n in names]
    block.append(END)
    _write(text.rstrip("\r\n") + "\n" + "\n".join(block) + "\n")
    return len(names)


def redirect_off():
    text, had = _strip(_read())
    if had:
        _write(text)
    return had


# ------------------------------------------------------------------ autostart

def autostart_is_on():
    r = subprocess.run('schtasks /Query /TN "%s"' % TASK, shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r.returncode == 0


def autostart_on():
    if getattr(sys, "frozen", False):
        cmd = '"%s"' % sys.executable
    else:
        pyw = sys.executable.replace("python.exe", "pythonw.exe")
        if not os.path.exists(pyw):
            pyw = sys.executable
        cmd = '\\"%s\\" \\"%s\\"' % (pyw, os.path.abspath(__file__))
    r = subprocess.run(
        'schtasks /Create /TN "%s" /TR "%s" /SC ONLOGON /RL HIGHEST /F' % (TASK, cmd),
        shell=True, capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


def autostart_off():
    r = subprocess.run('schtasks /Delete /TN "%s" /F' % TASK, shell=True,
                       capture_output=True, text=True)
    return r.returncode == 0, (r.stderr or r.stdout).strip()


# ------------------------------------------------------------------ settings

def load_settings():
    try:
        with open(SETTINGS) as f:
            return json.load(f)
    except Exception:
        return {"start_splitter": True, "safe_exit": True, "start_minimized": False}


def save_settings(s):
    try:
        with open(SETTINGS, "w") as f:
            json.dump(s, f, indent=2)
    except Exception:
        pass


# ------------------------------------------------------------------ icon

def make_icon(active):
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    ring = (61, 220, 132, 255) if active else (125, 134, 153, 255)
    d.ellipse([3, 3, 60, 60], outline=ring, width=6)
    # the split: two bars with a gap, which is the whole trick
    d.rectangle([20, 28, 30, 36], fill=ring)
    d.rectangle([35, 28, 45, 36], fill=ring)
    return img


# ------------------------------------------------------------------ app

class App:
    def __init__(self):
        import tkinter as tk
        self.tk = tk
        self.settings = load_settings()
        self.splitter = Splitter()
        self.lines = []
        self.tray = None
        self.quitting = False

        proxy.VERBOSE = False
        proxy.SINKS.append(self.push_line)
        proxy.load_recipe()

        self.root = tk.Tk()
        self.root.title(APP)
        self.root.configure(bg=BG)
        self.root.geometry("560x520")
        self.root.minsize(520, 460)
        self.root.protocol("WM_DELETE_WINDOW", self.hide)

        ensure_domains()
        self.rows = []
        self.build()
        self.refresh()

        for i in range(1, 6):
            self.root.bind(str(i), lambda e, n=i: self.activate(n))
        self.root.bind("<Escape>", lambda e: self.hide())

        if self.settings.get("start_splitter", True):
            self.do_splitter(True)

        threading.Thread(target=self.watchdog, daemon=True).start()
        self.start_tray()

        if self.settings.get("start_minimized"):
            self.root.after(300, self.hide)

    # ---------------- ui

    def build(self):
        tk = self.tk
        head = tk.Frame(self.root, bg=BG)
        head.pack(fill="x", padx=18, pady=(16, 6))
        tk.Label(head, text="UNBLOCK", bg=BG, fg=TXT,
                 font=("Consolas", 19, "bold")).pack(side="left")
        self.state_dot = tk.Label(head, text="\u25cf", bg=BG, fg=DIM,
                                  font=("Consolas", 17))
        self.state_dot.pack(side="right")
        self.state_txt = tk.Label(head, text="", bg=BG, fg=DIM,
                                  font=("Consolas", 10))
        self.state_txt.pack(side="right", padx=(0, 8))

        tk.Label(self.root,
                 text="click a line, or press its number",
                 bg=BG, fg=DIM, font=("Consolas", 9)).pack(anchor="w", padx=18)

        wrap = tk.Frame(self.root, bg=BG)
        wrap.pack(fill="x", padx=14, pady=(10, 6))

        self.specs = [
            (1, "SPLITTER", "the thing that beats the block", GREEN),
            (2, "AUTO-RESTART", "comes back on its own after a reboot", BLUE),
            (3, "REDIRECT", "sends roblox + discord through the splitter", AMBER),
            (4, "SAFE EXIT", "always undo the redirect when quitting", PURPLE),
            (5, "RESCAN + TUNE", "re-check the blocklist and the cut", RED),
        ]
        for n, name, desc, colour in self.specs:
            self.rows.append(self.make_row(wrap, n, name, desc, colour))

        tk.Label(self.root, text="live", bg=BG, fg=DIM,
                 font=("Consolas", 9)).pack(anchor="w", padx=18, pady=(8, 2))
        logf = tk.Frame(self.root, bg=PANEL, highlightthickness=1,
                        highlightbackground=EDGE)
        logf.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        self.logbox = tk.Text(logf, bg=PANEL, fg=DIM, bd=0, height=8,
                              font=("Consolas", 9), wrap="none",
                              state="disabled", padx=10, pady=8)
        self.logbox.pack(fill="both", expand=True)

    def make_row(self, parent, n, name, desc, colour):
        tk = self.tk
        f = tk.Frame(parent, bg=PANEL, highlightthickness=1,
                     highlightbackground=EDGE, cursor="hand2")
        f.pack(fill="x", pady=3)
        num = tk.Label(f, text=" %d " % n, bg=PANEL, fg=colour,
                       font=("Consolas", 13, "bold"), width=3)
        num.pack(side="left", padx=(8, 4), pady=9)
        mid = tk.Frame(f, bg=PANEL)
        mid.pack(side="left", fill="x", expand=True)
        tl = tk.Label(mid, text=name, bg=PANEL, fg=TXT,
                      font=("Consolas", 11, "bold"), anchor="w")
        tl.pack(anchor="w")
        dl = tk.Label(mid, text=desc, bg=PANEL, fg=DIM,
                      font=("Consolas", 8), anchor="w")
        dl.pack(anchor="w")
        pill = tk.Label(f, text="", bg=PANEL, fg=DIM,
                        font=("Consolas", 10, "bold"), width=9)
        pill.pack(side="right", padx=12)
        for w in (f, num, mid, tl, dl, pill):
            w.bind("<Button-1>", lambda e, k=n: self.activate(k))
        return {"n": n, "frame": f, "pill": pill, "colour": colour, "num": num}

    def set_pill(self, row, text, colour):
        row["pill"].config(text=text, fg=colour)
        row["frame"].config(highlightbackground=colour if text == "ON" else EDGE)

    def push_line(self, line):
        self.lines.append(time.strftime("[%H:%M:%S] ") + line)
        del self.lines[:-300]
        try:
            self.root.after(0, self.draw_log)
        except Exception:
            pass

    def draw_log(self):
        self.logbox.config(state="normal")
        self.logbox.delete("1.0", "end")
        self.logbox.insert("1.0", "\n".join(self.lines[-120:]))
        self.logbox.see("end")
        self.logbox.config(state="disabled")

    def refresh(self):
        sp = self.splitter.running
        rd = redirect_is_on()
        au = autostart_is_on()
        se = self.settings.get("safe_exit", True)
        self.set_pill(self.rows[0], "ON" if sp else "OFF", GREEN if sp else DIM)
        self.set_pill(self.rows[1], "ON" if au else "OFF", BLUE if au else DIM)
        self.set_pill(self.rows[2], "ON" if rd else "OFF", AMBER if rd else DIM)
        self.set_pill(self.rows[3], "ON" if se else "OFF", PURPLE if se else DIM)
        self.set_pill(self.rows[4], "run", RED)

        live = sp and rd
        self.state_dot.config(fg=GREEN if live else (AMBER if sp else RED))
        self.state_txt.config(
            text="working - %d connections - cut: %s"
                 % (self.splitter.served, proxy.current_recipe()) if live
            else ("splitter up, redirect off" if sp else "off"))
        if self.tray:
            try:
                self.tray.icon = make_icon(live)
                self.tray.title = "%s - %s" % (APP, "working" if live else "off")
            except Exception:
                pass

    # ---------------- actions

    def activate(self, n):
        if n == 1:
            self.do_splitter(not self.splitter.running)
        elif n == 2:
            self.do_autostart(not autostart_is_on())
        elif n == 3:
            self.do_redirect(not redirect_is_on())
        elif n == 4:
            self.settings["safe_exit"] = not self.settings.get("safe_exit", True)
            save_settings(self.settings)
            self.push_line("safe exit %s" % ("on" if self.settings["safe_exit"] else "OFF"))
        elif n == 5:
            threading.Thread(target=self.do_rescan, daemon=True).start()
        self.refresh()

    def do_splitter(self, want):
        if want:
            ok, msg = self.splitter.start()
            self.push_line(msg if ok else "splitter failed: " + msg)
        else:
            if redirect_is_on():
                self.do_redirect(False)
                self.push_line("redirect pulled first - never leave the apps stranded")
            self.splitter.stop()
        self.settings["start_splitter"] = bool(self.splitter.running)
        save_settings(self.settings)

    def do_redirect(self, want):
        try:
            if want:
                if not self.splitter.running:
                    ok, msg = self.splitter.start()
                    self.push_line("splitter started first: " + msg)
                    if not ok:
                        return
                n = redirect_on()
                self.push_line("redirect on - %d names -> 127.0.0.1" % n)
            else:
                if redirect_off():
                    self.push_line("redirect off - names resolve normally")
        except PermissionError:
            self.push_line("need admin to touch the hosts file")
        except Exception as e:
            self.push_line("redirect error: %s" % e)

    def do_autostart(self, want):
        ok, msg = autostart_on() if want else autostart_off()
        self.push_line(("auto-restart on - starts at logon, elevated" if want
                        else "auto-restart off") if ok else "autostart failed: " + msg)

    def do_rescan(self):
        self.push_line("rescanning blocked names...")
        import io, contextlib
        out = io.StringIO()
        try:
            import scan
            old = sys.argv
            sys.argv = ["scan.py", "--sync"]
            try:
                with contextlib.redirect_stdout(out):
                    scan.main()
            finally:
                sys.argv = old
        except Exception as e:
            self.push_line("rescan failed: %s" % e)
            return
        tail = [l for l in out.getvalue().splitlines()
                if "domains.json is now" in l or l.startswith("  added")
                or l.startswith("  dropped")]
        for l in (tail or ["rescan finished"]):
            self.push_line(l.strip()[:160])

        # the cut itself may need re-tuning if the ISP changed its box.
        # calibrate talks to the real servers over DoH, so the redirect
        # being installed does not skew it.
        self.push_line("tuning the cut...")
        out2 = io.StringIO()
        try:
            import calibrate
            with contextlib.redirect_stdout(out2):
                calibrate.main()
            for l in out2.getvalue().splitlines():
                if l.startswith("winner:") or l.startswith("best is"):
                    self.push_line(l.strip())
            proxy.load_recipe()
            self.push_line("cut in use: %s" % proxy.current_recipe())
        except Exception as e:
            self.push_line("tune failed: %s" % e)
        if redirect_is_on():
            redirect_off()
            redirect_on()
            self.push_line("redirect rewritten with the new list")
        self.root.after(0, self.refresh)

    def watchdog(self):
        """if the splitter ever dies while the redirect is in, pull the redirect"""
        while not self.quitting:
            time.sleep(2)
            try:
                if redirect_is_on() and not self.splitter.running:
                    redirect_off()
                    self.push_line("splitter was down - redirect pulled automatically")
                self.root.after(0, self.refresh)
            except Exception:
                pass

    # ---------------- tray

    def start_tray(self):
        import pystray
        from pystray import MenuItem as Item

        menu = pystray.Menu(
            Item("Open %s" % APP, self.show, default=True),
            pystray.Menu.SEPARATOR,
            Item("Splitter", lambda i, it: self.activate(1),
                 checked=lambda i: self.splitter.running),
            Item("Redirect", lambda i, it: self.activate(3),
                 checked=lambda i: redirect_is_on()),
            Item("Auto-restart", lambda i, it: self.activate(2),
                 checked=lambda i: autostart_is_on()),
            pystray.Menu.SEPARATOR,
            Item("Exit", self.quit),
        )
        self.tray = pystray.Icon(APP, make_icon(False), APP, menu)
        threading.Thread(target=self.tray.run, daemon=True).start()

    def show(self, *_):
        self.root.after(0, lambda: (self.root.deiconify(), self.root.lift(),
                                    self.root.focus_force()))

    def hide(self, *_):
        self.root.withdraw()
        self.push_line("hidden to the tray - show hidden icons, right-click, Exit to quit")

    def quit(self, *_):
        self.quitting = True
        try:
            if self.settings.get("safe_exit", True):
                redirect_off()
        except Exception:
            pass
        self.splitter.stop()
        try:
            self.tray.stop()
        except Exception:
            pass
        self.root.after(0, self.root.destroy)

    def run(self):
        self.root.mainloop()


def main():
    if not is_admin():
        if elevate():
            return 0
        ctypes.windll.user32.MessageBoxW(
            None, "Unblock needs administrator rights to edit the hosts file.\n"
                  "Right-click it and choose Run as administrator.", APP, 0x10)
        return 1
    App().run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
