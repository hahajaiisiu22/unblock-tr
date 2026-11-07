#!/usr/bin/env python3
"""
proxy.py - the local splitter.

sits on 127.0.0.1:443. anything that connects to it gets its TLS ClientHello
re-cut into two TLS records right through the middle of the hostname, in one
packet, with no added delay - the recipe that scored 9/9 against the filter.
after the handshake it is a dumb byte pipe. nothing is decrypted here; the
certificate still comes from the real server, so cert pinning is untouched.

needs DoH for name lookups, because the hosts file points these names at us.

run:  python proxy.py
stop: ctrl+c
"""
import socket, struct, threading, time, json, sys, os, base64, ssl, urllib.request

LISTEN = ("127.0.0.1", 443)
HERE = (os.path.dirname(os.path.abspath(sys.executable))
        if getattr(sys, "frozen", False)
        else os.path.dirname(os.path.abspath(__file__)))
DOH_IPS = ["1.1.1.1", "1.0.0.1", "9.9.9.9"]
TTL = 300.0
VERBOSE = "-q" not in sys.argv

_cache = {}
_cache_lock = threading.Lock()


SINKS = []          # the tray app drops a callback in here to see the lines


def log(*a):
    line = " ".join(str(x) for x in a)
    if VERBOSE:
        print(time.strftime("[%H:%M:%S]"), line, flush=True)
    for fn in list(SINKS):
        try:
            fn(line)
        except Exception:
            pass


# ---------------- dns over https (by ip, so our own hosts entries can't trap us)

def _dns_query(name):
    hdr = os.urandom(2) + b"\x01\x00" + struct.pack(">HHHH", 1, 0, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return hdr + q + struct.pack(">HH", 1, 1)


def _skip_name(b, off):
    while True:
        l = b[off]
        if l == 0:
            return off + 1
        if l & 0xC0 == 0xC0:
            return off + 2
        off += 1 + l


def _dns_parse(buf):
    if len(buf) < 12:
        return []
    qd, an = struct.unpack(">HH", buf[4:8])
    off = 12
    try:
        for _ in range(qd):
            off = _skip_name(buf, off) + 4
        ips = []
        for _ in range(an):
            off = _skip_name(buf, off)
            t, _c, _ttl, dl = struct.unpack(">HHIH", buf[off:off + 10])
            off += 10
            if t == 1 and dl == 4:
                ips.append(socket.inet_ntoa(buf[off:off + 4]))
            off += dl
        return ips
    except Exception:
        return []


_doh_ctx = ssl.create_default_context()
_doh_ctx.check_hostname = False
_doh_ctx.verify_mode = ssl.CERT_NONE


def resolve(name):
    now = time.time()
    with _cache_lock:
        hit = _cache.get(name)
        if hit and hit[1] > now:
            return hit[0]
    q = base64.urlsafe_b64encode(_dns_query(name)).rstrip(b"=").decode()
    for server in DOH_IPS:
        try:
            req = urllib.request.Request(
                "https://%s/dns-query?dns=%s" % (server, q),
                headers={"Accept": "application/dns-message"})
            with urllib.request.urlopen(req, timeout=6, context=_doh_ctx) as r:
                ips = _dns_parse(r.read())
            if ips:
                with _cache_lock:
                    _cache[name] = (ips, now + TTL)
                return ips
        except Exception as e:
            log("doh %s failed for %s: %s" % (server, name, type(e).__name__))
    return []


# ---------------- clienthello

def read_record(sock, timeout=10):
    """read exactly one TLS record. returns (header5, payload) or (None, buffered)"""
    sock.settimeout(timeout)
    head = b""
    while len(head) < 5:
        chunk = sock.recv(5 - len(head))
        if not chunk:
            return None, head
        head += chunk
    if head[0] != 0x16:
        return None, head
    want = struct.unpack(">H", head[3:5])[0]
    pl = b""
    while len(pl) < want:
        chunk = sock.recv(want - len(pl))
        if not chunk:
            return None, head + pl
        pl += chunk
    return head, pl


def parse_sni(pl):
    """pull the hostname out of a ClientHello handshake payload. returns (host, start, end)"""
    try:
        if not pl or pl[0] != 0x01:
            return None, 0, 0
        o = 4                      # handshake type + 3-byte length
        o += 2 + 32                # client_version + random
        o += 1 + pl[o]             # session_id
        o += 2 + struct.unpack(">H", pl[o:o + 2])[0]   # cipher_suites
        o += 1 + pl[o]             # compression_methods
        if o + 2 > len(pl):
            return None, 0, 0
        ext_end = o + 2 + struct.unpack(">H", pl[o:o + 2])[0]
        o += 2
        while o + 4 <= min(ext_end, len(pl)):
            etype, elen = struct.unpack(">HH", pl[o:o + 4])
            body = o + 4
            if etype == 0x0000 and elen >= 5:
                # server_name_list -> entry: type(1) len(2) host
                p = body + 2
                if pl[p] == 0:
                    hlen = struct.unpack(">H", pl[p + 1:p + 3])[0]
                    hs = p + 3
                    return pl[hs:hs + hlen].decode("ascii", "ignore"), hs, hs + hlen
            o = body + elen
    except Exception:
        pass
    return None, 0, 0


def _rec(p):
    return b"\x16\x03\x01" + struct.pack(">H", len(p)) + p


def _cut_at(pl, i):
    i = max(1, min(i, len(pl) - 1))
    return _rec(pl[:i]) + _rec(pl[i:])


# every one of these is a legal TLS handshake - the records are just cut
# in places a filter that doesn't reassemble records will choke on.
# different ISPs run different boxes, so calibrate.py picks the one that wins.
RECIPES = {
    "in-host":       lambda pl, a, b: _cut_at(pl, a + max(1, (b - a) // 2) if b > a else len(pl) // 2),
    "before-host":   lambda pl, a, b: _cut_at(pl, a if b > a else len(pl) // 2),
    "first1":        lambda pl, a, b: _cut_at(pl, 1),
    "first5":        lambda pl, a, b: _cut_at(pl, 5),
    "half":          lambda pl, a, b: _cut_at(pl, len(pl) // 2),
    "host-isolated": lambda pl, a, b: (_rec(pl[:a]) + _rec(pl[a:b]) + _rec(pl[b:])
                                       if b > a else _cut_at(pl, len(pl) // 2)),
    "chunk16":       lambda pl, a, b: b"".join(_rec(pl[i:i + 16]) for i in range(0, len(pl), 16)),
    "chunk64":       lambda pl, a, b: b"".join(_rec(pl[i:i + 64]) for i in range(0, len(pl), 64)),
    "none":          lambda pl, a, b: _rec(pl),
}

DEFAULT_RECIPE = "in-host"
_recipe = DEFAULT_RECIPE


def set_recipe(name):
    global _recipe
    _recipe = name if name in RECIPES else DEFAULT_RECIPE
    return _recipe


def current_recipe():
    return _recipe


def load_recipe():
    """settings.json may carry a recipe calibrate.py picked for this connection"""
    try:
        with open(os.path.join(HERE, "settings.json")) as f:
            return set_recipe(json.load(f).get("recipe", DEFAULT_RECIPE))
    except Exception:
        return set_recipe(DEFAULT_RECIPE)


def split_hello(pl, start, end):
    return RECIPES[_recipe](pl, start, end)


# ---------------- pipe

def pipe(src, dst, tag):
    try:
        src.settimeout(None)
        while True:
            d = src.recv(65536)
            if not d:
                break
            dst.sendall(d)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                s.close()
            except Exception:
                pass


def handle(client, peer):
    up = None
    try:
        head, pl = read_record(client)
        if head is None:
            log("%s:%d  not a TLS hello, dropped" % peer)
            client.close()
            return

        host, hs, he = parse_sni(pl)
        if not host:
            log("%s:%d  hello with no hostname, dropped" % peer)
            client.close()
            return

        ips = resolve(host)
        if not ips:
            log("%s -> no address (DoH down?)" % host)
            client.close()
            return

        t0 = time.time()
        up = socket.socket()
        up.settimeout(8)
        up.connect((ips[0], 443))
        up.sendall(split_hello(pl, hs, he))
        log("%s -> %s  split at %d/%d  %dms"
            % (host, ips[0], hs + (he - hs) // 2, len(pl), (time.time() - t0) * 1000))

        threading.Thread(target=pipe, args=(up, client, "down"), daemon=True).start()
        pipe(client, up, "up")
    except Exception as e:
        log("error for %s:%d - %s: %s" % (peer[0], peer[1], type(e).__name__, e))
        for s in (client, up):
            if s:
                try:
                    s.close()
                except Exception:
                    pass


class Splitter:
    """the server, as an object, so the tray app can flip it on and off"""

    def __init__(self, on_event=None):
        self.srv = None
        self.thread = None
        self.running = False
        self.served = 0
        self.on_event = on_event or (lambda line: None)

    def emit(self, line):
        try:
            self.on_event(line)
        except Exception:
            pass

    def start(self):
        if self.running:
            return True, "already running"
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(LISTEN)
        except OSError as e:
            s.close()
            return False, "cannot bind %s:%d - %s" % (LISTEN[0], LISTEN[1], e)
        s.listen(256)
        self.srv = s
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.emit("splitter up on %s:%d" % LISTEN)
        return True, "up"

    def _loop(self):
        while self.running:
            try:
                c, peer = self.srv.accept()
            except OSError:
                break
            self.served += 1
            threading.Thread(target=self._handle, args=(c, peer), daemon=True).start()
        self.running = False

    def _handle(self, c, peer):
        global log
        handle(c, peer)

    def stop(self):
        self.running = False
        if self.srv:
            try:
                self.srv.close()
            except Exception:
                pass
            self.srv = None
        self.emit("splitter down")


def main():
    with open(os.path.join(HERE, "domains.json")) as f:
        d = json.load(f)
    total = sum(len(v) for v in d.values())

    load_recipe()
    sp = Splitter()
    ok, msg = sp.start()
    if not ok:
        print(msg)
        print("something else owns 443. find it:  netstat -ano | findstr :443")
        return 1
    print("splitter up on %s:%d   covering %d domains" % (LISTEN[0], LISTEN[1], total))
    print("recipe: %s" % current_recipe())
    print("ctrl+c to stop\n")

    try:
        while sp.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        sp.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
