#!/usr/bin/env python3
"""
diag.py - find out WHICH layer blocks roblox/discord on this connection.

run this with the VPN OFF. no admin needed.
it only sends probes and reads what comes back. it changes nothing.
"""
import socket, ssl, struct, os, time, base64, urllib.request

TARGETS = {
    "roblox": ["www.roblox.com", "apis.roblox.com", "gamejoin.roblox.com",
               "clientsettings.roblox.com", "assetdelivery.roblox.com"],
    "discord": ["discord.com", "gateway.discord.gg", "cdn.discordapp.com",
                "discord.media"],
    "control": ["example.com", "www.cloudflare.com"],
}

# ---------- dns ----------

def dns_query(name, qtype=1):
    hdr = os.urandom(2) + b"\x01\x00" + struct.pack(">HHHH", 1, 0, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return hdr + q + struct.pack(">HH", qtype, 1)

def skip_name(b, off):
    while True:
        l = b[off]
        if l == 0:
            return off + 1
        if l & 0xC0 == 0xC0:
            return off + 2
        off += 1 + l

def dns_parse(buf):
    if len(buf) < 12:
        return "SHORT", []
    rcode = buf[3] & 0xF
    qd, an = struct.unpack(">HH", buf[4:8])
    off = 12
    try:
        for _ in range(qd):
            off = skip_name(buf, off) + 4
        ips = []
        for _ in range(an):
            off = skip_name(buf, off)
            t, _c, _ttl, dl = struct.unpack(">HHIH", buf[off:off + 10])
            off += 10
            if t == 1 and dl == 4:
                ips.append(socket.inet_ntoa(buf[off:off + 4]))
            off += dl
        return rcode, ips
    except Exception:
        return "MALFORMED", []

def dns_udp(server, name, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(dns_query(name), (server, 53))
        d, _ = s.recvfrom(4096)
        return dns_parse(d)
    except Exception as e:
        return "ERR:" + type(e).__name__, []
    finally:
        s.close()

def dns_doh(name, timeout=8):
    q = base64.urlsafe_b64encode(dns_query(name)).rstrip(b"=").decode()
    req = urllib.request.Request("https://1.1.1.1/dns-query?dns=" + q,
                                 headers={"Accept": "application/dns-message"})
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return dns_parse(r.read())
    except Exception as e:
        return "ERR:" + type(e).__name__, []

def dns_system(name):
    try:
        return 0, sorted({ai[4][0] for ai in socket.getaddrinfo(name, 443, socket.AF_INET)})
    except Exception as e:
        return "ERR:" + type(e).__name__, []

# ---------- tls ----------

def client_hello(sni):
    ext = b""
    if sni:
        hn = sni.encode()
        sn = b"\x00" + struct.pack(">H", len(hn)) + hn
        ext += b"\x00\x00" + struct.pack(">H", len(sn) + 2) + struct.pack(">H", len(sn)) + sn
    g = b"\x00\x1d\x00\x17\x00\x18"
    ext += b"\x00\x0a" + struct.pack(">H", len(g) + 2) + struct.pack(">H", len(g)) + g
    ext += b"\x00\x0b\x00\x02\x01\x00"
    sa = b"\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06\x01\x02\x01"
    ext += b"\x00\x0d" + struct.pack(">H", len(sa) + 2) + struct.pack(">H", len(sa)) + sa
    ext += b"\xff\x01\x00\x01\x00"  # renegotiation_info
    alpn = b"\x02h2\x08http/1.1"
    ext += b"\x00\x10" + struct.pack(">H", len(alpn) + 2) + struct.pack(">H", len(alpn)) + alpn
    # tls 1.2 only - no supported_versions, so no key_share is required of us
    cs = b"\xc0\x2b\xc0\x2c\xc0\x2f\xc0\x30\x00\x9c\x00\x9d\x00\x2f\x00\x35"
    body = b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
    body += struct.pack(">H", len(cs)) + cs + b"\x01\x00"
    body += struct.pack(">H", len(ext)) + ext
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs

ALERT = {40: "handshake_failure", 47: "illegal_parameter", 50: "decode_error",
         70: "protocol_version", 80: "internal_error", 109: "missing_extension",
         112: "unrecognized_name", 120: "no_application_protocol"}

def read_reply(s):
    d = s.recv(16)
    if not d:
        return "EOF_no_data"
    if d[0] == 0x16:
        return "TLS_OK"
    if d[0] == 0x15:
        desc = d[6] if len(d) >= 7 else -1
        return "alert:%s" % ALERT.get(desc, desc)
    if d[:4].lower().startswith(b"http"):
        return "HTTP_injected"
    return "odd:" + d[:8].hex()

def probe(ip, sni, mode, timeout=6):
    ch = client_hello(sni)
    s = socket.socket()
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, 443))
    except Exception as e:
        return "TCP_fail(%s)" % type(e).__name__, time.time() - t0
    try:
        if mode == "whole":
            s.sendall(ch)
        elif mode == "frag":
            cut = -1
            for needle in (b"roblox", b"discord"):
                i = ch.find(needle)
                if i > 0:
                    cut = i + 3
                    break
            if cut < 0:
                cut = len(ch) // 2
            s.sendall(ch[:cut])
            time.sleep(0.15)
            s.sendall(ch[cut:])
        elif mode == "records":
            pl = ch[5:]
            h = len(pl) // 2
            s.sendall(b"\x16\x03\x01" + struct.pack(">H", h) + pl[:h])
            time.sleep(0.15)
            s.sendall(b"\x16\x03\x01" + struct.pack(">H", len(pl) - h) + pl[h:])
        return read_reply(s), time.time() - t0
    except ConnectionResetError:
        return "RST_injected", time.time() - t0
    except socket.timeout:
        return "dropped(timeout)", time.time() - t0
    except Exception as e:
        return "err(%s)" % type(e).__name__, time.time() - t0
    finally:
        s.close()

# ---------- run ----------

def main():
    print("=" * 78)
    print("  block-layer diagnostic   (run with VPN OFF)")
    print("=" * 78)

    truth = {}
    for group, names in TARGETS.items():
        print("\n[%s]" % group.upper())
        for n in names:
            rc_d, ip_d = dns_doh(n)
            rc_s, ip_s = dns_system(n)
            rc_g, ip_g = dns_udp("8.8.8.8", n)
            truth[n] = ip_d[0] if ip_d else None
            if not ip_s:
                same = "NO_ANSWER"
            elif ip_d and set(ip_s) & set(ip_d):
                same = "same"
            else:
                same = "MISMATCH"
            print("  %-30s doh=%-15s sys=%-15s g8=%-15s %s"
                  % (n,
                     (ip_d[0] if ip_d else rc_d),
                     (ip_s[0] if ip_s else rc_s),
                     (ip_g[0] if ip_g else rc_g),
                     same))

    print("\n" + "=" * 78)
    print("  tls probes straight at the REAL ip (dns taken out of the picture)")
    print("=" * 78)
    print("  %-30s %-17s %-17s %-17s" % ("host", "whole-CH", "frag-CH", "split-records"))
    for group, names in TARGETS.items():
        for n in names:
            ip = truth.get(n)
            if not ip:
                print("  %-30s  (no ip from DoH - skipped)" % n)
                continue
            r1, _ = probe(ip, n, "whole")
            r2, _ = probe(ip, n, "frag")
            r3, _ = probe(ip, n, "records")
            print("  %-30s %-17s %-17s %-17s" % (n[:30], r1, r2, r3))

    print("\n" + "=" * 78)
    print("  is the IP itself blocked, or only the name inside the handshake?")
    print("=" * 78)
    for n in ("www.roblox.com", "discord.com", "gateway.discord.gg"):
        ip = truth.get(n)
        if not ip:
            continue
        real, _ = probe(ip, n, "whole")
        fake, _ = probe(ip, "example.com", "whole")
        none_, _ = probe(ip, None, "whole")
        print("  %-20s %-15s real:%-15s example.com:%-15s no-sni:%s"
              % (n, ip, real, fake, none_))

    print("\ndone. paste this whole output back.")

if __name__ == "__main__":
    main()
