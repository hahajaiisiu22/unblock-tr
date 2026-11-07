# Unblock

Roblox and Discord, on your own internet, without a VPN.

No tunnel. No server anywhere. No account. Nothing leaves your machine
except the traffic that was always going to Roblox and Discord anyway —
at your real speed, with your real ping.

![five coloured switches, a green dot, a live log](docs/screenshot.png)

---

## Why this exists

Roblox and Discord are blocked in Turkey. The usual answer is a VPN, and a
VPN works — but it drags every packet your computer sends through a server in
another country. Your ping goes from 40ms to 160ms, your downloads slow down,
and you end up flipping it on and off all day.

This does not do that. It changes about ten bytes in one packet, and those ten
bytes are the whole block.

## How the block actually works

When your computer opens an encrypted connection, the very first thing it says
is the name of the site — in plain text, before any encryption starts. It has
to; the server needs to know which certificate to send back. That field is
called **SNI**.

Your ISP runs a box that reads that field. If it sees `roblox`, it immediately
sends your computer a forged "connection closed" message. Your computer
believes it and gives up. That is the entire block:

- Your DNS is **not** poisoned — you get Roblox's real address.
- Roblox's servers are **not** unreachable — you can connect to the exact same
  IP and complete a handshake, as long as you say a different name.
- Only the **word** is the problem.

`diag.py` proves all three of those on your own connection in about a minute.

## How this beats it

A TLS handshake can legally arrive split across several TLS records. The
filtering box glues TCP packets back together before it looks — so slicing
packets does not fool it — but it does not reassemble *records*.

So the handshake is re-cut into two records straight through the middle of the
hostname. The box sees `www.rob` in one and `lox.com` in the other, matches
neither, and passes both along. The real server reassembles them correctly,
because that is what the spec says to do.

Both records go out in **one packet**. There is no delay, no extra round trip,
no bandwidth cost. Measured against the ISP this was built on:

| | result |
|---|---|
| normal handshake | killed on all 61 blocked hosts |
| cut mid-hostname | 24/24 through, repeated |

Nothing is decrypted. The certificate still comes from Roblox's own servers,
so certificate pinning is untouched and nothing can tell the difference.

### It tunes itself

Different ISPs run different boxes. `calibrate.py` probes nine different cuts
against the hosts that are *actually* blocked on your connection and saves the
one that wins. If your ISP's box is different from the one this was written
against, the app finds that out by itself.

## Install

Grab `Unblock.exe` from [Releases](../../releases), double-click, click **Yes**
on the prompt. That's it — no Python, no install, one file.

It asks for administrator because it writes a block of entries into the Windows
`hosts` file. That is the only reason, and the file is backed up first to
`hosts.unblock-backup`.

**Press 1, press 3, done.**

| key | | what it does |
|---|---|---|
| **1** | SPLITTER | the part that beats the block |
| **2** | AUTO-RESTART | registers a logon task so it comes back after a reboot |
| **3** | REDIRECT | points the blocked names at the splitter |
| **4** | SAFE EXIT | always undo the redirect when quitting (leave this on) |
| **5** | RESCAN + TUNE | re-check which names are blocked and which cut wins |

The **X button hides it to the tray** rather than quitting. The icon lives under
*show hidden icons* — green when it's working, grey when it isn't. Right-click
it for Exit.

### You cannot get stranded

The redirect points Roblox and Discord at your own machine. If the splitter
stopped while that was in place, both apps would be *deader* than before you
installed anything. So:

- quitting always removes the redirect
- turning the splitter off removes the redirect first
- a watchdog checks every 2 seconds and rips the redirect out on its own if the
  splitter dies unexpectedly

There is no state this leaves you broken in. If you ever want to be certain,
delete the block between `# >>> unblock begin >>>` and `# <<< unblock end <<<`
in `C:\Windows\System32\drivers\etc\hosts`.

## Run from source

```
pip install pystray pillow
python app.py
```

Just the proxy, no GUI, from an admin terminal:

```
python hosts.py on
python proxy.py
```

Build the exe:

```
pip install pyinstaller
python -m PyInstaller --onefile --noconsole --uac-admin --name Unblock ^
  --icon unblock.ico --add-data "domains.json;." ^
  --hidden-import scan --hidden-import diag --hidden-import proxy ^
  --hidden-import pystray._win32 app.py
```

## What each file is

| file | |
|---|---|
| `diag.py` | works out which layer is blocking you: DNS, the name in the handshake, or the IP itself |
| `recipe.py` | the experiment — twelve different cuts, scored against every blocked host |
| `calibrate.py` | picks the winning cut for your connection and saves it |
| `scan.py` | probes 103 names and rewrites `domains.json` to exactly the blocked ones |
| `proxy.py` | the splitter — reads the hostname, re-cuts the handshake, pipes bytes |
| `hosts.py` | adds and removes the `hosts` entries |
| `app.py` | the tray app |
| `domains.json` | the blocked names, maintained by `scan.py` rather than by hand |

Start with `diag.py`. If your output does not look like RST on the Roblox names
and TLS_OK on the controls, your block is a different shape and the rest of
this will not help you as-is — open an issue with the output.

## Limits, honestly

- **Windows only.** The splitter is portable Python; the `hosts` and tray parts
  are not.
- **Only HTTPS.** Roblox gameplay and Discord voice run over UDP to servers that
  are not filtered, so they never needed help. If your ISP starts blocking those
  too, this will not cover it.
- **The name list needs feeding.** Roblox adds subdomains. Press 5 when
  something breaks.
- **If your ISP starts reassembling TLS records**, this stops working, and the
  next move is a different cut — which is exactly what `recipe.py` and
  `calibrate.py` are for.
- Nothing here hides *that* you are connecting to Roblox. Your ISP can still see
  the destination IP. This defeats a word-matcher, not surveillance.

## Türkçe — kısa özet

Roblox ve Discord'u VPN olmadan, kendi internetinizle açar. Tünel yok, sunucu
yok, hesap yok. Ping'iniz gerçek ping'iniz olarak kalır.

Engel şöyle çalışır: bilgisayarınız her şifreli bağlantının en başında sitenin
adını açık metin olarak söyler. Operatörünüzdeki bir kutu bu alanı okur,
`roblox` görür ve bağlantıyı sahte bir "kapatıldı" mesajıyla keser. DNS'iniz
bozulmuyor, Roblox'un sunucuları erişilebilir durumda — sorun sadece o kelime.

Bu program el sıkışmasını tam ismin ortasından iki TLS kaydına böler. Kutu
`www.rob` ve `lox.com` görür, ikisini de tanımaz ve geçirir. Gecikme eklemez.

`Unblock.exe` dosyasını indirin, çift tıklayın, **Evet**'e basın, sonra
**1** ve **3** tuşlarına basın. Kapatmak için simgeyi gizli simgeler
bölümünden sağ tıklayıp **Exit**.

## License

MIT. Do what you like with it.
