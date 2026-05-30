# BadWebsiteBlocker

A self-control website blocker for Windows 11 that is **near-impossible to disable** by design.

Once installed there is no admin panel, no password, no uninstaller, and no way to change settings. It is intentionally brutal — the goal is to make impulsive bypassing infeasible, not inconvenient.

---

## What it blocks

| Category | Source |
|---|---|
| Adult / pornography | [Steven Black's hosts project](https://github.com/StevenBlack/hosts) — updated list downloaded at install time |
| Gambling | Same source |
| Social media *(optional)* | Bundled list: Facebook, Instagram, TikTok, YouTube, Twitter/X, Reddit, Discord, Twitch, and more |

---

## How it works (four-layer defense)

| Layer | Mechanism |
|---|---|
| **DNS sinkhole** | A local DNS server on `127.0.0.1:53` returns NXDOMAIN for blocked domains |
| **Firewall rules** | Persistent Windows Firewall rules block all DNS traffic to external servers — only `127.0.0.1` is allowed |
| **Hosts file** | All blocked domains are written to the Windows hosts file; any modification is detected and reverted within seconds |
| **Dual watchdog services** | Two Windows services monitor each other — if one is stopped, the other restarts it within 5 seconds |

Bypassing requires: stopping both services simultaneously + removing firewall rules + editing the hosts file — all before the watchdog revives everything. Safe mode or OS reinstall are the only realistic exits.

---

## Installation

> **Requires Windows 10/11 and [.NET 8 Runtime](https://dotnet.microsoft.com/en-us/download/dotnet/8.0)**

1. Download `BadWebsiteBlocker-installer.zip` from [Releases](../../releases/latest)
2. Extract the zip
3. Right-click `BadBlocker.Installer.exe` → **Run as administrator**
4. Follow the prompts — you will be asked whether to block social media
5. Type `CONFIRM` when ready
6. Done — the blocker is active immediately

**There is no uninstaller.** This is intentional. You will be warned clearly before installation completes.

---

## Frequently asked questions

**Can I remove it later?**
Not easily, and not impulsively. That is the entire point. The only practical ways out are Windows Safe Mode (services don't load) or reinstalling the OS.

**Does it slow down my computer?**
No. Both services use under 35–45 MB of RAM combined and effectively 0% CPU at idle. DNS lookups across 100,000+ domains complete in under 25ms.

**Does it block HTTPS/DoH too?**
Yes. Browser built-in DNS-over-HTTPS is blocked by also listing all major DoH provider domains (`dns.google`, `cloudflare-dns.com`, etc.) in the blocklist.

**Will it block things I need?**
The adult and gambling lists come from Steven Black's widely-used public blocklist project — they are carefully maintained to avoid false positives. The social media list is conservative (major platforms only).

**What if the blocklists get out of date?**
Lists are downloaded fresh at install time. Once installed the lists are static — the service does not phone home or update automatically.

---

## Building from source

Requirements: [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download/dotnet/8.0), Windows

```
git clone https://github.com/YOUR_USERNAME/BadWebsiteBlocker.git
cd BadWebsiteBlocker
dotnet build BadBlocker.sln
dotnet test src/BadBlocker.Test
```

To publish a self-contained installer bundle:

```
dotnet publish src/BadBlocker.Service   -c Release -r win-x64 --self-contained false -o publish/service
dotnet publish src/BadBlocker.Guard     -c Release -r win-x64 --self-contained false -o publish/guard
dotnet publish src/BadBlocker.Installer -c Release -r win-x64 --self-contained false -o publish/installer
copy publish\service\BadBlocker.Service.exe publish\installer\
copy publish\guard\BadBlocker.Guard.exe     publish\installer\
xcopy /E lists publish\installer\lists\
```

Then zip the `publish/installer` folder and attach it to a GitHub Release.

---

## License

MIT — use freely, modify freely, no warranty.
