<div align="center">

<h1>🔒 sing-box Setup & Manager</h1>

<p>
  <strong>A fully interactive Bash script for deploying and managing a VLESS + REALITY tunnel using <a href="https://github.com/SagerNet/sing-box">sing-box</a></strong><br/>
  Designed for the two-server bypass architecture: an <strong>outbound server</strong> (e.g. Germany) + an <strong>Iran-side client</strong>
</p>

<p>
  <img src="https://img.shields.io/badge/version-2.1.0-blue?style=flat-square" alt="version"/>
  <img src="https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-orange?style=flat-square" alt="platform"/>
  <img src="https://img.shields.io/badge/protocol-VLESS%20%2B%20REALITY-purple?style=flat-square" alt="protocol"/>
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="license"/>
</p>

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Requirements](#-requirements)
- [Quick Start](#-quick-start)
- [Menu Reference](#-menu-reference)
  - [1. Install Outbound Server](#1-install-outbound-server)
  - [2. Install Iran Client](#2-install-iran-client)
  - [3. User Management](#3-user-management)
  - [4. Status & Logs](#4-status--logs)
  - [5. Service Management](#5-service-management)
  - [6. Network & System Optimization](#6-network--system-optimization)
  - [7. Fail2ban — Intrusion Protection](#7-fail2ban--intrusion-protection)
  - [8. Speed Test](#8-speed-test)
  - [9. Update sing-box](#9-update-sing-box)
  - [10. Uninstall](#10-uninstall)
- [File Structure](#-file-structure)
- [VLESS Link Format](#-vless-link-format)
- [Security Notes](#-security-notes)
- [Troubleshooting](#-troubleshooting)
- [Author](#-author)

---

## 🌐 Overview

**sing-box Setup & Manager** is an all-in-one interactive Bash script that automates every aspect of running a VLESS + REALITY censorship-bypass tunnel. Instead of editing JSON configs by hand, you get a clean terminal menu that handles installation, user management, performance tuning, and intrusion protection — all in one place.

### ✨ Key Highlights

- **One-command deployment** — installs sing-box, generates keys, writes config, creates systemd service, opens firewall
- **Multi-user support** — add, remove, enable/disable users; each gets their own VLESS link + QR code
- **Full system optimizer** — BBR, TCP buffers, swappiness, CPU priority, OOM protection, file descriptors, journald
- **Fail2ban integration** — auto-detects log backend (systemd journal vs file), protects against brute-force
- **Live status dashboard** — every menu shows real-time state of all services
- **Safe by design** — `set -euo pipefail`, all destructive actions require confirmation

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Device                          │
│              v2rayN / Hiddify / NekoBox                     │
└────────────────────────┬────────────────────────────────────┘
                         │  VLESS + REALITY (TLS 1.3)
                         │  Disguised as: www.google.com
                         ▼
┌─────────────────────────────────────────────────────────────┐
│               Outbound Server  (e.g. Germany)               │
│                  sing-box  [inbound: VLESS]                  │
│               This script — Option 1                        │
└─────────────────────────────────────────────────────────────┘

         ─ ─ ─ OR use two-hop relay architecture ─ ─ ─

┌────────────────────┐        ┌────────────────────────────────┐
│   Client Device    │        │     Iran Relay Server          │
│  Any SOCKS5 app    │──────▶ │  sing-box [inbound: SOCKS5]    │
└────────────────────┘        │  This script — Option 2        │
                              └──────────────┬─────────────────┘
                                             │  VLESS + REALITY
                                             ▼
                              ┌──────────────────────────────── ┐
                              │   Outbound Server (Germany)     │
                              │  sing-box [inbound: VLESS]      │
                              └─────────────────────────────────┘
```

---

## 📦 Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Ubuntu 20.04 / 22.04 / 24.04 or Debian 11 / 12 |
| **Architecture** | x86_64 (amd64) |
| **User** | root or sudo |
| **RAM** | 512 MB minimum (1 GB recommended) |
| **Disk** | 2 GB free |
| **Network** | Access to GitHub (for downloading sing-box binary) |
| **Dependencies** | `curl`, `python3` (auto-installed if missing) |

> **Optional:** `qrencode` for terminal QR codes, `speedtest-cli` for speed tests — both auto-installed on demand.

---

## 🚀 Quick Start

```bash
# Download and run as root
wget -O singbox-manager.sh https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/singbox-manager.sh
chmod +x singbox-manager.sh
sudo bash singbox-manager.sh
```

Or run directly:

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/singbox-manager.sh)
```

> **Tip:** For a fresh server, run option `6 → 4 (Apply ALL optimizations)` right after installing the server.

---

## 📖 Menu Reference

### 1. Install Outbound Server

Deploys sing-box as a **VLESS + REALITY inbound** on your outbound server (the one outside the censored region).

**What it does, step by step:**

1. Downloads the latest stable (or pre-release) sing-box binary from GitHub
2. Prompts for configuration:
   - **UUID** — auto-generated, or enter your own
   - **Listen port** — default `443`
   - **SNI** — camouflage domain (default: `www.google.com`)
   - **Short ID** — REALITY handshake identifier
3. Generates a fresh REALITY **keypair** (private + public key)
4. Writes `/etc/sing-box/config.json`
5. Saves server info to `/etc/sing-box/server.json` (used by other menu options)
6. Creates and enables `sing-box.service` (systemd)
7. Opens the listen port in UFW / iptables
8. Starts the service and verifies it is running
9. Prints the complete **VLESS link** and shows a **terminal QR code**

**Output example:**
```
vless://xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx@1.2.3.4:443
  ?encryption=none&flow=xtls-rprx-vision&security=reality
  &sni=www.google.com&fp=chrome&pbk=<publickey>
  &sid=a1b2c3d4&type=tcp&headerType=none
  #Germany-Server
```

---

### 2. Install Iran Client

Deploys sing-box as a **local SOCKS5 proxy** that tunnels traffic to the outbound server. Useful for relay setups or running a proxy on an Iran-side server.

**Prompts for:**
- Outbound server IP and port
- UUID, PublicKey, Short ID, SNI (copy from Option 1 output)
- Local SOCKS5 port (default: `10808`)

**After install:** Automatically tests the tunnel by fetching the outbound IP through the SOCKS5 proxy and reports success/failure.

**systemd service:** `sing-box-client.service`

---

### 3. User Management

Full lifecycle management for all VLESS users.

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│  No.  UUID                                  Label                Quota        Used    Status │
│  ───────────────────────────────────────────────────────────────────────────────────────────│
│  1    550e8400-e29b-41d4-a716-446655440000  default              Unlimited    0.0 MB  ON     │
│  2    6ba7b810-9dad-11d1-80b4-00c04fd430c8  Alice                50 GB        12.4 GB ON     │
│  3    6ba7b811-9dad-11d1-80b4-00c04fd430c8  Bob                  10 GB        9.8 GB  OFF    │
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Option | Description |
|--------|-------------|
| **Add new user** | Generates UUID, sets label and optional traffic quota; prints VLESS link + QR |
| **View user details** | Shows full info + VLESS link + QR code for any user |
| **Edit quota** | Change a user's traffic quota (0 = unlimited) |
| **Enable / Disable** | Toggles user in the running config; takes effect immediately without restart |
| **Delete user** | Removes from both config and database; requires confirmation |
| **Reset traffic counter** | Zeroes the `used_bytes` counter in the database |

**Storage:** User data is persisted in `/etc/sing-box/users.json`. The running config at `/etc/sing-box/config.json` is always kept in sync.

---

### 4. Status & Logs

Displays a real-time overview:

- Active/inactive state of `sing-box` and `sing-box-client`
- Installed sing-box version
- Server info (PublicKey, SNI, Port) from `server.json`
- Last 10 lines of journal log for each active service

---

### 5. Service Management

Control sing-box without leaving the script:

| Option | Action |
|--------|--------|
| Start | `systemctl start` |
| Stop | `systemctl stop` |
| Restart | `systemctl restart` |
| Live log | `journalctl -u sing-box -f` (Ctrl+C to exit) |
| Switch service | Toggle between `sing-box` and `sing-box-client` |

---

### 6. Network & System Optimization

A three-level optimization suite designed to keep sing-box stable and fast on low-resource VPS servers (1 vCPU / 1 GB RAM). The top of the menu shows a **live status summary** of all subsystems.

```
  Network:  BBR [ON]  qdisc:fq  buffers: optimized
  System:   swappiness:10  sing-box nice:-5
  Storage:  journal:18.5M  fd-limit:1048576
```

#### 6.1 — Network: BBR & TCP

| Option | What it does |
|--------|-------------|
| **Enable BBR + FQ** | Sets `tcp_congestion_control=bbr` and `default_qdisc=fq`; checks kernel support |
| **Disable BBR** | Reverts to `cubic` |
| **TCP buffer optimization** | Raises `rmem_max` / `wmem_max` to 128 MB; sets `tcp_fastopen=3`, `tcp_mtu_probing=1`, `tcp_slow_start_after_idle=0`, `tcp_no_metrics_save=1` |
| **Apply both** | BBR + TCP buffers in one step |
| **Show values** | Prints all 11 relevant sysctl keys with current values |

#### 6.2 — System: Memory & CPU Priority

| Option | What it does |
|--------|-------------|
| **Optimize swap behavior** | `vm.swappiness=10`, `vm.vfs_cache_pressure=50` — kernel avoids swap until RAM is >90% full |
| **CPU priority** | Sets `Nice=-5` for sing-box via systemd drop-in; applies to running process immediately with `renice` |
| **OOM protection** | Sets `OOMScoreAdjust=-500` — Linux OOM killer will spare sing-box even under extreme memory pressure |
| **Apply all system** | All three above in one step |
| **Show info** | Live view of RAM, swap, load average, and sing-box process stats (PID, memory, CPU%, nice, OOM score) |

#### 6.3 — Storage: Logging & File Descriptors

| Option | What it does |
|--------|-------------|
| **Limit journald** | Caps journal at 50 MB (`SystemMaxUse=50M`); vacuums existing logs immediately; backs up original `journald.conf` |
| **File descriptors** | Raises `fs.file-max` to 1,048,576; sets PAM `nofile` limits; adds `LimitNOFILE=1048576` to systemd service drop-in |
| **Apply both** | Journal + FD in one step |
| **Show info** | Disk usage, journal size/limit, system fd limit, sing-box open fd count |

#### 6.4 — Apply ALL Optimizations ⭐

Runs all 6 steps in sequence with progress indicators. **Recommended after a fresh server install.**

```
── 1/6  BBR + FQ ──────────────────
── 2/6  TCP Buffers ───────────────
── 3/6  Swap & Cache ──────────────
── 4/6  CPU & OOM Priority ────────
── 5/6  File Descriptors ──────────
── 6/6  Journald Size ─────────────
```

#### 6.5 — Reset ALL to Defaults

Cleanly removes every optimization this script applied:
- Strips all added lines from `/etc/sysctl.conf`
- Restores `journald.conf` from backup
- Removes PAM `nofile` entries from `/etc/security/limits.conf`
- Deletes the systemd service drop-in directory
- Reloads all affected daemons

---

### 7. Fail2ban — Intrusion Protection

Protects the server from brute-force and invalid REALITY handshake attacks.

**Smart log detection:** Automatically determines whether to use the `systemd` journal backend or a file-based backend (`/var/log/sing-box/sing-box.log`) depending on what is available — no manual configuration needed.

| Option | Description |
|--------|-------------|
| **Install & configure** | Installs fail2ban + rsyslog (if needed), sets up sing-box log file, writes filter and jail config, starts service |
| **Show banned IPs** | Lists all currently banned IPs from the `singbox` jail |
| **Unban an IP** | Removes a specific IP from the ban list |
| **Change ban settings** | Update `maxretry`, `findtime`, `bantime` while preserving the existing backend |
| **Start / Stop** | Toggle fail2ban service |
| **Show live log** | `tail -f /var/log/fail2ban.log` |
| **Uninstall** | Removes fail2ban, cleans up all config files, rsyslog rules, and logrotate entries |

**Default ban settings:**
```
maxretry = 5 attempts
findtime = 60 seconds
bantime  = 3600 seconds (1 hour)
action   = iptables-allports (blocks all ports, not just VLESS)
```

**Filter regex** targets REALITY invalid connection log entries from sing-box.

---

### 8. Speed Test

Two testing modes:

| Mode | Tool | What it measures |
|------|------|-----------------|
| **Full speed test** | `speedtest-cli` | Download, upload, ping via Speedtest.net |
| **Quick test** | `curl` + `ping` | Download 10 MB & 50 MB from Cloudflare; latency to 1.1.1.1 and 8.8.8.8 |

`speedtest-cli` is auto-installed if not present.

---

### 9. Update sing-box

Updates the sing-box binary in-place:

1. Fetches latest version tag from GitHub API
2. Shows current vs. new version
3. Stops both services, installs new binary, restarts
4. Works for both stable and pre-release channels

---

### 10. Uninstall

Completely removes all traces of sing-box:

- Stops and disables both systemd services
- Deletes service unit files and drop-ins
- Removes the sing-box binary (`/usr/local/bin/sing-box`)
- Deletes the entire `/etc/sing-box/` directory (config, keys, user database)
- Runs `systemctl daemon-reload`

> ⚠️ This action is **irreversible**. The script asks for explicit confirmation before proceeding.

---

## 📁 File Structure

```
/usr/local/bin/
└── sing-box                         # Binary

/etc/sing-box/
├── config.json                      # Running configuration (inbounds/outbounds)
├── server.json                      # Server identity (keypair, SNI, port)
└── users.json                       # User database (uuid, label, quota, usage)

/etc/systemd/system/
├── sing-box.service                 # Server systemd unit
├── sing-box-client.service          # Client systemd unit
└── sing-box.service.d/
    └── priority.conf                # CPU/OOM/FD drop-in (created by optimizer)

/var/log/sing-box/
└── sing-box.log                     # Log file (created by fail2ban installer)

/etc/fail2ban/
├── jail.local                       # Fail2ban jail config
└── filter.d/
    └── singbox.conf                 # Fail2ban filter for REALITY logs

/etc/logrotate.d/
└── sing-box                         # Log rotation config

/etc/rsyslog.d/
└── 50-sing-box.conf                 # rsyslog forwarding rule (if applicable)
```

---

## 🔗 VLESS Link Format

Links generated by this script are compatible with **v2rayN**, **Hiddify**, **NekoBox**, **v2rayNG**, and other standard VLESS clients.

```
vless://<UUID>@<SERVER_IP>:<PORT>
  ?encryption=none
  &flow=xtls-rprx-vision
  &security=reality
  &sni=<SNI>
  &fp=chrome
  &pbk=<PUBLIC_KEY>
  &sid=<SHORT_ID>
  &type=tcp
  &headerType=none
  #<LABEL>
```

| Parameter | Description |
|-----------|-------------|
| `flow` | `xtls-rprx-vision` — required for REALITY |
| `security` | `reality` — TLS 1.3 with REALITY handshake |
| `sni` | Camouflage domain (e.g. `www.google.com`) |
| `fp` | TLS fingerprint — `chrome` |
| `pbk` | Server's REALITY public key |
| `sid` | Short ID for handshake verification |

---

## 🔐 Security Notes

- **REALITY private key** is stored only on the server in `/etc/sing-box/server.json`. Never share it.
- **UUID** acts as the user credential — treat it like a password.
- The script uses `set -euo pipefail` — it exits immediately on any unexpected error.
- All destructive operations (delete user, uninstall, reset) require explicit `y/n` confirmation.
- Fail2ban's `iptables-allports` action blocks **all ports** for a banned IP, not just the VLESS port.
- The OOM score adjustment (`-500`) ensures the kernel will never kill sing-box due to memory pressure — even on a 512 MB VPS.

---

## 🛠 Troubleshooting

**Service fails to start after install:**
```bash
journalctl -u sing-box --no-pager -n 30
```

**Check if port is already in use:**
```bash
ss -tlnp | grep :443
```

**Test VLESS connectivity manually:**
```bash
curl -v --connect-timeout 5 https://<SERVER_IP>
# Should return a TLS connection (mimicking the SNI site)
```

**Fail2ban not starting:**
```bash
journalctl -u fail2ban --no-pager -n 30
fail2ban-client --test
```

**High ping / packet loss from the server:**
```bash
# Check CPU steal time (high steal = noisy VPS neighbor)
top   # look for the 'st' column in the CPU line

# Check if BBR is actually active
sysctl net.ipv4.tcp_congestion_control

# Check memory pressure
free -m
cat /proc/meminfo | grep -i swap
```

**sing-box memory usage:**
```bash
ps aux | grep sing-box
# Or use option 6 → 2 → 5 (Show memory & CPU info)
```

---

## 👤 Author

**Mehdi Hesami**

- Script version: `2.1.0`
- Protocol: VLESS + REALITY ([sing-box](https://github.com/SagerNet/sing-box))
- Tested on: Ubuntu 22.04 LTS

---

<div align="center">

If this project helped you, consider giving it a ⭐ on GitHub.

</div>
