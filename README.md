# singbox-reality-tunnel

> A zero-hassle bash script to deploy and manage VLESS + REALITY tunnels using sing-box on Ubuntu/Debian servers.

**Author:** Mehdi Hesami

---

## What is this?

This script automates the full setup of a two-server anti-censorship tunnel:

```
Your Device  ──►  Iran Server (client)  ──►  Outbound Server (Germany)  ──►  Internet
```

It uses **VLESS + REALITY** protocol via [sing-box](https://github.com/SagerNet/sing-box), which disguises your traffic as normal HTTPS traffic to trusted sites (like `www.google.com`), making it very difficult for DPI (Deep Packet Inspection) systems to detect or block.

---

## Features

- Interactive menu — no manual config editing required
- Install outbound server (e.g. Germany) in one step
- Install Iran client with automatic tunnel setup and connection test
- Full user management: add, list, edit quota, enable/disable, delete, reset traffic
- Traffic quota per user with usage tracking
- QR code generation for VLESS links (scan directly with Hiddify / v2rayN mobile)
- Auto-generates REALITY keypairs and UUIDs
- Outputs ready-to-use VLESS links compatible with v2rayN and Hiddify
- Supports both stable and pre-release versions of sing-box
- BBR congestion control + TCP buffer optimization
- Built-in speed test (speedtest-cli or curl-based)
- Fail2ban integration for intrusion protection against port scanners
- Update, restart, and uninstall from the same menu
- Full error handling with meaningful messages

---

## Requirements

- Ubuntu 20.04+ or Debian 11+ (on both servers)
- Root access
- Two VPS servers:
  - **Outbound server**: located outside Iran (e.g. Germany, Netherlands)
  - **Iran server** *(optional)*: located in Iran, used as a relay

---

## Quick Start

```bash
wget https://raw.githubusercontent.com/YOUR_USERNAME/singbox-reality-tunnel/main/singbox-setup.sh
chmod +x singbox-setup.sh
sudo bash singbox-setup.sh
```

---

## Setup Guide

### Step 1 — Outbound Server (Germany)

Run the script and choose **option 1**:

```
1) Install outbound server (e.g. Germany)
```

The script will:
1. Download and install sing-box
2. Ask for port, SNI, UUID (with defaults)
3. Auto-generate REALITY keypair
4. Write config and start the service
5. Print the server details, VLESS link, and QR code

**Save the output** — you will need the `PublicKey`, `UUID`, and `IP` for the next step.

---

### Step 2 — Iran Client (Relay)

SSH into your Iran server, run the script, and choose **option 2**:

```
2) Install Iran client (tunnel to outbound)
```

Enter the details from Step 1 when prompted. The script will automatically test the tunnel and show the outbound IP.

---

### Step 3 — Connect from Windows / macOS

Use [Hiddify](https://github.com/hiddify/hiddify-app) or [v2rayN](https://github.com/2dust/v2rayN).

**Option A** — Connect via Iran relay server (slower, more stable):
- Add a new VLESS profile pointing to your **Iran server IP**

**Option B** — Connect directly to outbound server (faster):
- Go to menu **3 → User Management → Add new user**
- Scan the QR code with Hiddify or v2rayN mobile, or copy the VLESS link

---

## Menu Options

| Option | Description |
|--------|-------------|
| 1  | Install outbound server (VLESS+REALITY inbound) |
| 2  | Install Iran client (tunnel to outbound) |
| 3  | User management (add, list, quota, enable/disable, delete, QR code) |
| 4  | Show service status and recent logs |
| 5  | Start / Stop / Restart service, live log |
| 6  | Network optimization (BBR + TCP buffer tuning) |
| 7  | Fail2ban — intrusion protection (install, ban/unban, settings) |
| 8  | Speed test (full or quick curl-based) |
| 9  | Update sing-box to latest stable or pre-release |
| 10 | Completely uninstall sing-box |

---

## User Management

Each user has:
- **UUID** — unique identifier
- **Label** — friendly name shown in VLESS link
- **Quota** — traffic limit in GB (0 = unlimited)
- **Used** — tracked usage in MB/GB
- **Status** — enabled or disabled

Users are stored in `/etc/sing-box/users.json` and can be managed fully from the menu.

---

## Fail2ban Protection

The script can install and configure fail2ban to automatically ban IPs that repeatedly fail the REALITY handshake (port scanners, bots, etc.).

Default settings:
- **5 failed attempts** within **60 seconds** → ban for **1 hour**
- Bans apply to **all ports** (not just 443)

All settings are configurable from the menu without editing config files manually.

---

## Network Optimization (BBR)

BBR is Google's TCP congestion control algorithm that significantly improves throughput and stability on long-distance connections. Enable it from menu option 6.

Applied settings:
```
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
```

---

## Recommended SNI Domains

The SNI domain is used as camouflage. Choose a site that:
- Is always reachable from inside Iran
- Supports TLSv1.3
- Has high traffic (looks normal to DPI)

Good choices:
- `www.google.com` *(recommended)*
- `www.microsoft.com`
- `dl.google.com`

---

## Troubleshooting

**Service fails to start:**
```bash
sudo journalctl -u sing-box --no-pager -n 30
sudo journalctl -u sing-box-client --no-pager -n 30
```

**Connection test fails:**
```bash
curl -x socks5h://127.0.0.1:10808 https://ifconfig.me
```

**REALITY handshake error:**
- Make sure the SNI domain is reachable from your outbound server
- Verify `PublicKey` on client matches `PrivateKey` on server
- Try a different SNI domain (e.g. `www.microsoft.com`)

**DNS deprecation warning on sing-box 1.13+:**
The service file already includes `ENABLE_DEPRECATED_LEGACY_DNS_SERVERS=true` to handle this automatically.

---

## File Structure

```
singbox-reality-tunnel/
├── singbox-setup.sh    # Main setup and management script
└── README.md           # This file
```

Runtime files on server:
```
/etc/sing-box/config.json    # sing-box configuration
/etc/sing-box/users.json     # user database (quota, usage, status)
```

---

## License

MIT — use freely, modify as needed.
