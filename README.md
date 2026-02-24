# Singbox Reality Tunnel

> A zero-hassle bash script to deploy and manage VLESS + REALITY tunnels using sing-box on Ubuntu/Debian servers.

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
- Add multiple users to the server
- Auto-generates REALITY keypairs and UUIDs
- Outputs ready-to-use VLESS links for Hiddify, v2rayN, etc.
- Supports both stable and pre-release versions of sing-box
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
wget https://raw.githubusercontent.com/hesami/singbox-reality-tunnel/main/singbox-setup.sh

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
5. Print the server details and VLESS link

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
- Add a new user on the outbound server (option 3 in the menu)
- Import the generated VLESS link into Hiddify

---

## Menu Options

| Option | Description |
|--------|-------------|
| 1 | Install outbound server (VLESS+REALITY inbound) |
| 2 | Install Iran client (tunnel to outbound) |
| 3 | Add a new user and get VLESS link |
| 4 | Show service status and recent logs |
| 5 | Start / Stop / Restart service, live log |
| 6 | Update sing-box to latest stable or pre-release |
| 7 | Completely uninstall sing-box |

---

## Recommended SNI Domains

The SNI domain is used as camouflage. Choose a site that:
- Is always reachable from inside Iran
- Supports TLSv1.3
- Has high traffic (looks normal)

Good choices:
- `www.google.com`
- `www.microsoft.com`
- `dl.google.com`

Avoid sites that may be slow or blocked from your outbound server's location.

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
├── singbox-setup.sh    # Main setup script
└── README.md           # This file
```

Config is stored at `/etc/sing-box/config.json` on each server.

---

## License

MIT — use freely, modify as needed.
