# v4.0.4 — Stable Tunnel Health Checks

- Replaces `api.ipify.org` as the kill-switch / tunnel health oracle with Cloudflare `1.1.1.1/cdn-cgi/trace` over the reverse SOCKS tunnel.
- Retries tunnel probes to avoid false negatives from a single external service.
- Kill-switch now requires 5 consecutive failed probe cycles (each cycle retries twice) before stopping the customer gateway.
- Local VLESS/REALITY end-to-end self-test uses the same fixed endpoint, so intermittent `api.ipify.org` failures no longer look like REALITY failures.
- Pairing Code is unchanged and remains fully supported.
- Keeps the v4.0.1 SQLite/WAL subscription fix and v4.0.3 endpoint/REALITY diagnostics.

# v4.0.4 — Client Endpoint Separation + Deeper REALITY Diagnostics

- Separates the VLESS client endpoint from the HTTPS subscription hostname. The VLESS endpoint now defaults to the Iran public IP, while a domain such as `vp.example.com` can remain dedicated to HTTPS subscriptions.
- `Upgrade / repair runtime` migrates older v4.0.2 state by adding `client_host` with the detected Iran public IP without changing the subscription domain, certificate, users, UUIDs, Reality keys, quota or expiry.
- Generated v2rayN subscription links use `client_host` (public IP recommended) instead of reusing the subscription domain. This avoids client-side DNS overrides/fake-IP mappings breaking the VLESS TCP connection.
- Customer Gateway setup now verifies that the selected REALITY target completes a TLS certificate handshake from the Iran VPS before proceeding.
- The local REALITY client self-test now runs with debug logging, includes `spiderX=/`, and prints recent server access/error logs when the end-to-end test fails.
- Keeps the v4.0.1 SQLite/WAL subscription-service fix and all production hardening from v4.0.2.

# Iran ↔ Turkey Gateway Manager — v4.0.4 Minimal Production Edition

## v4.0.1 HTTPS subscription fix

The hardened subscription service now grants its systemd sandbox write access only to `/etc/singbox-manager/data` (required by SQLite WAL/SHM), returns/logs HTTP 500 instead of silently closing a request on internal errors, and performs a local subscription self-test during gateway setup.


This edition intentionally removes experimental transports that were not useful for the validated deployment. It keeps one production architecture:

```
v2rayN / customer
        │ VLESS + Reality
        ▼
     Iran VPS
 Customer Gateway
        │ SOCKS 127.0.0.1:10808
        ▼
 Hardened Reverse SSH
   Turkey → Iran
        │
        ▼
    Turkey VPS
        │
        ▼
     Internet
```

## Retained features

- Hardened Reverse SSH transport from Turkey to Iran
- Dedicated non-root tunnel account and dedicated sshd port
- Turkey-IP-only firewall rule for the tunnel sshd
- Automatic reconnect with systemd
- Safe BBR/TCP tuning when supported
- VLESS + Reality customer gateway on the Iran VPS
- Per-customer UUID, quota, expiry, enable/disable and traffic reset
- Individual v2rayN subscription URLs and QR codes
- HTTPS subscription using an existing certificate or Certbot DNS-01
- Subscription rate limiting + Fail2ban
- Kill-switch: customer gateway stops after repeated loss of Turkey egress
- Traffic accounting via Xray Stats API
- Tunnel key rotation
- Health checks, security audit, logs, backup/restore
- Optional cleanup of legacy experimental services

## Removed from this edition

- Hysteria2 tunnel modes
- Salamander / Gecko experiments
- sing-box tunnel client/server modes
- Xray Reality as the Iran→Turkey transport
- VLESS WS/gRPC tunnel menus
- Generic inbound manager and unrelated protocol menus

These removals are intentional. The production tunnel transport is Reverse SSH only.

## First-time installation

Extract the same package on both VPSs and run:

```bash
chmod +x manager.sh
bash manager.sh
```

### Step 1 — Turkey VPS

Choose:

`1) Guided Setup` → `1) Turkey / Foreign Exit`

Enter the Iran VPS IP. The wizard creates the Turkey connector and prints one **Pairing Code**.

### Step 2 — Iran VPS

Choose:

`1) Guided Setup` → `2) Iran Gateway`

Paste the Pairing Code. The wizard:

1. Creates the restricted tunnel account.
2. Creates a dedicated sshd listener (default 22022/tcp) restricted to the Turkey IP.
3. Waits for the Turkey connector.
4. Verifies that Internet egress is actually the Turkey VPS.
5. Offers to configure Customer Gateway.
6. Offers to create the first customer.

## Defaults

- Dedicated tunnel SSH: `22022/tcp`
- Reverse SOCKS on Iran: `127.0.0.1:10808`
- Customer VLESS Reality: `24443/tcp`
- Subscription server: `18080/tcp`

Ports 80/443 and nginx/website configuration are never modified by this manager.

## Upgrade from v3.x

The user database remains at:

`/etc/singbox-manager/data/users.db`

Existing customer records are retained. Old experimental services are **not automatically removed**. After verifying v4.0.4, use:

`Maintenance` → `Cleanup legacy experimental components`

This cleanup explicitly does not modify nginx, Apache or website data.

## Important

The manager improves security and operational resilience, but no Internet transport can be guaranteed to be invisible to DPI or impossible to block. Reverse SSH remains identifiable as SSH traffic to sufficiently capable network monitoring.
