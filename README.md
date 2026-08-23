# Iran ↔ Foreign Gateway Manager — v4.3.2 Domain-First Production

This is the minimal production branch for the verified architecture:

`v2rayN client → Iran VLESS/REALITY → reverse-SSH SOCKS → Foreign exit → Internet`

It intentionally keeps only the working production path: Reverse SSH, Customer Gateway, users/quota/expiry, subscriptions, HTTPS, health/security checks, backup/restore, and performance hardening.

## v4.3.2: production hardening

- Fixed custom reverse-SOCKS ports: health checks, watchdog, gateway routing, diagnostics and status now use the paired port instead of assuming `10808`.
- Added strict host/IPv4/port validation to prevent malformed or unsafe service configuration.
- Added SQLite busy timeouts, WAL checkpointing before backups, quota validation, atomic state writes and error propagation during customer rebuilds.
- Added Xray release checksum verification, safer default file permissions, dynamic IPv6 link formatting and a bounded threaded subscription server.

## v4.2.0: root fixes

### 1. Domain-first customer endpoint
Customer VLESS links are no longer forcibly migrated to the Iran IP. If the configured subscription/customer domain resolves directly to the Iran VPS, the manager stores and publishes that domain in VLESS links.

For example:

- Client endpoint: `vp.example.com:24443`
- Subscription: `https://vp.example.com:18080/sub/<token>`
- REALITY SNI: independent camouflage target such as `www.speedtest.net`

The client domain and REALITY SNI are separate concepts.

For non-standard ports such as 24443 and 18080, the DNS record must reach the VPS directly unless the DNS/CDN proxy explicitly supports those ports. With Cloudflare, this normally means **DNS only** for this host.

### 2. External-path REALITY validation
Older builds tested REALITY by connecting from the Iran VPS back to `127.0.0.1:24443`. That is not the same network path as a real customer and could produce a false failure even when v2rayN worked.

v4.2.0 tests the real public endpoint instead:

`Iran diagnostic Xray → reverse SSH SOCKS → Foreign exit → public customer domain:24443 → Iran REALITY inbound → reverse SSH SOCKS → Foreign Internet`

This validates:

- reverse SSH SOCKS
- public DNS/customer domain
- public VLESS port reachability from outside Iran
- REALITY handshake and credentials
- Iran Xray routing
- final foreign egress

The diagnostic client uses the current simplified VLESS outbound schema and Xray-core v26.7.28.

### 3. Pinned Xray runtime
The manager pins Xray-core to `26.7.28` and repairs runtime drift during Gateway upgrade. Server and diagnostic client therefore use the same core generation.

### 4. Stable health source
Tunnel health uses Cloudflare trace via `1.1.1.1`, not `api.ipify.org`, because the latter was observed to time out intermittently even on the foreign VPS itself.

### 5. Subscription SQLite/WAL fix
The subscription service has write access to `/etc/singbox-manager/data` as required by SQLite WAL/SHM operation, preventing empty HTTP responses.

## Existing installation upgrade
Replace only the manager source and run on the Iran server:

1. `Customer Gateway`
2. `Upgrade / repair runtime`

The upgrade preserves:

- user database
- UUIDs
- quota/expiry
- REALITY private/public keys
- Short ID
- HTTPS certificate
- subscription tokens
- reverse-SSH pairing

If the stored VLESS endpoint is an IP but the configured subscription domain resolves directly to the same Iran VPS, v4.2.0 automatically restores the domain as the customer endpoint.

After upgrading, update the subscription once in v2rayN so the node address is refreshed to the domain.

## Fresh setup order

1. Foreign server → Guided Setup → Foreign / Exit Server
2. Copy Pairing Code
3. Iran server → Guided Setup → Iran Gateway
4. Paste Pairing Code
5. Enable safe TCP/BBR tuning when supported
6. Configure Customer Gateway
7. Use a domain that resolves directly to the Iran VPS
8. Configure HTTPS subscription with existing certificate or DNS-01
9. Create a customer
10. Run System Health

## Important
### Client-path diagnostics

During Upgrade / repair, the manager first opens a raw TCP connection to the configured VLESS endpoint through the foreign SOCKS exit. This separates DNS/firewall/Cloudflare reachability failures from REALITY credential failures:

- `EXTERNAL_ENDPOINT_UNREACHABLE`: the foreign server cannot reach the configured host and port. Use a direct DNS-only A record for the Iran VPS, remove an unsupported proxy/CDN path, ensure the port is allowed, and verify any AAAA record is valid.
- `EXTERNAL_ENDPOINT_REACHABLE` followed by `EXTERNAL_REALITY_FAILED`: TCP works, but the REALITY endpoint parameters or server runtime need investigation. The diagnostic output includes the relevant Xray logs.

The manager does not modify nginx, an existing website, or ports 80/443. The default customer ports remain 24443/TCP and 18080/TCP.
