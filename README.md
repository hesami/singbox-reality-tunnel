# Iran ↔ Foreign Gateway Manager — v4.1.0 Known-Good Data Plane

This release freezes the customer data-plane to the exact Xray-core version that was previously verified working in this project: **Xray-core v26.7.28**.

## Why v4.1.0 exists

The control-plane changes (Guided Setup / Pairing Code / hardening) were not supposed to change customer VLESS+REALITY behavior, but later builds allowed the locally installed Xray binary to drift. The affected server ended up on Xray 26.3.27 while generated configuration had fields from newer Xray schemas. That created two misleading failure modes:

- VLESS could start with a user schema that did not match the installed runtime, yielding `invalid request user id` even for the exact configured UUID.
- REALITY client diagnostics used the newer client-side public-key field while an older runtime could interpret the profile differently, so the diagnostic could fail before VLESS and show no fresh server access entry.

v4.1.0 removes that version/schema ambiguity entirely.

## Data-plane policy

- Xray runtime is pinned to **26.7.28**.
- Setup / Upgrade checks the installed Xray version every time.
- Any other Xray version is atomically replaced by 26.7.28 before rebuilding the gateway.
- The generated server profile uses the same VLESS+REALITY shape as the previously working pre-Pairing build:
  - VLESS inbound `settings.users`
  - RAW transport (`method: raw`)
  - REALITY target / SNI / X25519 keys / short ID
  - no extra experimental REALITY options added by the manager
- The internal diagnostic client uses the canonical `vnext/users` VLESS outbound form and the v26.7.28 REALITY `password` public-key field.
- Upgrade is not reported successful if the end-to-end local customer path test fails.

## Retained architecture

- Pairing Code stays enabled.
- Reverse SSH remains Turkey/foreign → Iran.
- SOCKS remains bound to `127.0.0.1:10808` on Iran.
- Customer traffic path remains:

  `v2rayN → VLESS+REALITY → Iran → reverse SSH SOCKS → foreign exit → Internet`

- Per-user quota, expiry, traffic accounting and subscriptions remain enabled.
- Subscription HTTPS/WAL fix remains included.
- Stable Cloudflare-based tunnel health probing remains included.
- Kill-switch, dedicated tunnel user/sshd, firewall restriction, key rotation, BBR/TCP tuning and backups remain included.
- nginx, the existing website and ports 80/443 are not modified.

## Recommended repair for an existing v4 install

Replace the manager source with v4.1.0, then on the Iran server run:

```bash
bash manager.sh
```

Choose:

`Customer Gateway → Upgrade / repair runtime`

The manager will preserve users, UUIDs, subscription tokens, REALITY keys, certificate and endpoints, normalize Xray to v26.7.28, rebuild the gateway and run an end-to-end test.

A healthy repair ends with:

```text
VLESS/REALITY → Turkey self-test passed: <foreign-exit-ip>
Runtime upgrade/repair completed and validated end-to-end.
```

If the end-to-end test fails, the command returns failure instead of printing a false success message.

## First installation

1. Run `Guided Setup` on the foreign/exit server.
2. Copy the Pairing Code.
3. Run `Guided Setup` on the Iran server and paste the Pairing Code.
4. Configure Customer Gateway.
5. Create customers from Customer Management.
6. Add each subscription URL to v2rayN.

For v2rayN, use a current Xray-core. The server runtime itself is fixed by the manager at v26.7.28 so future upstream releases cannot silently change the server behavior.
