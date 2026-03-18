# Doxxnet VPN Integration

Living document tracking the doxxnet WireGuard VPN provider for OpenClaw.

## Status

**Working.** The `feat/add-doxxnet-vpn-provider` branch implements full doxxnet VPN support.
End-to-end verified: gateway binds to doxxnet tunnel IP, reachable from other doxxnet peers.

## What Is Doxxnet

[Doxx.net](https://doxx.net) provides a WireGuard-based overlay VPN with:

- Per-account tunnel tokens (persistent addresses across reconnects)
- Mesh networking (`firewall_link_all`) for peer-to-peer routing between clients
- Firewall rules per tunnel (inbound TCP allow)
- Custom `.wg` domains with doxxnet-hosted DNS and CA-signed TLS certificates

## Architecture

```
OpenClaw host (VM/server)
  └── openclaw gateway run (bind=doxxnet)
        ├── getOrCreateTunnelConfig()  → fetches WG config from config.doxx.net API
        ├── wg-quick up ~/.openclaw/vpn/doxxnet.conf
        │     → interface utun0 (macOS) / wg0 (Linux)
        │     → IP: <tunnel-ip>/32
        └── HTTP/S server binds to <tunnel-ip>:18789

Remote peer (another doxxnet client)
  └── connects to <tunnel-ip>:18789 (routed via doxxnet mesh)
```

## Configuration

`~/.openclaw/openclaw.json` gateway section with `bind=doxxnet`:

```json
{
  "gateway": {
    "bind": "doxxnet",
    "port": 18789,
    "doxxnet": {
      "mode": "on",
      "scope": "gateway",
      "token": "<your-doxxnet-token>",
      "server": "wireguard.mia.us.doxx.net",
      "domain": "openclaw-<id>.wg",
      "resetOnExit": true
    },
    "tls": {
      "enabled": true,
      "certPath": "~/.openclaw/vpn/tls/doxxnet-cert.pem",
      "keyPath": "~/.openclaw/vpn/tls/doxxnet-key.pem"
    },
    "controlUi": {
      "allowedOrigins": [
        "http://localhost:18789",
        "http://127.0.0.1:18789",
        "https://openclaw-<id>.wg:18789"
      ]
    }
  }
}
```

Run `openclaw onboard` to set this up interactively.

## Files Changed

| File                                        | Purpose                                                     |
| ------------------------------------------- | ----------------------------------------------------------- |
| `src/infra/doxxnet.ts`                      | Doxxnet API client, WG config fetch/write, tunnel lifecycle |
| `src/infra/doxxnet.test.ts`                 | Unit tests                                                  |
| `src/gateway/server-doxxnet.ts`             | Gateway doxxnet startup lifecycle                           |
| `src/gateway/server.impl.ts`                | Pre-bind (bind=doxxnet) + late-startup integration          |
| `src/config/types.gateway.ts`               | Config type: `doxxnet` field, `DoxxnetTrafficScope`         |
| `src/config/zod-schema.ts`                  | Zod schema for `gateway.doxxnet`                            |
| `src/config/gateway-control-ui-origins.ts`  | `"doxxnet"` in non-loopback bind modes                      |
| `src/gateway/startup-control-ui-origins.ts` | Seed HTTPS origin at startup for doxxnet domain             |
| `src/wizard/setup.gateway-config.ts`        | Full wizard flow (token, server, scope, HTTPS, teardown)    |
| `src/wizard/clack-prompter.ts`              | Masked password prompt for token                            |
| `src/wizard/prompts.ts`                     | Password prompt type                                        |

## Doxxnet API

All calls: `POST https://config.doxx.net/v1/` (form-encoded).

| Params                                                                                                                     | Description                                       |
| -------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `auth=1&token=<tok>`                                                                                                       | Verify token validity                             |
| `servers=1`                                                                                                                | List available WireGuard servers                  |
| `create_tunnel=1&token=<tok>&name=<name>&server=<server_name>&type=wireguard`                                              | Create tunnel, returns `tunnel_token`             |
| `wireguard=1&token=<tok>&tunnel_token=<tt>`                                                                                | Get WG config (may need ~60s after create_tunnel) |
| `firewall_link_all_toggle=1&token=<tok>&enabled=1`                                                                         | Enable mesh networking                            |
| `firewall_rule_add=1&token=<tok>&tunnel_token=<tt>&protocol=TCP&src_ip=0.0.0.0/0&src_port=ALL&dst_ip=<ip>&dst_port=<port>` | Add inbound firewall rule                         |
| `create_domain=1&token=<tok>&domain=<domain>`                                                                              | Register `.wg` domain                             |
| `create_dns_record=1&token=<tok>&domain=<d>&name=<d>&type=A&content=<ip>&ttl=300`                                          | Set A record                                      |
| `sign_certificate=1&token=<tok>&domain=<d>&csr=<pem>`                                                                      | Sign CSR with doxxnet CA                          |

**Important API notes:**

- `create_tunnel` requires `type=wireguard` (not documented in some references but required)
- `wireguard=1` requires both `token` AND `tunnel_token` (not just `token`)
- After `create_tunnel`, the tunnel takes ~60s to provision before `wireguard=1` returns config
- The `tunnel_token` is persistent — save it to disk and reuse it to avoid creating new tunnels

## Network Notes

- `config.doxx.net` returns IPv4 + IPv6 addresses. IPv6 may be unreachable in some VM/NAT setups (TLS data drops even when TCP connects). Force IPv4 via undici `connect: { family: 4 }`.
- Critical API calls (WG config) use a 60s timeout with 2 retries.
- Optional API calls (mesh, firewall, DNS) use a 10s timeout with no retries — they are non-fatal and should not block gateway startup.
- The WG config is cached at `~/.openclaw/vpn/doxxnet.conf` after onboarding. Gateway startup uses this cached file and skips the API round-trip when the file exists.

## Traffic Scopes

| Scope     | AllowedIPs in WG config        | Effect                                       |
| --------- | ------------------------------ | -------------------------------------------- |
| `gateway` | Default from API (subnet only) | Only doxxnet mesh traffic routes through VPN |
| `all`     | `0.0.0.0/0, ::/0`              | All traffic routes through doxxnet           |

## TLS

During onboarding (`openclaw onboard`):

1. `registerDoxxnetDomain(token, "openclaw-<id>.wg")` — reserves domain
2. EC key + CSR generated locally
3. `doxxnetSignCertificate(token, domain, csr)` — CSR signed by doxxnet CA
4. Cert + key written to `~/.openclaw/vpn/tls/doxxnet-{cert,key}.pem`
5. Config saved with `gateway.tls.enabled=true`

The `.wg` domain resolves via doxxnet's authoritative DNS. Peers must be connected to doxxnet DNS to resolve it.

## Verification

From any peer on the doxxnet mesh:

```bash
# Ping the tunnel IP
ping <tunnel-ip>

# HTTPS via tunnel IP
curl -sk https://<tunnel-ip>:18789/

# HTTPS via .wg domain (requires doxxnet DNS)
curl -sk https://openclaw-<id>.wg:18789/
```

On the gateway host:

```bash
# WireGuard tunnel status
sudo wg show

# Gateway logs
tail -f /tmp/openclaw/openclaw-$(date +%Y-%m-%d).log
```
