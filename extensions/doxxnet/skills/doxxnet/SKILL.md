---
name: doxxnet
description: Manage doxxnet VPN tunnels, devices, firewall rules, DNS blocking, and account settings. Uses DOXXNET_TOKEN for auth. Call this skill when the user asks about doxxnet tunnels, VPN status, network routing, or doxxnet account management.
---

# doxxnet VPN Management

Use the doxxnet Config API (`POST https://config.doxx.net/v1/`) for all operations.
Auth token: read from `DOXXNET_TOKEN` environment variable.

## API reference

**Base URL**: `https://config.doxx.net/v1/`
**Method**: POST, `application/x-www-form-urlencoded`
**Always check `status` field** — HTTP 200 does not mean success.

```
{"status": "success", ...}
{"status": "error", "message": "..."}
```

Regional failover subdomains: `config-us-east`, `config-us-west`, `config-eu-central`.

## Key endpoints

| Action               | Parameters                                                        |
| -------------------- | ----------------------------------------------------------------- |
| Validate token       | `auth=1&token=$TOKEN`                                             |
| List servers         | `servers=1` (no auth)                                             |
| List tunnels         | `list_tunnels=1&token=$TOKEN`                                     |
| Get WireGuard config | `wireguard=1&token=$TOKEN`                                        |
| Create tunnel        | `create_tunnel=1&token=$TOKEN&name=openclaw&server=<server_name>` |
| Delete tunnel        | `delete_tunnel=1&token=$TOKEN`                                    |

## Tunnel management

- **Idempotent creation**: call `wireguard=1` first; only call `create_tunnel=1` if no config exists.
- **server_name**: use the `server_name` field from `servers=1` response when creating tunnels.
- **Local activation**: once WireGuard config is obtained, run `wg-quick up ~/.openclaw/vpn/doxxnet.conf` to activate.
- **Local deactivation**: run `wg-quick down ~/.openclaw/vpn/doxxnet.conf`.

## Traffic scope (AllowedIPs)

| Scope                 | AllowedIPs to use                 |
| --------------------- | --------------------------------- |
| All traffic           | `0.0.0.0/0, ::/0`                 |
| Gateway / subnet only | Keep API default (doxxnet subnet) |

## Server selection

`servers=1` response fields per server:

- `server_name` — pass to `create_tunnel` as `server=`
- `location` — show to user (e.g. "Miami, FL")
- `description` — show to user (e.g. "US Southeast")
- `best_for` — optional hint
- `continent` — optional region filter

## Common workflows

**Check tunnel status**:

1. Call `list_tunnels=1` to see active tunnels
2. Run `wg show doxxnet` locally to verify interface

**Create and activate a new tunnel**:

1. `servers=1` → pick server
2. `create_tunnel=1&name=openclaw&server=<server_name>`
3. `wireguard=1` → write config to `~/.openclaw/vpn/doxxnet.conf` (chmod 600)
4. `wg-quick up ~/.openclaw/vpn/doxxnet.conf`

**Gateway integration**:

- Set `gateway.doxxnet.mode=on` and `gateway.doxxnet.scope=gateway|all|web`
- scope=gateway: bind=doxxnet; remote clients reach gateway via WireGuard IP
- scope=all: route all outbound traffic through doxxnet
- scope=web: agent web requests route via doxxnet

Get your token at https://a0x13.doxx.net
