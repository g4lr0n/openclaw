import fs from "node:fs/promises";
import type { DoxxnetTrafficScope, GatewayDoxxnetMode } from "../config/types.gateway.js";
import {
  addDoxxnetFirewallRule,
  createDoxxnetDnsRecord,
  enableDoxxnetMesh,
  findWgQuickBinary,
  getDoxxnetWgConfPath,
  getOrCreateTunnelConfig,
  loadStoredDoxxnetTunnelToken,
  pickPrimaryDoxxnetIPv4,
  wgQuickDown,
  wgQuickUp,
  writeDoxxnetWgConfig,
} from "../infra/doxxnet.js";

const WG_QUICK_INSTALL_HINT =
  "Install wireguard-tools: macOS: `brew install wireguard-tools`, " +
  "Debian/Ubuntu: `apt install wireguard-tools`, " +
  "see https://www.wireguard.com/install/";

/**
 * Bring up the doxxnet WireGuard tunnel and optionally register a teardown callback.
 *
 * Returns a cleanup function (for `resetOnExit`) or null.
 */
export async function startGatewayDoxxnetExposure(params: {
  doxxnetMode: GatewayDoxxnetMode;
  scope: DoxxnetTrafficScope;
  doxxnetToken?: string;
  doxxnetServer?: string;
  doxxnetDomain?: string;
  resetOnExit?: boolean;
  port: number;
  logDoxxnet: { info: (msg: string) => void; warn: (msg: string) => void };
}): Promise<(() => Promise<void>) | null> {
  if (params.doxxnetMode === "off") {
    return null;
  }

  const token = params.doxxnetToken ?? process.env.DOXXNET_TOKEN?.trim();
  if (!token) {
    params.logDoxxnet.warn(
      "doxxnet mode=on but no token found. Set DOXXNET_TOKEN or configure gateway.doxxnet.token.",
    );
    return null;
  }

  const bin = await findWgQuickBinary();
  if (!bin) {
    params.logDoxxnet.warn(`doxxnet: wg-quick not found. ${WG_QUICK_INSTALL_HINT}`);
    return null;
  }

  let confPath!: string;
  try {
    // Use the cached WG config written during onboarding if it exists — this avoids
    // an API round-trip on every gateway restart (especially important when connectivity
    // to config.doxx.net is slow or the host routes through a VPN/NAT that filters TLS).
    const cachedConfPath = getDoxxnetWgConfPath();
    let usedCache = false;
    try {
      await fs.access(cachedConfPath);
      confPath = cachedConfPath;
      usedCache = true;
    } catch {
      // Cache miss — fall through to fetch from API
    }
    if (!usedCache) {
      const serverName = params.doxxnetServer ?? "";
      const wgConf = await getOrCreateTunnelConfig(token, serverName);
      confPath = await writeDoxxnetWgConfig(wgConf, params.scope);
    }
  } catch (err) {
    params.logDoxxnet.warn(
      `doxxnet: failed to get/write WireGuard config: ${err instanceof Error ? err.message : String(err)}`,
    );
    return null;
  }

  // Always call wgQuickUp — it handles "already exists" idempotently and always reads
  // the conf + sets the active CIDR, so pickPrimaryDoxxnetIPv4 works on restarts too.
  try {
    const { interfaceIp, alreadyUp } = await wgQuickUp(confPath, bin);
    const ip = interfaceIp || pickPrimaryDoxxnetIPv4() || "";
    if (alreadyUp) {
      params.logDoxxnet.info(
        `doxxnet: tunnel already up${ip ? ` — interface IP ${ip}` : ""} (scope=${params.scope})`,
      );
    } else if (ip) {
      params.logDoxxnet.info(`doxxnet: tunnel up — interface IP ${ip} (scope=${params.scope})`);
    } else {
      params.logDoxxnet.info(`doxxnet: tunnel up (scope=${params.scope})`);
    }
  } catch (err) {
    params.logDoxxnet.warn(
      `doxxnet: wg-quick up failed: ${err instanceof Error ? err.message : String(err)}`,
    );
    return null;
  }

  // Resolve tunnel IP (used for firewall rules and DNS record).
  const tunnelIp = pickPrimaryDoxxnetIPv4() || "";

  // Enable mesh networking and add a firewall rule for the gateway port.
  // Non-fatal: mesh failure shouldn't block gateway startup.
  try {
    await enableDoxxnetMesh(token);
    if (tunnelIp) {
      const tunnelToken = await loadStoredDoxxnetTunnelToken();
      if (tunnelToken) {
        await addDoxxnetFirewallRule({
          token,
          tunnelToken,
          dstIp: tunnelIp,
          port: params.port,
        });
        params.logDoxxnet.info(
          `doxxnet: mesh networking enabled, firewall rule added for port ${params.port}`,
        );
      }
    }
  } catch (err) {
    params.logDoxxnet.warn(
      `doxxnet: mesh/firewall setup failed (non-fatal): ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  // Update DNS record so the registered domain resolves to the current tunnel IP.
  if (params.doxxnetDomain && tunnelIp) {
    try {
      await createDoxxnetDnsRecord(token, params.doxxnetDomain, tunnelIp);
      params.logDoxxnet.info(`doxxnet: DNS record updated — ${params.doxxnetDomain} → ${tunnelIp}`);
    } catch (err) {
      params.logDoxxnet.warn(
        `doxxnet: DNS update failed (non-fatal): ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  if (!params.resetOnExit) {
    return null;
  }

  return async () => {
    try {
      await wgQuickDown(confPath, bin);
    } catch (err) {
      params.logDoxxnet.warn(
        `doxxnet: wg-quick down failed: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  };
}
