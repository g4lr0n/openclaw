import { existsSync } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { resolveStateDir } from "../config/config.js";
import type { DoxxnetTrafficScope } from "../config/types.gateway.js";
import { runExec } from "../process/exec.js";
import { isIpInCidr } from "../shared/net/ip.js";

const DOXXNET_CONFIG_API = "https://config.doxx.net/v1/";

export type DoxxnetServer = {
  /** server_name field from API — pass to create_tunnel */
  serverName: string;
  /** Human-readable location, e.g. "Miami, FL" */
  location: string;
  /** Short description, e.g. "US Southeast" */
  description: string;
  bestFor?: string;
  continent?: string;
};

/** Path to the doxxnet WireGuard config file. */
export function getDoxxnetWgConfPath(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(resolveStateDir(env), "vpn", "doxxnet.conf");
}

// Module-level cache: CIDR assigned to the WireGuard interface (set when tunnel comes up).
let activeDoxxnetCidr: string | null = null;

/** Store the CIDR extracted from the WireGuard config after tunnel activation. */
export function setActiveDoxxnetCidr(cidr: string | null): void {
  activeDoxxnetCidr = cidr;
}

/** Returns true if `address` is in the active doxxnet WireGuard subnet. */
export function isDoxxnetIPv4(address: string): boolean {
  if (!activeDoxxnetCidr) {
    return false;
  }
  return isIpInCidr(address, activeDoxxnetCidr);
}

/**
 * Returns the WireGuard interface IPv4 assigned to this machine.
 * Only available after the tunnel is up and `setActiveDoxxnetCidr` has been called.
 */
export function pickPrimaryDoxxnetIPv4(): string | undefined {
  if (!activeDoxxnetCidr) {
    return undefined;
  }
  const ifaces = os.networkInterfaces();
  for (const entries of Object.values(ifaces)) {
    if (!entries) {
      continue;
    }
    for (const e of entries) {
      if (!e || e.internal || e.family !== "IPv4") {
        continue;
      }
      if (isIpInCidr(e.address, activeDoxxnetCidr)) {
        return e.address;
      }
    }
  }
  return undefined;
}

/** Parse the `Address = <ip/cidr>` line from a WireGuard config string. Returns CIDR string. */
export function parseWgAddressCidr(conf: string): string | null {
  const match = conf.match(/^\s*Address\s*=\s*([^\n\r,]+)/m);
  if (!match) {
    return null;
  }
  return match[1].trim() || null;
}

/** Parse just the IP (no prefix) from an `Address = <ip/cidr>` line. */
function parseWgIp(conf: string): string | null {
  const cidr = parseWgAddressCidr(conf);
  if (!cidr) {
    return null;
  }
  return cidr.split("/")[0]?.trim() ?? null;
}

/** Locate `wg-quick` binary via PATH and known install paths. */
export async function findWgQuickBinary(): Promise<string | null> {
  // Try PATH first
  try {
    const { stdout } = await runExec("which", ["wg-quick"], { timeoutMs: 3000 });
    const found = stdout.trim();
    if (found && existsSync(found)) {
      return found;
    }
  } catch {
    // not in PATH
  }
  // Known install locations
  for (const p of [
    "/usr/local/bin/wg-quick",
    "/opt/homebrew/bin/wg-quick",
    "/usr/bin/wg-quick",
    "/usr/sbin/wg-quick",
  ]) {
    if (existsSync(p)) {
      return p;
    }
  }
  return null;
}

async function doxxnetPost(params: Record<string, string>): Promise<unknown> {
  const body = new URLSearchParams(params).toString();
  const response = await fetch(DOXXNET_CONFIG_API, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!response.ok) {
    throw new Error(`doxxnet API error: HTTP ${response.status} ${response.statusText}`);
  }
  return await response.json();
}

function assertApiSuccess(
  result: unknown,
  context: string,
): asserts result is Record<string, unknown> {
  if (typeof result !== "object" || result === null) {
    throw new Error(`${context}: unexpected response format`);
  }
  const r = result as Record<string, unknown>;
  if (r.status !== "success") {
    const msg = typeof r.message === "string" ? r.message : JSON.stringify(r);
    throw new Error(`${context}: ${msg}`);
  }
}

/** Verify the doxxnet token is valid. Throws with the API error message on failure. */
export async function verifyDoxxnetToken(token: string): Promise<void> {
  const result = await doxxnetPost({ auth: "1", token });
  assertApiSuccess(result, "Token verification failed");
}

/** List available doxxnet VPN servers (no auth required). */
export async function listDoxxnetServers(): Promise<DoxxnetServer[]> {
  const result = await doxxnetPost({ servers: "1" });
  // The `servers` endpoint returns an array directly
  const arr = Array.isArray(result) ? result : (result as Record<string, unknown>)?.servers;
  if (!Array.isArray(arr)) {
    throw new Error("doxxnet servers API returned unexpected format");
  }
  return arr.map((s) => {
    const server = s as Record<string, string>;
    return {
      serverName: server.server_name ?? "",
      location: server.location ?? "",
      description: server.description ?? "",
      bestFor: server.best_for,
      continent: server.continent,
    };
  });
}

/**
 * Get WireGuard config for an existing tunnel, or create one and return the config.
 * Idempotent: calls `wireguard=1` first; only calls `create_tunnel=1` if no config exists.
 */
export async function getOrCreateTunnelConfig(token: string, serverName: string): Promise<string> {
  // Try to get existing tunnel config
  try {
    const existing = await doxxnetPost({ wireguard: "1", token });
    const r = existing as Record<string, unknown>;
    if (r.status === "success") {
      const conf =
        typeof r.config === "string"
          ? r.config
          : typeof r.wireguard_config === "string"
            ? r.wireguard_config
            : null;
      if (conf && conf.includes("[Interface]")) {
        return conf;
      }
    }
  } catch {
    // No existing tunnel or API error — proceed to create
  }

  // Create tunnel
  const created = await doxxnetPost({
    create_tunnel: "1",
    token,
    name: "openclaw",
    server: serverName,
  });
  assertApiSuccess(created, "Failed to create doxxnet tunnel");

  // Fetch config after creation
  const configResult = await doxxnetPost({ wireguard: "1", token });
  const r2 = configResult as Record<string, unknown>;
  const conf =
    r2.status === "success"
      ? typeof r2.config === "string"
        ? r2.config
        : typeof r2.wireguard_config === "string"
          ? r2.wireguard_config
          : null
      : null;
  if (!conf || !conf.includes("[Interface]")) {
    throw new Error("Failed to retrieve WireGuard config after tunnel creation");
  }
  return conf;
}

function patchAllowedIps(conf: string, scope: DoxxnetTrafficScope): string {
  if (scope === "all") {
    // Route all traffic through doxxnet
    return conf.replace(/^\s*AllowedIPs\s*=\s*.+$/m, "AllowedIPs = 0.0.0.0/0, ::/0");
  }
  // For "gateway" and "web": keep the default subnet-only routing from API
  return conf;
}

/**
 * Write the doxxnet WireGuard config to `~/.openclaw/vpn/doxxnet.conf`.
 * Patches AllowedIPs based on the requested traffic scope.
 * Sets file permissions to 0o600.
 * Returns the path written.
 */
export async function writeDoxxnetWgConfig(
  conf: string,
  scope: DoxxnetTrafficScope,
  env: NodeJS.ProcessEnv = process.env,
): Promise<string> {
  const confPath = getDoxxnetWgConfPath(env);
  const dir = path.dirname(confPath);
  await fs.mkdir(dir, { recursive: true });
  const patched = patchAllowedIps(conf, scope);
  await fs.writeFile(confPath, patched, { encoding: "utf8", mode: 0o600 });
  // Ensure mode is exactly 600 (writeFile mode may be masked by umask)
  await fs.chmod(confPath, 0o600);
  return confPath;
}

/**
 * Bring up the WireGuard tunnel via `wg-quick up`.
 * Sets the active CIDR so `pickPrimaryDoxxnetIPv4` can find the interface IP.
 */
export async function wgQuickUp(
  confPath: string,
  bin: string,
): Promise<{ interfaceName: string; interfaceIp: string }> {
  await runExec(bin, ["up", confPath], { timeoutMs: 30_000 });
  const conf = await fs.readFile(confPath, "utf8");
  const cidr = parseWgAddressCidr(conf);
  if (cidr) {
    setActiveDoxxnetCidr(cidr);
  }
  const ip = parseWgIp(conf) ?? "";
  const interfaceName = path.basename(confPath, ".conf");
  return { interfaceName, interfaceIp: ip };
}

/** Bring down the WireGuard tunnel via `wg-quick down`. */
export async function wgQuickDown(confPath: string, bin: string): Promise<void> {
  await runExec(bin, ["down", confPath], { timeoutMs: 30_000 }).catch(() => {
    // Ignore errors — tunnel may already be down
  });
  setActiveDoxxnetCidr(null);
}

/**
 * Check whether a WireGuard interface is currently active.
 * Returns true if `wg show <name>` succeeds and shows the interface.
 */
export async function checkDoxxnetInterface(name: string): Promise<boolean> {
  try {
    const { stdout } = await runExec("wg", ["show", name], { timeoutMs: 5_000 });
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}
