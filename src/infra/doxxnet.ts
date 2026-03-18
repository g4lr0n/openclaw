import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
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

/** Path to the stored doxxnet tunnel token file. */
export function getDoxxnetTunnelTokenPath(env: NodeJS.ProcessEnv = process.env): string {
  return path.join(resolveStateDir(env), "vpn", "doxxnet-tunnel-token.txt");
}

/** Persist the tunnel token for reuse across gateway restarts. */
async function saveTunnelToken(
  tunnelToken: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<void> {
  const p = getDoxxnetTunnelTokenPath(env);
  await fs.mkdir(path.dirname(p), { recursive: true });
  await fs.writeFile(p, tunnelToken, { encoding: "utf8", mode: 0o600 });
}

/** Load a previously saved tunnel token, or return null. */
async function loadTunnelToken(env: NodeJS.ProcessEnv = process.env): Promise<string | null> {
  try {
    return (await fs.readFile(getDoxxnetTunnelTokenPath(env), "utf8")).trim() || null;
  } catch {
    return null;
  }
}

/**
 * Convert a doxxnet JSON config object to a WireGuard .conf string.
 * Handles both the legacy string format and the current structured JSON format.
 */
export function jsonConfigToWgConf(config: Record<string, unknown>): string | null {
  // Legacy: API returned a flat string
  if (typeof config.config === "string") {
    const s = (config as { config: string }).config;
    if (s.includes("[Interface]")) {
      return s;
    }
  }
  // Current: API returns structured { interface: {...}, peer: {...} }
  const iface = config.interface as Record<string, string> | undefined;
  const peer = config.peer as Record<string, string | number> | undefined;
  if (!iface || !peer) {
    return null;
  }
  const lines: string[] = ["[Interface]"];
  if (iface.private_key) {
    lines.push(`PrivateKey = ${iface.private_key}`);
  }
  if (iface.address) {
    lines.push(`Address = ${iface.address}`);
  }
  if (iface.dns) {
    lines.push(`DNS = ${iface.dns}`);
  }
  lines.push("", "[Peer]");
  if (peer.public_key) {
    lines.push(`PublicKey = ${peer.public_key}`);
  }
  if (peer.allowed_ips) {
    lines.push(`AllowedIPs = ${peer.allowed_ips}`);
  }
  if (peer.endpoint) {
    lines.push(`Endpoint = ${peer.endpoint}`);
  }
  if (peer.persistent_keepalive) {
    lines.push(`PersistentKeepalive = ${peer.persistent_keepalive}`);
  }
  return lines.join("\n");
}

/**
 * Fetch WireGuard config via `wireguard=1&token=$TOKEN`.
 * The API returns the existing tunnel config for the account; returns null if no tunnel exists
 * or on any error.
 */
async function fetchWireguardConfig(token: string): Promise<string | null> {
  try {
    const result = await doxxnetPost({ wireguard: "1", token });
    const r = result as Record<string, unknown>;
    if (r.status !== "success") {
      return null;
    }
    // API may return a nested config object or a legacy flat string
    const cfg =
      typeof r.config === "object" && r.config !== null
        ? jsonConfigToWgConf(r.config as Record<string, unknown>)
        : typeof r.config === "string" && r.config.includes("[Interface]")
          ? r.config
          : null;
    return cfg;
  } catch {
    return null;
  }
}

/**
 * Get WireGuard config for an existing tunnel, or create one and return the config.
 *
 * Flow (per SKILL.md):
 *  1. `wireguard=1&token` — returns config if a tunnel already exists.
 *  2. `create_tunnel=1&token&name=openclaw&server=<serverName>` — create a tunnel.
 *  3. `wireguard=1&token` again — retrieve config for the newly created tunnel.
 *
 * The `tunnel_token` returned by `create_tunnel` is persisted to disk for use in
 * firewall rule calls; it is NOT used when fetching the WireGuard config.
 */
export async function getOrCreateTunnelConfig(
  token: string,
  serverName: string,
  env: NodeJS.ProcessEnv = process.env,
): Promise<string> {
  // Step 1: try to get existing tunnel config
  const existing = await fetchWireguardConfig(token);
  if (existing) {
    return existing;
  }

  // Step 2: no existing tunnel — create one
  const created = await doxxnetPost({
    create_tunnel: "1",
    token,
    name: "openclaw",
    server: serverName,
  });
  assertApiSuccess(created, "Failed to create doxxnet tunnel");

  // Persist tunnel_token for subsequent firewall rule calls
  const tunnelToken =
    typeof created.tunnel_token === "string"
      ? (created as { tunnel_token: string }).tunnel_token
      : null;
  if (tunnelToken) {
    await saveTunnelToken(tunnelToken, env);
  }

  // Step 3: retrieve config for the newly created tunnel
  const conf = await fetchWireguardConfig(token);
  if (!conf) {
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
  try {
    await runExec(bin, ["up", confPath], { timeoutMs: 30_000 });
  } catch (err) {
    // On macOS wg-quick maps the config name to a utunN interface. If the
    // interface already exists (e.g. gateway restarted while tunnel is still
    // up), wg-quick exits non-zero with "already exists as `utunN'". Treat
    // this as idempotent success so CIDR/IP detection still runs.
    const msg = err instanceof Error ? err.message : String(err);
    if (!msg.includes("already exists")) {
      throw err;
    }
  }
  const conf = await fs.readFile(confPath, "utf8");
  const cidr = parseWgAddressCidr(conf);
  if (cidr) {
    setActiveDoxxnetCidr(cidr);
  }
  const ip = parseWgIp(conf) ?? "";
  const interfaceName = path.basename(confPath, ".conf");
  return { interfaceName, interfaceIp: ip };
}

/** Expose the stored tunnel token for firewall rule creation. */
export async function loadStoredDoxxnetTunnelToken(
  env: NodeJS.ProcessEnv = process.env,
): Promise<string | null> {
  return loadTunnelToken(env);
}

/** Enable peer-to-peer mesh networking between all doxxnet tunnels on this account. */
export async function enableDoxxnetMesh(token: string): Promise<void> {
  const result = await doxxnetPost({ firewall_link_all_toggle: "1", token, enabled: "1" });
  assertApiSuccess(result, "Failed to enable doxxnet mesh networking");
}

/** Add a firewall rule allowing inbound TCP on `port` to a tunnel's IP. */
export async function addDoxxnetFirewallRule(params: {
  token: string;
  tunnelToken: string;
  dstIp: string;
  port: number;
}): Promise<void> {
  const result = await doxxnetPost({
    firewall_rule_add: "1",
    token: params.token,
    tunnel_token: params.tunnelToken,
    protocol: "TCP",
    src_ip: "0.0.0.0/0",
    src_port: "ALL",
    dst_ip: params.dstIp,
    dst_port: String(params.port),
  });
  assertApiSuccess(result, "Failed to add doxxnet firewall rule");
}

/** Register a doxxnet domain (e.g. "openclaw-xxxx.wg"). Idempotent — rethrows only on unexpected errors. */
export async function registerDoxxnetDomain(token: string, domain: string): Promise<void> {
  const result = await doxxnetPost({ create_domain: "1", token, domain });
  assertApiSuccess(result, `Failed to register doxxnet domain ${domain}`);
}

/** Create/update an A record pointing a doxxnet domain to an IP address. */
export async function createDoxxnetDnsRecord(
  token: string,
  domain: string,
  ip: string,
): Promise<void> {
  const result = await doxxnetPost({
    create_dns_record: "1",
    token,
    domain,
    name: domain,
    type: "A",
    content: ip,
    ttl: "300",
  });
  assertApiSuccess(result, `Failed to create DNS record for ${domain}`);
}

const execFileAsync = promisify(execFile);

/**
 * Sign a CSR with the doxxnet CA. Returns the signed PEM certificate.
 * Handles both raw PEM responses and JSON `{ status, cert }` responses.
 */
async function doxxnetSignCertificate(token: string, domain: string, csr: string): Promise<string> {
  const response = await fetch(DOXXNET_CONFIG_API, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ sign_certificate: "1", token, domain, csr }).toString(),
  });
  if (!response.ok) {
    throw new Error(
      `doxxnet sign_certificate error: HTTP ${response.status} ${response.statusText}`,
    );
  }
  const text = await response.text();
  // API may return raw PEM directly
  if (text.trimStart().startsWith("-----BEGIN")) {
    return text.trim();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new Error(`doxxnet sign_certificate returned unexpected body: ${text.slice(0, 200)}`);
  }
  const r = parsed as Record<string, unknown>;
  if (r.status !== "success") {
    const msg = typeof r.message === "string" ? r.message : JSON.stringify(r);
    throw new Error(`doxxnet sign_certificate failed: ${msg}`);
  }
  const cert = r.cert ?? r.certificate ?? r.config;
  if (typeof cert !== "string") {
    throw new Error(`doxxnet sign_certificate response missing cert field: ${JSON.stringify(r)}`);
  }
  return cert.trim();
}

/**
 * Generate an EC private key + CSR, sign it with the doxxnet CA, and write
 * the cert + key to disk. The domain must already be registered.
 */
export async function setupDoxxnetDomainCert(params: {
  token: string;
  domain: string;
  certPath: string;
  keyPath: string;
}): Promise<void> {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "doxxnet-cert-"));
  try {
    const tmpKey = path.join(tmpDir, "key.pem");
    const tmpCsr = path.join(tmpDir, "csr.pem");
    // Generate EC private key (prime256v1)
    await execFileAsync("openssl", [
      "ecparam",
      "-name",
      "prime256v1",
      "-genkey",
      "-noout",
      "-out",
      tmpKey,
    ]);
    // Generate CSR
    await execFileAsync("openssl", [
      "req",
      "-new",
      "-key",
      tmpKey,
      "-out",
      tmpCsr,
      "-subj",
      `/CN=${params.domain}`,
    ]);
    const csr = await fs.readFile(tmpCsr, "utf8");
    const cert = await doxxnetSignCertificate(params.token, params.domain, csr);
    // Write key and cert
    await fs.mkdir(path.dirname(params.keyPath), { recursive: true });
    await fs.mkdir(path.dirname(params.certPath), { recursive: true });
    const keyPem = await fs.readFile(tmpKey, "utf8");
    await fs.writeFile(params.keyPath, keyPem, { mode: 0o600 });
    await fs.chmod(params.keyPath, 0o600);
    await fs.writeFile(params.certPath, cert, { mode: 0o644 });
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
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
 * On Linux, `wg show <name>` works directly.
 * On macOS, wg-quick maps the config name to a utunN interface via
 * `/var/run/wireguard/<name>.name` (readable by root only). We fall back to
 * `wg show all` and check whether any interface output is present, covering
 * the case where the `.name` file is unreadable by the current process.
 */
export async function checkDoxxnetInterface(name: string): Promise<boolean> {
  // Try direct name first (works on Linux and macOS when root).
  try {
    const { stdout } = await runExec("wg", ["show", name], { timeoutMs: 5_000 });
    if (stdout.trim().length > 0) {
      return true;
    }
  } catch {
    // Fall through to alternative check.
  }
  // On macOS the interface may be registered as utunN; `wg show all` lists all
  // active WireGuard interfaces regardless of name resolution.
  try {
    const { stdout } = await runExec("wg", ["show", "all"], { timeoutMs: 5_000 });
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}
