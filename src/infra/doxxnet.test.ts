import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  getOrCreateTunnelConfig,
  listDoxxnetServers,
  parseWgAddressCidr,
  verifyDoxxnetToken,
  writeDoxxnetWgConfig,
} from "./doxxnet.js";

const { runExecMock } = vi.hoisted(() => ({ runExecMock: vi.fn() }));

vi.mock("../process/exec.js", () => ({
  runExec: (...args: unknown[]) => runExecMock(...args),
}));

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal("fetch", mockFetch);
});

afterEach(() => {
  vi.clearAllMocks();
});

function mockApiResponse(body: unknown, ok = true, status = 200) {
  mockFetch.mockResolvedValueOnce({
    ok,
    status,
    statusText: ok ? "OK" : "Bad Request",
    json: async () => body,
  });
}

describe("verifyDoxxnetToken", () => {
  it("resolves on success status", async () => {
    mockApiResponse({ status: "success" });
    await expect(verifyDoxxnetToken("tok123")).resolves.toBeUndefined();
  });

  it("throws with API message when status is error (HTTP 200)", async () => {
    mockApiResponse({ status: "error", message: "invalid token" });
    await expect(verifyDoxxnetToken("bad-token")).rejects.toThrow("invalid token");
  });
});

describe("listDoxxnetServers", () => {
  it("parses server array from response", async () => {
    mockApiResponse([
      {
        server_name: "wireguard.mia.us.doxx.net",
        location: "Miami, FL",
        description: "US Southeast",
        best_for: "US East Coast",
        continent: "NA",
      },
      {
        server_name: "wireguard.fra.eu.doxx.net",
        location: "Frankfurt, DE",
        description: "EU Central",
        best_for: "Europe",
        continent: "EU",
      },
    ]);
    const servers = await listDoxxnetServers();
    expect(servers).toHaveLength(2);
    expect(servers[0]).toMatchObject({
      serverName: "wireguard.mia.us.doxx.net",
      location: "Miami, FL",
      description: "US Southeast",
    });
    expect(servers[1]).toMatchObject({
      serverName: "wireguard.fra.eu.doxx.net",
      location: "Frankfurt, DE",
    });
  });
});

describe("getOrCreateTunnelConfig", () => {
  const WG_CONF = "[Interface]\nAddress = 10.8.0.1/24\n[Peer]\nPublicKey = abc";
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "doxxnet-tunnel-test-"));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("returns existing config via stored tunnel_token without calling create_tunnel", async () => {
    // Pre-write a stored tunnel token
    const vpnDir = path.join(tmpDir, "vpn");
    await fs.mkdir(vpnDir, { recursive: true });
    await fs.writeFile(path.join(vpnDir, "doxxnet-tunnel-token.txt"), "stored-tunnel-tok");

    // wireguard=1 with tunnel_token returns config
    mockApiResponse({ status: "success", config: WG_CONF });

    const env = { OPENCLAW_STATE_DIR: tmpDir } as unknown as NodeJS.ProcessEnv;
    const conf = await getOrCreateTunnelConfig("tok", "wireguard.mia.us.doxx.net", env);
    expect(conf).toBe(WG_CONF);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const call = mockFetch.mock.calls[0];
    const body = new URLSearchParams(call[1].body as string);
    expect(body.get("wireguard")).toBe("1");
    expect(body.get("tunnel_token")).toBe("stored-tunnel-tok");
    expect(body.has("create_tunnel")).toBe(false);
  });

  it("calls create_tunnel (with type=wireguard) then wireguard when no stored token", async () => {
    // create_tunnel=1 returns success + tunnel_token
    mockApiResponse({ status: "success", tunnel_token: "new-tunnel-tok" });
    // wireguard=1 returns config on first retry
    mockApiResponse({ status: "success", config: WG_CONF });

    const env = { OPENCLAW_STATE_DIR: tmpDir } as unknown as NodeJS.ProcessEnv;
    // Pass [0] delay to skip real provisioning wait in tests
    const conf = await getOrCreateTunnelConfig("tok", "wireguard.mia.us.doxx.net", env, [0]);
    expect(conf).toBe(WG_CONF);
    expect(mockFetch).toHaveBeenCalledTimes(2);
    const createCall = mockFetch.mock.calls[0];
    const body = new URLSearchParams(createCall[1].body as string);
    expect(body.get("create_tunnel")).toBe("1");
    expect(body.get("type")).toBe("wireguard"); // required by actual API
    expect(body.get("server")).toBe("wireguard.mia.us.doxx.net");
    // tunnel_token should be persisted to disk
    const saved = await fs.readFile(path.join(tmpDir, "vpn", "doxxnet-tunnel-token.txt"), "utf8");
    expect(saved.trim()).toBe("new-tunnel-tok");
  });

  it("falls through to create_tunnel when stored token returns no config", async () => {
    const vpnDir = path.join(tmpDir, "vpn");
    await fs.mkdir(vpnDir, { recursive: true });
    await fs.writeFile(path.join(vpnDir, "doxxnet-tunnel-token.txt"), "stale-token");

    // wireguard=1 with stale token returns error
    mockApiResponse({ status: "error", message: "invalid tunnel_token" });
    // create_tunnel=1 returns new tunnel_token
    mockApiResponse({ status: "success", tunnel_token: "fresh-token" });
    // wireguard=1 returns config on first retry
    mockApiResponse({ status: "success", config: WG_CONF });

    const env = { OPENCLAW_STATE_DIR: tmpDir } as unknown as NodeJS.ProcessEnv;
    // Pass [0] delay to skip real provisioning wait in tests
    const conf = await getOrCreateTunnelConfig("tok", "wireguard.mia.us.doxx.net", env, [0]);
    expect(conf).toBe(WG_CONF);
    expect(mockFetch).toHaveBeenCalledTimes(3);
  });
});

describe("writeDoxxnetWgConfig", () => {
  let tmpDir: string;

  beforeEach(async () => {
    tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "doxxnet-test-"));
  });

  afterEach(async () => {
    await fs.rm(tmpDir, { recursive: true, force: true });
  });

  it("writes config and patches AllowedIPs for scope=all", async () => {
    const conf =
      "[Interface]\nAddress = 10.8.0.1/24\n[Peer]\nAllowedIPs = 10.8.0.0/24\nEndpoint = host:51820";
    const env = { OPENCLAW_STATE_DIR: tmpDir } as unknown as NodeJS.ProcessEnv;
    const written = await writeDoxxnetWgConfig(conf, "all", env);
    const content = await fs.readFile(written, "utf8");
    expect(content).toContain("AllowedIPs = 0.0.0.0/0, ::/0");
  });

  it("patches AllowedIPs to 10.0.0.0/8 and strips IPv6 for scope=gateway", async () => {
    // The doxxnet API returns AllowedIPs = 0.0.0.0/0 and IPv6 Address/DNS by default.
    // scope=gateway restricts to IPv4 mesh only so curl's IPv6 preference doesn't bypass
    // the tunnel and hit the broken UTM NAT path.
    const conf =
      "[Interface]\nAddress = 10.8.0.1/24, 2602:f5c1:1::1/128\nDNS = 10.10.10.10,fd53::\n[Peer]\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = host:51820";
    const env = { OPENCLAW_STATE_DIR: tmpDir } as unknown as NodeJS.ProcessEnv;
    const written = await writeDoxxnetWgConfig(conf, "gateway", env);
    const content = await fs.readFile(written, "utf8");
    expect(content).toContain("AllowedIPs = 10.0.0.0/8");
    expect(content).not.toContain("::/0");
    expect(content).toContain("Address = 10.8.0.1/24");
    expect(content).not.toContain("2602:f5c1");
    expect(content).toContain("DNS = 10.10.10.10");
    expect(content).not.toContain("fd53::");
  });

  it("sets file mode to 0o600", async () => {
    const conf = "[Interface]\nAddress = 10.8.0.1/24\n[Peer]\nAllowedIPs = 10.8.0.0/24";
    const env = { OPENCLAW_STATE_DIR: tmpDir } as unknown as NodeJS.ProcessEnv;
    const written = await writeDoxxnetWgConfig(conf, "gateway", env);
    const stat = await fs.stat(written);
    // Check that only owner has read/write (mode & 0o777 === 0o600)
    expect(stat.mode & 0o777).toBe(0o600);
  });
});

describe("parseWgAddressCidr", () => {
  it("extracts CIDR from WireGuard config", () => {
    const conf = "[Interface]\nAddress = 10.8.0.1/24\nPrivateKey = abc";
    expect(parseWgAddressCidr(conf)).toBe("10.8.0.1/24");
  });

  it("returns null when Address line is missing", () => {
    expect(parseWgAddressCidr("[Interface]\nPrivateKey = abc")).toBeNull();
  });
});

describe("findWgQuickBinary", () => {
  it("returns null or a path depending on host", async () => {
    // findWgQuickBinary checks known paths on disk after runExec; just verify no throw
    const { findWgQuickBinary } = await import("./doxxnet.js");
    const result = await findWgQuickBinary();
    expect(result === null || typeof result === "string").toBe(true);
  });
});

describe("wgQuickUp", () => {
  it("throws descriptive error when wg-quick fails with unrecognized error", async () => {
    vi.resetModules();
    runExecMock.mockRejectedValue(new Error("Operation not permitted"));
    const { wgQuickUp: wgUp } = await import("./doxxnet.js");
    await expect(wgUp("/tmp/test.conf", "/usr/bin/wg-quick")).rejects.toThrow(
      "Operation not permitted",
    );
  });

  it("treats 'already exists as utunN' as idempotent success (macOS AC-4)", async () => {
    // wg-quick up exits non-zero with "already exists" when tunnel is already up on macOS
    vi.resetModules();
    runExecMock.mockRejectedValue(
      new Error("Command failed: wg-quick up /tmp/doxxnet.conf\nalready exists as `utun0'"),
    );
    const { wgQuickUp: wgUp } = await import("./doxxnet.js");
    // Should not throw; reads the conf from disk to extract CIDR
    const tmpConf = path.join(os.tmpdir(), "doxxnet-idempotent.conf");
    await fs.writeFile(tmpConf, "[Interface]\nAddress = 10.8.0.1/24\n[Peer]\nPublicKey = abc");
    try {
      const result = await wgUp(tmpConf, "/opt/homebrew/bin/wg-quick");
      expect(result.interfaceIp).toBe("10.8.0.1");
    } finally {
      await fs.rm(tmpConf, { force: true });
    }
  });
});
