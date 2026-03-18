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

const runExecMock = vi.fn();

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

  it("returns existing config without calling create_tunnel", async () => {
    mockApiResponse({ status: "success", config: WG_CONF });
    const conf = await getOrCreateTunnelConfig("tok", "wireguard.mia.us.doxx.net");
    expect(conf).toBe(WG_CONF);
    expect(mockFetch).toHaveBeenCalledTimes(1);
    const call = mockFetch.mock.calls[0];
    const body = new URLSearchParams(call[1].body as string);
    expect(body.get("wireguard")).toBe("1");
    expect(body.has("create_tunnel")).toBe(false);
  });

  it("calls create_tunnel then wireguard when no existing config", async () => {
    // wireguard=1 returns no config
    mockApiResponse({ status: "error", message: "no tunnel" });
    // create_tunnel=1 returns success
    mockApiResponse({ status: "success" });
    // wireguard=1 second call returns config
    mockApiResponse({ status: "success", config: WG_CONF });

    const conf = await getOrCreateTunnelConfig("tok", "wireguard.mia.us.doxx.net");
    expect(conf).toBe(WG_CONF);
    expect(mockFetch).toHaveBeenCalledTimes(3);
    const createCall = mockFetch.mock.calls[1];
    const body = new URLSearchParams(createCall[1].body as string);
    expect(body.get("create_tunnel")).toBe("1");
    expect(body.get("server")).toBe("wireguard.mia.us.doxx.net");
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

  it("preserves AllowedIPs for scope=gateway", async () => {
    const conf =
      "[Interface]\nAddress = 10.8.0.1/24\n[Peer]\nAllowedIPs = 10.8.0.0/24\nEndpoint = host:51820";
    const env = { OPENCLAW_STATE_DIR: tmpDir } as unknown as NodeJS.ProcessEnv;
    const written = await writeDoxxnetWgConfig(conf, "gateway", env);
    const content = await fs.readFile(written, "utf8");
    expect(content).toContain("AllowedIPs = 10.8.0.0/24");
    expect(content).not.toContain("0.0.0.0/0");
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
  it("throws descriptive error when wg-quick fails", async () => {
    vi.resetModules();
    runExecMock.mockRejectedValue(new Error("Operation not permitted"));
    const { wgQuickUp } = await import("./doxxnet.js");
    await expect(wgQuickUp("/tmp/test.conf", "/usr/bin/wg-quick")).rejects.toThrow(
      "Operation not permitted",
    );
  });
});
