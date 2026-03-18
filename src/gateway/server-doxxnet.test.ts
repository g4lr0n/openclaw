import { afterEach, describe, expect, it, vi } from "vitest";
import * as doxxnet from "../infra/doxxnet.js";
import { startGatewayDoxxnetExposure } from "./server-doxxnet.js";

vi.mock("../infra/doxxnet.js", () => ({
  findWgQuickBinary: vi.fn(),
  getOrCreateTunnelConfig: vi.fn(),
  writeDoxxnetWgConfig: vi.fn(),
  wgQuickUp: vi.fn(),
  wgQuickDown: vi.fn(),
  checkDoxxnetInterface: vi.fn(),
  pickPrimaryDoxxnetIPv4: vi.fn(),
  setActiveDoxxnetCidr: vi.fn(),
}));

const mockLog = { info: vi.fn(), warn: vi.fn() };

afterEach(() => vi.clearAllMocks());

describe("startGatewayDoxxnetExposure", () => {
  it("returns null immediately when mode=off", async () => {
    const result = await startGatewayDoxxnetExposure({
      doxxnetMode: "off",
      scope: "gateway",
      port: 18789,
      logDoxxnet: mockLog,
    });
    expect(result).toBeNull();
    expect(doxxnet.findWgQuickBinary).not.toHaveBeenCalled();
  });

  it("returns null and warns when no token provided", async () => {
    const origEnv = process.env.DOXXNET_TOKEN;
    delete process.env.DOXXNET_TOKEN;
    try {
      const result = await startGatewayDoxxnetExposure({
        doxxnetMode: "on",
        scope: "gateway",
        port: 18789,
        logDoxxnet: mockLog,
      });
      expect(result).toBeNull();
      expect(mockLog.warn).toHaveBeenCalledWith(expect.stringContaining("no token"));
    } finally {
      if (origEnv !== undefined) {
        process.env.DOXXNET_TOKEN = origEnv;
      }
    }
  });

  it("returns null and warns when wg-quick is missing", async () => {
    vi.mocked(doxxnet.findWgQuickBinary).mockResolvedValue(null);
    const result = await startGatewayDoxxnetExposure({
      doxxnetMode: "on",
      scope: "gateway",
      doxxnetToken: "test-token",
      port: 18789,
      logDoxxnet: mockLog,
    });
    expect(result).toBeNull();
    expect(mockLog.warn).toHaveBeenCalledWith(expect.stringContaining("wg-quick not found"));
  });

  it("brings up tunnel and logs IP on success", async () => {
    vi.mocked(doxxnet.findWgQuickBinary).mockResolvedValue("/usr/bin/wg-quick");
    vi.mocked(doxxnet.getOrCreateTunnelConfig).mockResolvedValue(
      "[Interface]\nAddress = 10.8.0.1/24\n[Peer]\nAllowedIPs = 10.8.0.0/24",
    );
    vi.mocked(doxxnet.writeDoxxnetWgConfig).mockResolvedValue("/tmp/doxxnet.conf");
    vi.mocked(doxxnet.checkDoxxnetInterface).mockResolvedValue(false);
    vi.mocked(doxxnet.wgQuickUp).mockResolvedValue({
      interfaceName: "doxxnet",
      interfaceIp: "10.8.0.1",
    });
    vi.mocked(doxxnet.pickPrimaryDoxxnetIPv4).mockReturnValue("10.8.0.1");

    const result = await startGatewayDoxxnetExposure({
      doxxnetMode: "on",
      scope: "gateway",
      doxxnetToken: "test-token",
      doxxnetServer: "wireguard.mia.us.doxx.net",
      port: 18789,
      logDoxxnet: mockLog,
    });

    expect(doxxnet.wgQuickUp).toHaveBeenCalledWith("/tmp/doxxnet.conf", "/usr/bin/wg-quick");
    expect(mockLog.info).toHaveBeenCalledWith(expect.stringContaining("10.8.0.1"));
    // resetOnExit not set → returns null
    expect(result).toBeNull();
  });

  it("skips wgQuickUp when tunnel is already up (idempotent AC-4)", async () => {
    vi.mocked(doxxnet.findWgQuickBinary).mockResolvedValue("/usr/bin/wg-quick");
    vi.mocked(doxxnet.getOrCreateTunnelConfig).mockResolvedValue(
      "[Interface]\nAddress = 10.8.0.1/24\n[Peer]\nAllowedIPs = 10.8.0.0/24",
    );
    vi.mocked(doxxnet.writeDoxxnetWgConfig).mockResolvedValue("/tmp/doxxnet.conf");
    vi.mocked(doxxnet.checkDoxxnetInterface).mockResolvedValue(true); // already up
    vi.mocked(doxxnet.pickPrimaryDoxxnetIPv4).mockReturnValue("10.8.0.1");

    await startGatewayDoxxnetExposure({
      doxxnetMode: "on",
      scope: "gateway",
      doxxnetToken: "test-token",
      port: 18789,
      logDoxxnet: mockLog,
    });

    expect(doxxnet.wgQuickUp).not.toHaveBeenCalled();
    expect(mockLog.info).toHaveBeenCalledWith(expect.stringContaining("already up"));
  });

  it("reads token from DOXXNET_TOKEN env when doxxnetToken param is absent (AC-11)", async () => {
    const prev = process.env.DOXXNET_TOKEN;
    process.env.DOXXNET_TOKEN = "env-token-value";
    try {
      vi.mocked(doxxnet.findWgQuickBinary).mockResolvedValue("/usr/bin/wg-quick");
      vi.mocked(doxxnet.getOrCreateTunnelConfig).mockResolvedValue(
        "[Interface]\nAddress = 10.9.0.1/24\n[Peer]\nAllowedIPs = 10.9.0.0/24",
      );
      vi.mocked(doxxnet.writeDoxxnetWgConfig).mockResolvedValue("/tmp/doxxnet.conf");
      vi.mocked(doxxnet.checkDoxxnetInterface).mockResolvedValue(false);
      vi.mocked(doxxnet.wgQuickUp).mockResolvedValue({
        interfaceName: "doxxnet",
        interfaceIp: "10.9.0.1",
      });
      vi.mocked(doxxnet.pickPrimaryDoxxnetIPv4).mockReturnValue("10.9.0.1");

      await startGatewayDoxxnetExposure({
        doxxnetMode: "on",
        scope: "gateway",
        // no doxxnetToken param — must fall back to env
        port: 18789,
        logDoxxnet: mockLog,
      });

      // wg-quick up should have been called, proving the env token was used
      expect(doxxnet.wgQuickUp).toHaveBeenCalled();
      expect(mockLog.warn).not.toHaveBeenCalledWith(expect.stringContaining("no token"));
    } finally {
      if (prev === undefined) {
        delete process.env.DOXXNET_TOKEN;
      } else {
        process.env.DOXXNET_TOKEN = prev;
      }
    }
  });

  it("returns teardown function when resetOnExit=true", async () => {
    vi.mocked(doxxnet.findWgQuickBinary).mockResolvedValue("/usr/bin/wg-quick");
    vi.mocked(doxxnet.getOrCreateTunnelConfig).mockResolvedValue(
      "[Interface]\nAddress = 10.8.0.1/24\n[Peer]\nAllowedIPs = 10.8.0.0/24",
    );
    vi.mocked(doxxnet.writeDoxxnetWgConfig).mockResolvedValue("/tmp/doxxnet.conf");
    vi.mocked(doxxnet.checkDoxxnetInterface).mockResolvedValue(false);
    vi.mocked(doxxnet.wgQuickUp).mockResolvedValue({
      interfaceName: "doxxnet",
      interfaceIp: "10.8.0.1",
    });
    vi.mocked(doxxnet.pickPrimaryDoxxnetIPv4).mockReturnValue("10.8.0.1");
    vi.mocked(doxxnet.wgQuickDown).mockResolvedValue();

    const cleanup = await startGatewayDoxxnetExposure({
      doxxnetMode: "on",
      scope: "gateway",
      doxxnetToken: "test-token",
      doxxnetServer: "wireguard.mia.us.doxx.net",
      resetOnExit: true,
      port: 18789,
      logDoxxnet: mockLog,
    });

    expect(cleanup).toBeTypeOf("function");
    await cleanup!();
    expect(doxxnet.wgQuickDown).toHaveBeenCalledWith("/tmp/doxxnet.conf", "/usr/bin/wg-quick");
  });
});
