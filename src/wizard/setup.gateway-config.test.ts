import { describe, expect, it, vi } from "vitest";
import { createWizardPrompter as buildWizardPrompter } from "../../test/helpers/wizard-prompter.js";
import { DEFAULT_DANGEROUS_NODE_COMMANDS } from "../gateway/node-command-policy.js";
import type { RuntimeEnv } from "../runtime.js";
import type { WizardPrompter, WizardSelectParams } from "./prompts.js";

const mocks = vi.hoisted(() => ({
  randomToken: vi.fn(),
  getTailnetHostname: vi.fn(),
  findWgQuickBinary: vi.fn(async () => "/opt/homebrew/bin/wg-quick"),
  verifyDoxxnetToken: vi.fn(async () => undefined),
  listDoxxnetServers: vi.fn(async () => [
    { serverName: "wireguard.mia.us.doxx.net", location: "Miami, FL", description: "US Southeast" },
    {
      serverName: "wireguard.fra.eu.doxx.net",
      location: "Frankfurt, DE",
      description: "EU Central",
    },
  ]),
}));

vi.mock("../commands/onboard-helpers.js", async (importActual) => {
  const actual = await importActual<typeof import("../commands/onboard-helpers.js")>();
  return {
    ...actual,
    randomToken: mocks.randomToken,
  };
});

vi.mock("../infra/tailscale.js", () => ({
  findTailscaleBinary: vi.fn(async () => undefined),
  getTailnetHostname: mocks.getTailnetHostname,
}));

vi.mock("../infra/doxxnet.js", () => ({
  findWgQuickBinary: (...args: unknown[]) => mocks.findWgQuickBinary(...args),
  verifyDoxxnetToken: (...args: unknown[]) => mocks.verifyDoxxnetToken(...args),
  listDoxxnetServers: (...args: unknown[]) => mocks.listDoxxnetServers(...args),
  registerDoxxnetDomain: vi.fn(async () => undefined),
  setupDoxxnetDomainCert: vi.fn(async () => undefined),
}));

import { configureGatewayForSetup } from "./setup.gateway-config.js";

describe("configureGatewayForSetup", () => {
  function createPrompter(params: { selectQueue: string[]; textQueue: Array<string | undefined> }) {
    const selectQueue = [...params.selectQueue];
    const textQueue = [...params.textQueue];
    const select = vi.fn(async (params: WizardSelectParams<unknown>) => {
      const next = selectQueue.shift();
      if (next !== undefined) {
        return next;
      }
      return params.initialValue ?? params.options[0]?.value;
    }) as unknown as WizardPrompter["select"];

    return buildWizardPrompter({
      select,
      text: vi.fn(async () => textQueue.shift() as string),
    });
  }

  function createRuntime(): RuntimeEnv {
    return {
      log: vi.fn(),
      error: vi.fn(),
      exit: vi.fn(),
    };
  }

  function createQuickstartGateway(authMode: "token" | "password") {
    return {
      hasExisting: false,
      port: 18789,
      bind: "loopback" as const,
      authMode,
      tailscaleMode: "off" as const,
      token: undefined,
      password: undefined,
      customBindHost: undefined,
      tailscaleResetOnExit: false,
    };
  }

  async function runGatewayConfig(params?: {
    flow?: "advanced" | "quickstart";
    bindChoice?: string;
    authChoice?: "token" | "password";
    tailscaleChoice?: "off" | "serve";
    textQueue?: Array<string | undefined>;
    nextConfig?: Record<string, unknown>;
  }) {
    const authChoice = params?.authChoice ?? "token";
    const prompter = createPrompter({
      selectQueue: [params?.bindChoice ?? "loopback", authChoice, params?.tailscaleChoice ?? "off"],
      textQueue: params?.textQueue ?? ["18789", undefined],
    });
    const runtime = createRuntime();
    return configureGatewayForSetup({
      flow: params?.flow ?? "advanced",
      baseConfig: {},
      nextConfig: params?.nextConfig ?? {},
      localPort: 18789,
      quickstartGateway: createQuickstartGateway(authChoice),
      prompter,
      runtime,
    });
  }

  it("generates a token when the prompt returns undefined", async () => {
    mocks.randomToken.mockReturnValue("generated-token");
    const result = await runGatewayConfig();

    expect(result.settings.gatewayToken).toBe("generated-token");
    expect(result.nextConfig.gateway?.nodes?.denyCommands).toEqual(DEFAULT_DANGEROUS_NODE_COMMANDS);
  });

  it("prefers OPENCLAW_GATEWAY_TOKEN during quickstart token setup", async () => {
    const prevToken = process.env.OPENCLAW_GATEWAY_TOKEN;
    process.env.OPENCLAW_GATEWAY_TOKEN = "token-from-env";
    mocks.randomToken.mockReturnValue("generated-token");
    mocks.randomToken.mockClear();

    try {
      const result = await runGatewayConfig({
        flow: "quickstart",
        textQueue: [],
      });

      expect(result.settings.gatewayToken).toBe("token-from-env");
    } finally {
      if (prevToken === undefined) {
        delete process.env.OPENCLAW_GATEWAY_TOKEN;
      } else {
        process.env.OPENCLAW_GATEWAY_TOKEN = prevToken;
      }
    }
  });

  it("does not set password to literal 'undefined' when prompt returns undefined", async () => {
    mocks.randomToken.mockReturnValue("unused");
    const result = await runGatewayConfig({
      authChoice: "password",
    });

    const authConfig = result.nextConfig.gateway?.auth as { mode?: string; password?: string };
    expect(authConfig?.mode).toBe("password");
    expect(authConfig?.password).toBe("");
    expect(authConfig?.password).not.toBe("undefined");
  });

  it("seeds control UI allowed origins for non-loopback binds", async () => {
    mocks.randomToken.mockReturnValue("generated-token");
    const result = await runGatewayConfig({
      bindChoice: "lan",
    });

    expect(result.nextConfig.gateway?.controlUi?.allowedOrigins).toEqual([
      "http://localhost:18789",
      "http://127.0.0.1:18789",
    ]);
  });

  it("honors secretInputMode=ref for gateway password prompts", async () => {
    const previous = process.env.OPENCLAW_GATEWAY_PASSWORD;
    process.env.OPENCLAW_GATEWAY_PASSWORD = "gateway-secret"; // pragma: allowlist secret
    try {
      const prompter = createPrompter({
        selectQueue: ["loopback", "password", "off", "env"],
        textQueue: ["18789", "OPENCLAW_GATEWAY_PASSWORD"],
      });
      const runtime = createRuntime();

      const result = await configureGatewayForSetup({
        flow: "advanced",
        baseConfig: {},
        nextConfig: {},
        localPort: 18789,
        quickstartGateway: createQuickstartGateway("password"),
        secretInputMode: "ref", // pragma: allowlist secret
        prompter,
        runtime,
      });

      expect(result.nextConfig.gateway?.auth?.mode).toBe("password");
      expect(result.nextConfig.gateway?.auth?.password).toEqual({
        source: "env",
        provider: "default",
        id: "OPENCLAW_GATEWAY_PASSWORD",
      });
    } finally {
      if (previous === undefined) {
        delete process.env.OPENCLAW_GATEWAY_PASSWORD;
      } else {
        process.env.OPENCLAW_GATEWAY_PASSWORD = previous;
      }
    }
  });

  it("stores gateway token as SecretRef when secretInputMode=ref", async () => {
    const previous = process.env.OPENCLAW_GATEWAY_TOKEN;
    process.env.OPENCLAW_GATEWAY_TOKEN = "token-from-env";
    try {
      const prompter = createPrompter({
        selectQueue: ["loopback", "token", "off", "env"],
        textQueue: ["18789", "OPENCLAW_GATEWAY_TOKEN"],
      });
      const runtime = createRuntime();

      const result = await configureGatewayForSetup({
        flow: "advanced",
        baseConfig: {},
        nextConfig: {},
        localPort: 18789,
        quickstartGateway: createQuickstartGateway("token"),
        secretInputMode: "ref", // pragma: allowlist secret
        prompter,
        runtime,
      });

      expect(result.nextConfig.gateway?.auth?.mode).toBe("token");
      expect(result.nextConfig.gateway?.auth?.token).toEqual({
        source: "env",
        provider: "default",
        id: "OPENCLAW_GATEWAY_TOKEN",
      });
      expect(result.settings.gatewayToken).toBe("token-from-env");
    } finally {
      if (previous === undefined) {
        delete process.env.OPENCLAW_GATEWAY_TOKEN;
      } else {
        process.env.OPENCLAW_GATEWAY_TOKEN = previous;
      }
    }
  });

  it("doxxnet: re-prompts on invalid token then accepts valid token (AC-1/2)", async () => {
    mocks.randomToken.mockReturnValue("gen-token");
    // First token attempt fails, second succeeds
    mocks.verifyDoxxnetToken
      .mockRejectedValueOnce(new Error("invalid token"))
      .mockResolvedValueOnce(undefined);

    const noteMessages: string[] = [];
    // Stateful select queue: bind, auth, tailscale, server, scope
    const selectQueue = ["loopback", "token", "off", "wireguard.mia.us.doxx.net", "gateway"];
    const prompter = buildWizardPrompter({
      select: vi.fn(async (p: WizardSelectParams<unknown>) => {
        const next = selectQueue.shift();
        return next ?? p.initialValue ?? p.options[0]?.value;
      }) as unknown as WizardPrompter["select"],
      confirm: vi
        .fn()
        .mockResolvedValueOnce(true) // doxxnetEnabled
        .mockResolvedValueOnce(false), // resetOnExit
      text: vi
        .fn()
        .mockResolvedValueOnce("18789") // port
        .mockResolvedValueOnce("bad-token") // first token attempt
        .mockResolvedValueOnce("good-token") // second token attempt
        .mockResolvedValueOnce(undefined), // gateway token
      note: vi.fn(async (msg: string) => {
        noteMessages.push(msg);
      }),
    });
    const runtime: RuntimeEnv = { log: vi.fn(), error: vi.fn(), exit: vi.fn() };

    const result = await configureGatewayForSetup({
      flow: "advanced",
      baseConfig: {},
      nextConfig: {},
      localPort: 18789,
      quickstartGateway: createQuickstartGateway("token"),
      prompter,
      runtime,
    });

    // Re-prompt note should have been shown once for the bad token
    expect(noteMessages.some((m) => m.includes("Token verification failed"))).toBe(true);
    // Final config should have the doxxnet token
    expect(result.nextConfig.gateway?.doxxnet?.token).toBe("good-token");
    expect(result.nextConfig.gateway?.doxxnet?.mode).toBe("on");
  });

  it("doxxnet: populates server list from API in wizard (AC-3)", async () => {
    mocks.randomToken.mockReturnValue("gen-token");
    mocks.verifyDoxxnetToken.mockResolvedValue(undefined);

    const serverSelectOptions: string[] = [];
    const prompter = buildWizardPrompter({
      select: vi.fn(async (p: WizardSelectParams<unknown>) => {
        // Capture the options when the server selection prompt fires
        if (p.message === "doxxnet server") {
          for (const opt of p.options) {
            serverSelectOptions.push(String((opt as { label: string }).label));
          }
          return (p.options[0] as { value: unknown }).value;
        }
        // bind, auth, tailscale, scope
        const defaults: Record<string, unknown> = {
          "Gateway bind": "loopback",
          "Gateway auth": "token",
          "Tailscale exposure": "off",
          "doxxnet traffic scope": "gateway",
        };
        return defaults[p.message] ?? p.initialValue ?? p.options[0]?.value;
      }) as unknown as WizardPrompter["select"],
      confirm: vi
        .fn()
        .mockResolvedValueOnce(true) // doxxnetEnabled
        .mockResolvedValueOnce(false), // resetOnExit
      text: vi
        .fn()
        .mockResolvedValueOnce("18789")
        .mockResolvedValueOnce("my-token")
        .mockResolvedValueOnce(undefined),
    });
    const runtime: RuntimeEnv = { log: vi.fn(), error: vi.fn(), exit: vi.fn() };

    await configureGatewayForSetup({
      flow: "advanced",
      baseConfig: {},
      nextConfig: {},
      localPort: 18789,
      quickstartGateway: createQuickstartGateway("token"),
      prompter,
      runtime,
    });

    expect(serverSelectOptions).toContain("Miami, FL — US Southeast");
    expect(serverSelectOptions).toContain("Frankfurt, DE — EU Central");
  });

  it("doxxnet: scope=gateway auto-sets bind=doxxnet; scope=all keeps loopback", async () => {
    mocks.randomToken.mockReturnValue("gen-token");
    mocks.verifyDoxxnetToken.mockResolvedValue(undefined);

    async function runWithScope(scope: string) {
      const prompter = buildWizardPrompter({
        select: vi.fn(async (p: WizardSelectParams<unknown>) => {
          if (p.message === "doxxnet traffic scope") {
            return scope;
          }
          if (p.message === "doxxnet server") {
            return "wireguard.mia.us.doxx.net";
          }
          const defaults: Record<string, unknown> = {
            "Gateway bind": "loopback",
            "Gateway auth": "token",
            "Tailscale exposure": "off",
          };
          return defaults[p.message] ?? p.initialValue ?? p.options[0]?.value;
        }) as unknown as WizardPrompter["select"],
        confirm: vi
          .fn()
          .mockResolvedValueOnce(true) // doxxnetEnabled
          .mockResolvedValueOnce(false), // resetOnExit
        text: vi
          .fn()
          .mockResolvedValueOnce("18789")
          .mockResolvedValueOnce("tok")
          .mockResolvedValueOnce(undefined),
      });
      const runtime: RuntimeEnv = { log: vi.fn(), error: vi.fn(), exit: vi.fn() };
      return configureGatewayForSetup({
        flow: "advanced",
        baseConfig: {},
        nextConfig: {},
        localPort: 18789,
        quickstartGateway: createQuickstartGateway("token"),
        prompter,
        runtime,
      });
    }

    const gatewayResult = await runWithScope("gateway");
    expect(gatewayResult.nextConfig.gateway?.bind).toBe("doxxnet");

    const allResult = await runWithScope("all");
    expect(allResult.nextConfig.gateway?.bind).toBe("loopback");
  });

  it("resolves quickstart exec SecretRefs for gateway token bootstrap", async () => {
    const quickstartGateway = {
      ...createQuickstartGateway("token"),
      token: {
        source: "exec" as const,
        provider: "gatewayTokens",
        id: "gateway/auth/token",
      },
    };
    const runtime = createRuntime();
    const prompter = createPrompter({
      selectQueue: [],
      textQueue: [],
    });

    const result = await configureGatewayForSetup({
      flow: "quickstart",
      baseConfig: {},
      nextConfig: {
        secrets: {
          providers: {
            gatewayTokens: {
              source: "exec",
              command: process.execPath,
              allowInsecurePath: true,
              allowSymlinkCommand: true,
              args: [
                "-e",
                "let input='';process.stdin.setEncoding('utf8');process.stdin.on('data',d=>input+=d);process.stdin.on('end',()=>{const req=JSON.parse(input||'{}');const values={};for(const id of req.ids||[]){values[id]='token-from-exec';}process.stdout.write(JSON.stringify({protocolVersion:1,values}));});",
              ],
            },
          },
        },
      },
      localPort: 18789,
      quickstartGateway,
      prompter,
      runtime,
    });

    expect(result.nextConfig.gateway?.auth?.token).toEqual(quickstartGateway.token);
    expect(result.settings.gatewayToken).toBe("token-from-exec");
  });
});
