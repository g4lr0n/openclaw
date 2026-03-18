import path from "node:path";
import {
  normalizeGatewayTokenInput,
  randomToken,
  validateGatewayPasswordInput,
} from "../commands/onboard-helpers.js";
import type { GatewayAuthChoice, SecretInputMode } from "../commands/onboard-types.js";
import type {
  DoxxnetTrafficScope,
  GatewayBindMode,
  GatewayDoxxnetMode,
  GatewayTailscaleMode,
  OpenClawConfig,
} from "../config/config.js";
import { ensureControlUiAllowedOriginsForNonLoopbackBind } from "../config/gateway-control-ui-origins.js";
import { resolveStateDir } from "../config/paths.js";
import {
  normalizeSecretInputString,
  resolveSecretInputRef,
  type SecretInput,
} from "../config/types.secrets.js";
import {
  maybeAddTailnetOriginToControlUiAllowedOrigins,
  TAILSCALE_DOCS_LINES,
  TAILSCALE_EXPOSURE_OPTIONS,
  TAILSCALE_MISSING_BIN_NOTE_LINES,
} from "../gateway/gateway-config-prompts.shared.js";
import { DEFAULT_DANGEROUS_NODE_COMMANDS } from "../gateway/node-command-policy.js";
import {
  findWgQuickBinary,
  getOrCreateTunnelConfig,
  listDoxxnetServers,
  registerDoxxnetDomain,
  setupDoxxnetDomainCert,
  verifyDoxxnetToken,
} from "../infra/doxxnet.js";
import { findTailscaleBinary } from "../infra/tailscale.js";
import {
  promptSecretRefForSetup,
  resolveSecretInputModeForEnvSelection,
} from "../plugins/provider-auth-input.js";
import type { RuntimeEnv } from "../runtime.js";
import { validateIPv4AddressInput } from "../shared/net/ipv4.js";
import type { WizardPrompter } from "./prompts.js";
import { resolveSetupSecretInputString } from "./setup.secret-input.js";
import type {
  GatewayWizardSettings,
  QuickstartGatewayDefaults,
  WizardFlow,
} from "./setup.types.js";

type ConfigureGatewayOptions = {
  flow: WizardFlow;
  baseConfig: OpenClawConfig;
  nextConfig: OpenClawConfig;
  localPort: number;
  quickstartGateway: QuickstartGatewayDefaults;
  secretInputMode?: SecretInputMode;
  prompter: WizardPrompter;
  runtime: RuntimeEnv;
};

type ConfigureGatewayResult = {
  nextConfig: OpenClawConfig;
  settings: GatewayWizardSettings;
};

export async function configureGatewayForSetup(
  opts: ConfigureGatewayOptions,
): Promise<ConfigureGatewayResult> {
  const { flow, localPort, quickstartGateway, prompter } = opts;
  let { nextConfig } = opts;

  const port =
    flow === "quickstart"
      ? quickstartGateway.port
      : Number.parseInt(
          String(
            await prompter.text({
              message: "Gateway port",
              initialValue: String(localPort),
              validate: (value) => (Number.isFinite(Number(value)) ? undefined : "Invalid port"),
            }),
          ),
          10,
        );

  let bind: GatewayWizardSettings["bind"] =
    flow === "quickstart"
      ? quickstartGateway.bind
      : await prompter.select<GatewayWizardSettings["bind"]>({
          message: "Gateway bind",
          options: [
            { value: "loopback", label: "Loopback (127.0.0.1)" },
            { value: "lan", label: "LAN (0.0.0.0)" },
            {
              value: "doxxnet",
              label: "doxxnet",
              hint: "Accessible via doxxnet VPN",
            },
            { value: "tailnet", label: "Tailnet (Tailscale IP)" },
            { value: "auto", label: "Auto (Loopback → LAN)" },
            { value: "custom", label: "Custom IP" },
          ],
        });

  let customBindHost = quickstartGateway.customBindHost;
  if (bind === "custom") {
    const needsPrompt = flow !== "quickstart" || !customBindHost;
    if (needsPrompt) {
      const input = await prompter.text({
        message: "Custom IP address",
        placeholder: "192.168.1.100",
        initialValue: customBindHost ?? "",
        validate: validateIPv4AddressInput,
      });
      customBindHost = typeof input === "string" ? input.trim() : undefined;
    }
  }

  let authMode =
    flow === "quickstart" || bind === "doxxnet"
      ? ("token" as GatewayAuthChoice)
      : ((await prompter.select({
          message: "Gateway auth",
          options: [
            {
              value: "token",
              label: "Token",
              hint: "Recommended default (local + remote)",
            },
            { value: "password", label: "Password" },
          ],
          initialValue: "token",
        })) as GatewayAuthChoice);

  const tailscaleMode: GatewayWizardSettings["tailscaleMode"] =
    flow === "quickstart" || bind === "doxxnet"
      ? ("off" as const)
      : await prompter.select<GatewayWizardSettings["tailscaleMode"]>({
          message: "Tailscale exposure",
          options: [...TAILSCALE_EXPOSURE_OPTIONS],
        });

  // Detect Tailscale binary before proceeding with serve/funnel setup.
  // Persist the path so getTailnetHostname can reuse it for origin injection.
  let tailscaleBin: string | null = null;
  if (tailscaleMode !== "off") {
    tailscaleBin = await findTailscaleBinary();
    if (!tailscaleBin) {
      await prompter.note(TAILSCALE_MISSING_BIN_NOTE_LINES.join("\n"), "Tailscale Warning");
    }
  }

  let tailscaleResetOnExit = flow === "quickstart" ? quickstartGateway.tailscaleResetOnExit : false;
  if (tailscaleMode !== "off" && flow !== "quickstart") {
    await prompter.note(TAILSCALE_DOCS_LINES.join("\n"), "Tailscale");
    tailscaleResetOnExit = Boolean(
      await prompter.confirm({
        message: "Reset Tailscale serve/funnel on exit?",
        initialValue: false,
      }),
    );
  }

  // --- doxxnet VPN (optional, advanced flow only) ---
  let doxxnetMode: GatewayWizardSettings["doxxnetMode"] = "off";
  let doxxnetScope: GatewayWizardSettings["doxxnetScope"] = "gateway";
  let doxxnetResetOnExit = false;
  let doxxnetToken: string | undefined;
  let doxxnetServer: string | undefined;
  let doxxnetDomain: string | undefined;

  if (flow !== "quickstart") {
    // If user picked bind=doxxnet, skip the confirm and go straight to setup
    const doxxnetEnabled =
      bind === "doxxnet" ||
      Boolean(
        await prompter.confirm({
          message: "Route gateway traffic through doxxnet VPN? (optional)",
          initialValue: false,
        }),
      );

    if (doxxnetEnabled) {
      doxxnetMode = "on";

      // Check for wg-quick early so we can warn before prompting for creds
      const wgQuickBin = await findWgQuickBinary();
      if (!wgQuickBin) {
        await prompter.note(
          [
            "wg-quick not found in PATH.",
            "Install wireguard-tools to activate the tunnel:",
            "  macOS:          brew install wireguard-tools",
            "  Debian/Ubuntu:  apt install wireguard-tools",
            "",
            "You can continue setup, but the tunnel will fail at runtime.",
          ].join("\n"),
          "doxxnet Warning",
        );
      }

      // Token input
      let verified = false;
      while (!verified) {
        const rawToken = String(
          await prompter.text({
            message: "doxxnet auth token (get yours at https://a0x13.doxx.net)",
            placeholder: "Paste your doxxnet token",
            secret: true,
          }),
        ).trim();
        if (!rawToken) {
          break;
        }
        try {
          await verifyDoxxnetToken(rawToken);
          doxxnetToken = rawToken;
          verified = true;
        } catch (err) {
          await prompter.note(
            `Token verification failed: ${err instanceof Error ? err.message : String(err)}\nPlease try again.`,
            "doxxnet Error",
          );
        }
      }

      if (doxxnetToken) {
        // Server selection
        try {
          const servers = await listDoxxnetServers();
          if (servers.length > 0) {
            const selected = await prompter.select<string>({
              message: "doxxnet server",
              options: servers.map((s) => ({
                value: s.serverName,
                label: `${s.location} — ${s.description}`,
                hint: s.serverName,
              })),
            });
            doxxnetServer = typeof selected === "string" ? selected : undefined;
          }
        } catch {
          // Non-fatal: user can configure server manually later
        }

        // Traffic scope
        doxxnetScope = await prompter.select<DoxxnetTrafficScope>({
          message: "doxxnet traffic scope",
          options: [
            {
              value: "gateway" as const,
              label: "Gateway access only",
              hint: "Remote clients reach you via doxxnet",
            },
            {
              value: "all" as const,
              label: "All outbound traffic",
              hint: "Route all openclaw API calls through doxxnet",
            },
            {
              value: "web" as const,
              label: "Agent web requests",
              hint: "Only agent browse/search via doxxnet",
            },
          ],
          initialValue: "gateway" as const,
        });

        // Constraints: scope=gateway binds to the WireGuard IP; others use loopback
        if (doxxnetScope === "gateway") {
          bind = "doxxnet" as GatewayBindMode;
          customBindHost = undefined;
        } else if (bind === "doxxnet") {
          bind = "loopback";
        }

        doxxnetResetOnExit = Boolean(
          await prompter.confirm({
            message: "Tear down doxxnet tunnel on gateway shutdown?",
            initialValue: false,
          }),
        );

        // Pre-provision WireGuard tunnel so it's ready by the time gateway starts.
        // The doxxnet API takes ~60s to provision; doing it here avoids a wait at
        // gateway startup. Non-fatal: gateway will retry with backoff on startup.
        if (doxxnetServer) {
          await prompter.note(
            [
              "Creating WireGuard tunnel on doxxnet...",
              "(This may take up to 90 seconds while provisioning.)",
            ].join("\n"),
            "doxxnet tunnel",
          );
          try {
            await getOrCreateTunnelConfig(doxxnetToken, doxxnetServer);
            await prompter.note("WireGuard tunnel ready.", "doxxnet tunnel");
          } catch (err) {
            await prompter.note(
              [
                `Tunnel pre-provisioning failed: ${err instanceof Error ? err.message : String(err)}`,
                "The gateway will retry automatically on startup.",
              ].join("\n"),
              "doxxnet Warning",
            );
          }
        }

        // HTTPS via doxxnet domain + CA-signed cert (scope=gateway only)
        if (doxxnetScope === "gateway") {
          const wantsHttps = Boolean(
            await prompter.confirm({
              message:
                "Set up HTTPS via a doxxnet domain? (Enables secure Control UI — recommended)",
              initialValue: true,
            }),
          );
          if (wantsHttps) {
            // Generate a random domain like openclaw-a1b2c3d4.wg
            const suffix = Math.random().toString(16).slice(2, 10);
            const proposedDomain = `openclaw-${suffix}.wg`;
            await prompter.note(
              [
                `Registering doxxnet domain: ${proposedDomain}`,
                "Generating EC private key and signing certificate with doxxnet CA...",
                "(This may take a few seconds.)",
              ].join("\n"),
              "doxxnet HTTPS",
            );
            try {
              await registerDoxxnetDomain(doxxnetToken, proposedDomain);
              const stateDir = resolveStateDir(process.env);
              const certPath = path.join(stateDir, "vpn", "tls", "doxxnet-cert.pem");
              const keyPath = path.join(stateDir, "vpn", "tls", "doxxnet-key.pem");
              await setupDoxxnetDomainCert({
                token: doxxnetToken,
                domain: proposedDomain,
                certPath,
                keyPath,
              });
              doxxnetDomain = proposedDomain;
              nextConfig = {
                ...nextConfig,
                gateway: {
                  ...nextConfig.gateway,
                  tls: {
                    enabled: true,
                    certPath,
                    keyPath,
                  },
                },
              };
              await prompter.note(
                [
                  `Domain registered: ${proposedDomain}`,
                  "Certificate signed by doxxnet CA and saved.",
                  "Gateway will serve HTTPS. Connect via:",
                  `  https://${proposedDomain}:${port}`,
                ].join("\n"),
                "doxxnet HTTPS ready",
              );
            } catch (err) {
              await prompter.note(
                [
                  `HTTPS setup failed: ${err instanceof Error ? err.message : String(err)}`,
                  "Continuing without HTTPS. You can set up a doxxnet domain manually later.",
                ].join("\n"),
                "doxxnet HTTPS Warning",
              );
            }
          }
        }
      }
    }
  } else {
    // quickstart: apply stored doxxnet defaults
    doxxnetMode =
      (
        opts.quickstartGateway as typeof opts.quickstartGateway & {
          doxxnetMode?: "off" | "on";
        }
      ).doxxnetMode ?? "off";
    doxxnetScope =
      (
        opts.quickstartGateway as typeof opts.quickstartGateway & {
          doxxnetScope?: DoxxnetTrafficScope;
        }
      ).doxxnetScope ?? "gateway";
    doxxnetResetOnExit =
      (
        opts.quickstartGateway as typeof opts.quickstartGateway & {
          doxxnetResetOnExit?: boolean;
        }
      ).doxxnetResetOnExit ?? false;
  }

  // Safety + constraints:
  // - Tailscale wants bind=loopback so we never expose a non-loopback server + tailscale serve/funnel at once.
  // - Funnel requires password auth.
  if (tailscaleMode !== "off" && bind !== "loopback") {
    await prompter.note("Tailscale requires bind=loopback. Adjusting bind to loopback.", "Note");
    bind = "loopback";
    customBindHost = undefined;
  }

  if (tailscaleMode === "funnel" && authMode !== "password") {
    await prompter.note("Tailscale funnel requires password auth.", "Note");
    authMode = "password";
  }

  let gatewayToken: string | undefined;
  let gatewayTokenInput: SecretInput | undefined;
  if (authMode === "token") {
    const quickstartTokenString = normalizeSecretInputString(quickstartGateway.token);
    const quickstartTokenRef = resolveSecretInputRef({
      value: quickstartGateway.token,
      defaults: nextConfig.secrets?.defaults,
    }).ref;
    const tokenMode =
      flow === "quickstart" && opts.secretInputMode !== "ref" // pragma: allowlist secret
        ? quickstartTokenRef
          ? "ref"
          : "plaintext"
        : await resolveSecretInputModeForEnvSelection({
            prompter,
            explicitMode: opts.secretInputMode,
            copy: {
              modeMessage: "How do you want to provide the gateway token?",
              plaintextLabel: "Generate/store plaintext token",
              plaintextHint: "Default",
              refLabel: "Use SecretRef",
              refHint: "Store a reference instead of plaintext",
            },
          });
    if (tokenMode === "ref") {
      if (flow === "quickstart" && quickstartTokenRef) {
        gatewayTokenInput = quickstartTokenRef;
        gatewayToken = await resolveSetupSecretInputString({
          config: nextConfig,
          value: quickstartTokenRef,
          path: "gateway.auth.token",
          env: process.env,
        });
      } else {
        const resolved = await promptSecretRefForSetup({
          provider: "gateway-auth-token",
          config: nextConfig,
          prompter,
          preferredEnvVar: "OPENCLAW_GATEWAY_TOKEN",
          copy: {
            sourceMessage: "Where is this gateway token stored?",
            envVarPlaceholder: "OPENCLAW_GATEWAY_TOKEN",
          },
        });
        gatewayTokenInput = resolved.ref;
        gatewayToken = resolved.resolvedValue;
      }
    } else if (flow === "quickstart") {
      gatewayToken =
        (quickstartTokenString ?? normalizeGatewayTokenInput(process.env.OPENCLAW_GATEWAY_TOKEN)) ||
        randomToken();
      gatewayTokenInput = gatewayToken;
    } else {
      const tokenInput = await prompter.text({
        message: "Gateway token (blank to generate)",
        placeholder: "Needed for multi-machine or non-loopback access",
        initialValue:
          quickstartTokenString ??
          normalizeGatewayTokenInput(process.env.OPENCLAW_GATEWAY_TOKEN) ??
          "",
      });
      gatewayToken = normalizeGatewayTokenInput(tokenInput) || randomToken();
      gatewayTokenInput = gatewayToken;
    }
  }

  if (authMode === "password") {
    let password: SecretInput | undefined =
      flow === "quickstart" && quickstartGateway.password ? quickstartGateway.password : undefined;
    if (!password) {
      const selectedMode = await resolveSecretInputModeForEnvSelection({
        prompter,
        explicitMode: opts.secretInputMode,
        copy: {
          modeMessage: "How do you want to provide the gateway password?",
          plaintextLabel: "Enter password now",
          plaintextHint: "Stores the password directly in OpenClaw config",
        },
      });
      if (selectedMode === "ref") {
        const resolved = await promptSecretRefForSetup({
          provider: "gateway-auth-password",
          config: nextConfig,
          prompter,
          preferredEnvVar: "OPENCLAW_GATEWAY_PASSWORD",
          copy: {
            sourceMessage: "Where is this gateway password stored?",
            envVarPlaceholder: "OPENCLAW_GATEWAY_PASSWORD",
          },
        });
        password = resolved.ref;
      } else {
        password = String(
          (await prompter.text({
            message: "Gateway password",
            validate: validateGatewayPasswordInput,
          })) ?? "",
        ).trim();
      }
    }
    nextConfig = {
      ...nextConfig,
      gateway: {
        ...nextConfig.gateway,
        auth: {
          ...nextConfig.gateway?.auth,
          mode: "password",
          password,
        },
      },
    };
  } else if (authMode === "token") {
    nextConfig = {
      ...nextConfig,
      gateway: {
        ...nextConfig.gateway,
        auth: {
          ...nextConfig.gateway?.auth,
          mode: "token",
          token: gatewayTokenInput,
        },
      },
    };
  }

  nextConfig = {
    ...nextConfig,
    gateway: {
      ...nextConfig.gateway,
      port,
      bind: bind as GatewayBindMode,
      ...(bind === "custom" && customBindHost ? { customBindHost } : {}),
      tailscale: {
        ...nextConfig.gateway?.tailscale,
        mode: tailscaleMode as GatewayTailscaleMode,
        resetOnExit: tailscaleResetOnExit,
      },
      ...(doxxnetMode !== "off"
        ? {
            doxxnet: {
              ...nextConfig.gateway?.doxxnet,
              mode: doxxnetMode as GatewayDoxxnetMode,
              scope: doxxnetScope,
              ...(doxxnetToken ? { token: doxxnetToken } : {}),
              ...(doxxnetServer ? { server: doxxnetServer } : {}),
              ...(doxxnetDomain ? { domain: doxxnetDomain } : {}),
              resetOnExit: doxxnetResetOnExit,
            },
          }
        : {}),
    },
  };

  nextConfig = ensureControlUiAllowedOriginsForNonLoopbackBind(nextConfig, {
    requireControlUiEnabled: true,
  }).config;
  nextConfig = await maybeAddTailnetOriginToControlUiAllowedOrigins({
    config: nextConfig,
    tailscaleMode,
    tailscaleBin,
  });

  // If this is a new gateway setup (no existing gateway settings), start with a
  // denylist for high-risk node commands. Users can arm these temporarily via
  // /phone arm ... (phone-control plugin).
  if (
    !quickstartGateway.hasExisting &&
    nextConfig.gateway?.nodes?.denyCommands === undefined &&
    nextConfig.gateway?.nodes?.allowCommands === undefined &&
    nextConfig.gateway?.nodes?.browser === undefined
  ) {
    nextConfig = {
      ...nextConfig,
      gateway: {
        ...nextConfig.gateway,
        nodes: {
          ...nextConfig.gateway?.nodes,
          denyCommands: [...DEFAULT_DANGEROUS_NODE_COMMANDS],
        },
      },
    };
  }

  return {
    nextConfig,
    settings: {
      port,
      bind: bind as GatewayBindMode,
      customBindHost: bind === "custom" ? customBindHost : undefined,
      authMode,
      gatewayToken,
      tailscaleMode: tailscaleMode as GatewayTailscaleMode,
      tailscaleResetOnExit,
      doxxnetMode,
      doxxnetScope,
      doxxnetResetOnExit,
      doxxnetDomain,
    },
  };
}
