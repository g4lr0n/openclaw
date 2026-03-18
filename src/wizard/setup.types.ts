import type { GatewayAuthChoice } from "../commands/onboard-types.js";
import type { DoxxnetTrafficScope } from "../config/types.gateway.js";
import type { SecretInput } from "../config/types.secrets.js";

export type WizardFlow = "quickstart" | "advanced";

export type QuickstartGatewayDefaults = {
  hasExisting: boolean;
  port: number;
  bind: "loopback" | "lan" | "auto" | "custom" | "tailnet" | "doxxnet";
  authMode: GatewayAuthChoice;
  tailscaleMode: "off" | "serve" | "funnel";
  token?: SecretInput;
  password?: SecretInput;
  customBindHost?: string;
  tailscaleResetOnExit: boolean;
  doxxnetMode?: "off" | "on";
  doxxnetScope?: DoxxnetTrafficScope;
  doxxnetResetOnExit?: boolean;
};

export type GatewayWizardSettings = {
  port: number;
  bind: "loopback" | "lan" | "auto" | "custom" | "tailnet" | "doxxnet";
  customBindHost?: string;
  authMode: GatewayAuthChoice;
  gatewayToken?: string;
  tailscaleMode: "off" | "serve" | "funnel";
  tailscaleResetOnExit: boolean;
  doxxnetMode: "off" | "on";
  doxxnetScope: DoxxnetTrafficScope;
  doxxnetResetOnExit: boolean;
};
