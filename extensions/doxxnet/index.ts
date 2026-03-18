import { definePluginEntry } from "openclaw/plugin-sdk/core";

export default definePluginEntry({
  id: "doxxnet",
  name: "doxxnet",
  description: "doxxnet VPN management skills for OpenClaw agents.",
  register(_api) {
    // Skills are auto-discovered from skills/doxxnet/SKILL.md.
  },
});
