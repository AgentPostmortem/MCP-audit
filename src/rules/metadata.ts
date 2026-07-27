import type { Finding, Rule } from "../types.js";
import { containsAny } from "./helpers.js";

const LEAK_TERMS = [
  "internal",
  "localhost",
  "127.0.0.1",
  "todo",
  "fixme",
  "debug",
  "staging",
  "password",
  "api_key",
  "apikey",
  "token=",
  "secret",
];

/**
 * MCP050 - Server metadata / instructions leak internal details. The
 * `instructions` field is model-visible and sometimes carries internal hosts,
 * debug notes, or secrets.
 */
export const metadataLeak: Rule = {
  id: "MCP050",
  title: "Server metadata leaks internal information",
  description:
    "Server instructions and metadata are model-visible and should not contain internal hosts, debug notes, or secrets.",
  severity: "medium",
  category: "metadata",
  evaluate(target, ctx): Finding[] {
    const instructions = target.serverInfo.instructions;
    const hit = containsAny(instructions, LEAK_TERMS);
    if (!hit) return [];
    return [
      ctx.report({
        title: "Sensitive term in server instructions",
        message: `Server instructions contain "${hit}", which may leak internal details to the model.`,
        remediation:
          "Scrub server instructions of internal hostnames, debug notes, and any credential-like strings.",
        location: target.serverInfo.name ?? target.source,
      }),
    ];
  },
};

/**
 * MCP051 - Server does not report a version. Without a version, operators
 * cannot track which build is deployed or map it to advisories.
 */
export const missingServerVersion: Rule = {
  id: "MCP051",
  title: "Server does not report a version",
  description:
    "Servers should report a version string so deployments can be tracked against advisories.",
  severity: "info",
  category: "metadata",
  evaluate(target, ctx): Finding[] {
    if (target.serverInfo.version && target.serverInfo.version.trim() !== "") {
      return [];
    }
    return [
      ctx.report({
        title: "No server version reported",
        message: "The server did not report a version during initialization.",
        remediation:
          "Populate the server's version field so operators can identify the running build.",
        location: target.serverInfo.name ?? target.source,
      }),
    ];
  },
};

export const metadataRules: Rule[] = [metadataLeak, missingServerVersion];
