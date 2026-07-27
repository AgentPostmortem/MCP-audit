import type { Finding, Rule } from "../types.js";
import { looksLikeUrlArg } from "./helpers.js";

/**
 * MCP040 - HTTP transport with no authentication. A network-reachable MCP
 * server with no auth lets anyone invoke its tools.
 */
export const httpNoAuth: Rule = {
  id: "MCP040",
  title: "HTTP transport has no authentication",
  description:
    "MCP servers reachable over HTTP must require authentication before exposing tools.",
  severity: "high",
  category: "transport",
  evaluate(target, ctx): Finding[] {
    if (target.transport !== "http") return [];
    if (target.connection.authProvided) return [];
    return [
      ctx.report({
        title: "No authentication on HTTP transport",
        message: `The server at ${target.connection.url ?? target.source} accepted a connection without any auth token or header.`,
        remediation:
          "Require a bearer token or OAuth. Reject unauthenticated requests before enumerating capabilities.",
        location: target.connection.url ?? target.source,
      }),
    ];
  },
};

/**
 * MCP041 - SSRF-prone URL argument on a network-capable server. A tool taking a
 * caller-controlled URL can be steered at internal metadata endpoints.
 */
export const ssrfUrlArg: Rule = {
  id: "MCP041",
  title: "Tool accepts a caller-controlled URL (SSRF risk)",
  description:
    "URL arguments that the server will fetch can be pointed at internal services and cloud metadata.",
  severity: "medium",
  category: "transport",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      const props = tool.inputSchema?.properties ?? {};
      for (const [name, schema] of Object.entries(props)) {
        if (!looksLikeUrlArg(name, schema)) continue;
        const constrained =
          schema.enum !== undefined || schema["pattern"] !== undefined;
        if (!constrained) {
          findings.push(
            ctx.report({
              title: "Potential SSRF via unconstrained URL argument",
              message: `Argument "${name}" of tool "${tool.name}" accepts an arbitrary URL the server may fetch, enabling SSRF.`,
              remediation:
                "Allowlist destination hosts/schemes, block private and link-local ranges (169.254.169.254, 10/8, 127/8), and constrain the argument with a pattern.",
              location: `${tool.name}.${name}`,
            }),
          );
        }
      }
    }
    return findings;
  },
};

export const transportRules: Rule[] = [httpNoAuth, ssrfUrlArg];
