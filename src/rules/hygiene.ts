import type { Finding, Rule } from "../types.js";

/** Default threshold above which tool count is considered capability sprawl. */
const SPRAWL_THRESHOLD = 40;

/**
 * MCP060 - Tool name collision. Duplicate tool names make dispatch ambiguous
 * and can let a malicious tool shadow a trusted one.
 */
export const toolNameCollision: Rule = {
  id: "MCP060",
  title: "Duplicate tool names",
  description:
    "Tool names must be unique; collisions make invocation ambiguous and enable shadowing.",
  severity: "high",
  category: "hygiene",
  evaluate(target, ctx): Finding[] {
    const seen = new Map<string, number>();
    for (const tool of target.tools) {
      seen.set(tool.name, (seen.get(tool.name) ?? 0) + 1);
    }
    const findings: Finding[] = [];
    for (const [name, count] of seen) {
      if (count > 1) {
        findings.push(
          ctx.report({
            title: "Duplicate tool name",
            message: `Tool name "${name}" is declared ${count} times; invocations are ambiguous and one tool may shadow another.`,
            remediation:
              "Give every tool a unique name, namespacing where necessary.",
            location: name,
          }),
        );
      }
    }
    return findings;
  },
};

/**
 * MCP061 - Capability sprawl. A very large tool surface increases attack
 * surface and dilutes the model's ability to choose safely.
 */
export const capabilitySprawl: Rule = {
  id: "MCP061",
  title: "Excessive number of tools",
  description:
    "A large tool count widens the attack surface and degrades safe tool selection.",
  severity: "low",
  category: "hygiene",
  evaluate(target, ctx): Finding[] {
    if (target.tools.length <= SPRAWL_THRESHOLD) return [];
    return [
      ctx.report({
        title: "Capability sprawl",
        message: `Server exposes ${target.tools.length} tools (threshold ${SPRAWL_THRESHOLD}); this is a large attack surface.`,
        remediation:
          "Split responsibilities across focused servers and expose only the tools each client needs.",
        location: target.serverInfo.name ?? target.source,
      }),
    ];
  },
};

/**
 * MCP062 - Missing tool descriptions. An undocumented tool cannot be reviewed
 * and gives the model no basis for safe use.
 */
export const missingToolDescription: Rule = {
  id: "MCP062",
  title: "Tool has no description",
  description:
    "Every tool should document what it does so it can be reviewed and used safely.",
  severity: "info",
  category: "hygiene",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      if (!tool.description || tool.description.trim() === "") {
        findings.push(
          ctx.report({
            title: "Undocumented tool",
            message: `Tool "${tool.name}" has no description.`,
            remediation:
              "Add a concise, accurate description documenting the tool's behaviour and scope.",
            location: tool.name,
          }),
        );
      }
    }
    return findings;
  },
};

export const hygieneRules: Rule[] = [
  toolNameCollision,
  capabilitySprawl,
  missingToolDescription,
];
