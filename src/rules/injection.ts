import type { Finding, Rule } from "../types.js";
import { containsAny, INJECTION_PHRASES } from "./helpers.js";

const VAGUE_TERMS = [
  "anything",
  "any file",
  "any command",
  "arbitrary",
  "everything",
  "all files",
  "unrestricted",
  "full access",
  "whatever",
];

/**
 * MCP020 - Tool or prompt description contains probable prompt-injection sinks.
 * Tool descriptions are fed to the model verbatim, so imperative phrases inside
 * them can hijack the model's behaviour.
 */
export const injectionInDescription: Rule = {
  id: "MCP020",
  title: "Description contains probable prompt-injection text",
  description:
    "Tool and prompt descriptions are model-visible; imperative phrasing can be used to hijack the agent.",
  severity: "high",
  category: "injection",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    const scan = (label: string, name: string, text?: string) => {
      const hit = containsAny(text, INJECTION_PHRASES);
      if (hit) {
        findings.push(
          ctx.report({
            title: "Injection-style phrasing in description",
            message: `${label} "${name}" description contains the phrase "${hit}", a common prompt-injection pattern.`,
            remediation:
              "Rewrite the description as neutral documentation. Never place directives (\"ignore previous\", \"you must\") in model-visible metadata.",
            location: name,
          }),
        );
      }
    };
    for (const tool of target.tools) scan("Tool", tool.name, tool.description);
    for (const prompt of target.prompts)
      scan("Prompt", prompt.name, prompt.description);
    return findings;
  },
};

/**
 * MCP021 - Overly broad tool description. Descriptions that advertise
 * "anything"/"arbitrary" access signal an over-permissioned capability.
 */
export const overlyBroadDescription: Rule = {
  id: "MCP021",
  title: "Tool advertises overly broad capability",
  description:
    "Descriptions promising arbitrary or unrestricted access indicate an over-scoped tool.",
  severity: "medium",
  category: "injection",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      const hit = containsAny(tool.description, VAGUE_TERMS);
      if (hit) {
        findings.push(
          ctx.report({
            title: "Overly broad capability description",
            message: `Tool "${tool.name}" describes itself with "${hit}", implying an unbounded scope.`,
            remediation:
              "Narrow the tool to a specific, documented capability and reflect that scope in the description.",
            location: tool.name,
          }),
        );
      }
    }
    return findings;
  },
};

export const injectionRules: Rule[] = [
  injectionInDescription,
  overlyBroadDescription,
];
