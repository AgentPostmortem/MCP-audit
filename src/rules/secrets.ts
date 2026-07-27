import type { Finding, Rule } from "../types.js";
import { containsAny, SECRET_PATH_PATTERNS } from "./helpers.js";

const PATH_ARG_NAMES = ["path", "file", "filename", "filepath", "dir", "directory", "location"];

/**
 * MCP030 - A resource points at secret material or a sensitive system path.
 * Exposing `.env`, private keys, or `/etc/*` as MCP resources leaks credentials
 * straight into the model context.
 */
export const resourceExposesSecrets: Rule = {
  id: "MCP030",
  title: "Resource exposes secrets or sensitive paths",
  description:
    "Resources should never surface credential files, private keys, or sensitive system paths.",
  severity: "critical",
  category: "secrets",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const res of target.resources) {
      const haystack = `${res.uri} ${res.name ?? ""} ${res.description ?? ""}`;
      const hit = containsAny(haystack, SECRET_PATH_PATTERNS);
      if (hit) {
        findings.push(
          ctx.report({
            title: "Resource surfaces sensitive material",
            message: `Resource "${res.uri}" references "${hit}", which commonly holds secrets or system credentials.`,
            remediation:
              "Remove the resource or restrict it to non-sensitive content. Never expose credential files or system paths over MCP.",
            location: res.uri,
          }),
        );
      }
    }
    return findings;
  },
};

/**
 * MCP031 - A path/file argument with no constraints invites path traversal.
 * Without a pattern or enum, the model can supply `../../etc/passwd`.
 */
export const pathTraversalArg: Rule = {
  id: "MCP031",
  title: "Path argument is vulnerable to traversal",
  description:
    "File/path arguments should constrain their values to prevent directory traversal.",
  severity: "high",
  category: "secrets",
  evaluate(target, ctx): Finding[] {
    const findings: Finding[] = [];
    for (const tool of target.tools) {
      const props = tool.inputSchema?.properties ?? {};
      for (const [name, schema] of Object.entries(props)) {
        const isPathArg = PATH_ARG_NAMES.some((p) =>
          name.toLowerCase().includes(p),
        );
        if (!isPathArg || schema.type !== "string") continue;
        const constrained =
          schema["pattern"] !== undefined || schema.enum !== undefined;
        if (!constrained) {
          findings.push(
            ctx.report({
              title: "Unconstrained filesystem path argument",
              message: `Argument "${name}" of tool "${tool.name}" accepts an unconstrained path and may allow traversal (e.g. "../../etc/passwd").`,
              remediation:
                "Constrain the argument with a pattern, resolve and validate the path against an allowed root, and reject `..` segments.",
              location: `${tool.name}.${name}`,
            }),
          );
        }
      }
    }
    return findings;
  },
};

export const secretRules: Rule[] = [resourceExposesSecrets, pathTraversalArg];
