import type { JsonSchema, ToolSpec } from "../types.js";

/** Words that strongly imply a destructive or state-changing action. */
export const DESTRUCTIVE_VERBS = [
  "delete",
  "remove",
  "destroy",
  "drop",
  "truncate",
  "wipe",
  "erase",
  "purge",
  "overwrite",
  "reset",
  "revoke",
  "kill",
  "terminate",
  "shutdown",
];

/** Words implying arbitrary code / command execution. */
export const EXEC_VERBS = [
  "exec",
  "execute",
  "spawn",
  "shell",
  "bash",
  "sh ",
  "command",
  "eval",
  "run_command",
  "system",
  "subprocess",
];

/** Words implying writing/mutating persistent state. */
export const WRITE_VERBS = [
  "write",
  "update",
  "create",
  "modify",
  "patch",
  "insert",
  "upload",
  "put",
  "set",
];

/** Phrases frequently used to smuggle prompt-injection instructions. */
export const INJECTION_PHRASES = [
  "ignore previous",
  "ignore all previous",
  "disregard",
  "you must",
  "always call",
  "do not tell",
  "without asking",
  "without confirmation",
  "system prompt",
  "override",
  "regardless of",
  "no matter what",
  "instead of",
];

/** Substrings that indicate a sensitive filesystem path or secret material. */
export const SECRET_PATH_PATTERNS = [
  ".env",
  "id_rsa",
  "id_ed25519",
  ".ssh",
  ".pem",
  ".key",
  "private_key",
  "credentials",
  "secrets",
  "/etc/passwd",
  "/etc/shadow",
  ".aws",
  ".npmrc",
  ".git/config",
  ".dockercfg",
  ".kube/config",
];

/** Case-insensitive "does haystack contain any needle". */
export function containsAny(
  haystack: string | undefined,
  needles: string[],
): string | undefined {
  if (!haystack) return undefined;
  const lower = haystack.toLowerCase();
  return needles.find((n) => lower.includes(n));
}

/** Collect the property names of a tool's input schema. */
export function schemaProperties(tool: ToolSpec): string[] {
  const props = tool.inputSchema?.properties;
  return props ? Object.keys(props) : [];
}

/** Walk a JSON schema, yielding every nested schema node (including root). */
export function walkSchema(
  schema: JsonSchema | undefined,
  visit: (node: JsonSchema, path: string) => void,
  path = "$",
): void {
  if (!schema || typeof schema !== "object") return;
  visit(schema, path);
  if (schema.properties) {
    for (const [key, child] of Object.entries(schema.properties)) {
      walkSchema(child, visit, `${path}.${key}`);
    }
  }
  if (schema.items) {
    if (Array.isArray(schema.items)) {
      schema.items.forEach((child, i) =>
        walkSchema(child, visit, `${path}[${i}]`),
      );
    } else {
      walkSchema(schema.items, visit, `${path}[]`);
    }
  }
  if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
    walkSchema(schema.additionalProperties, visit, `${path}.*`);
  }
}

/** Heuristic: does a property look like it holds a URL/endpoint? */
export function looksLikeUrlArg(name: string, schema?: JsonSchema): boolean {
  const n = name.toLowerCase();
  if (/(url|uri|endpoint|host|webhook|callback|link|href)/.test(n)) return true;
  const fmt = schema?.["format"];
  return fmt === "uri" || fmt === "url";
}
