import type { AuditTarget } from "../src/types.js";

/** Build a minimal target, overriding only the fields a test cares about. */
export function makeTarget(partial: Partial<AuditTarget> = {}): AuditTarget {
  return {
    transport: "static",
    source: "test",
    serverInfo: { name: "t", version: "1.0.0" },
    tools: [],
    resources: [],
    prompts: [],
    connection: {},
    ...partial,
  };
}
