import type { AuditResult } from "../engine/engine.js";

/** Serialize an audit result as a stable, machine-readable JSON document. */
export function renderJson(result: AuditResult): string {
  const doc = {
    tool: "mcp-audit",
    version: "0.1.0",
    target: {
      transport: result.target.transport,
      source: result.target.source,
      server: result.target.serverInfo,
      counts: {
        tools: result.target.tools.length,
        resources: result.target.resources.length,
        prompts: result.target.prompts.length,
      },
    },
    summary: result.counts,
    rulesRun: result.rulesRun,
    findings: result.findings,
  };
  return JSON.stringify(doc, null, 2);
}
