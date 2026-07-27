/**
 * Public programmatic API for mcp-audit. Consumers can connect to a server or
 * load a manifest, then run the rule engine and render findings.
 */
export * from "./types.js";
export { Engine, exceedsThreshold } from "./engine/engine.js";
export type { AuditResult, EngineOptions } from "./engine/engine.js";
export { ALL_RULES, getRule } from "./rules/index.js";
export { runAudit, shouldFail, applyIgnores } from "./audit.js";
export {
  DEFAULT_CONFIG,
  loadConfig,
  normalizeConfig,
  findConfigFile,
} from "./config.js";
export type { McpAuditConfig } from "./config.js";
export { connectStdio, parseCommand } from "./transport/stdio.js";
export { connectHttp } from "./transport/http.js";
export { loadManifest, normalize as normalizeManifest } from "./static/manifest.js";
export { renderTerminal } from "./reporters/terminal.js";
export { renderJson } from "./reporters/json.js";
export { renderSarif } from "./reporters/sarif.js";
