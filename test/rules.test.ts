import { describe, it, expect } from "vitest";
import { ALL_RULES } from "../src/rules/index.js";
import { runAudit } from "../src/audit.js";
import { DEFAULT_CONFIG } from "../src/config.js";
import { normalize } from "../src/static/manifest.js";
import { makeTarget } from "./helpers.js";
import type { AuditTarget } from "../src/types.js";
// The mock server surfaces are the single source of truth for fixtures.
import { insecureSurface } from "../fixtures/surfaces.mjs";

function audit(target: AuditTarget) {
  return runAudit(target, DEFAULT_CONFIG, ALL_RULES);
}

function idsFor(target: AuditTarget): Set<string> {
  return new Set(audit(target).findings.map((f) => f.ruleId));
}

describe("rule catalog", () => {
  it("has unique ids and at least 15 rules", () => {
    const ids = ALL_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect(ALL_RULES.length).toBeGreaterThanOrEqual(15);
  });

  it("every rule declares required metadata", () => {
    for (const r of ALL_RULES) {
      expect(r.id).toMatch(/^MCP\d{3}$/);
      expect(r.title.length).toBeGreaterThan(0);
      expect(r.remediation ?? "ok").toBeTruthy();
    }
  });
});

describe("rules against the insecure surface", () => {
  const target = normalize(insecureSurface, "insecure");
  const ids = idsFor(target);

  for (const expected of [
    "MCP001", // destructive delete_file
    "MCP002", // exec run_shell
    "MCP003", // unscoped write_record
    "MCP010", // no schema
    "MCP011", // additionalProperties
    "MCP012", // unconstrained string
    "MCP014", // unbounded numeric
    "MCP020", // injection phrase
    "MCP021", // overly broad
    "MCP030", // .env resource
    "MCP031", // path traversal
    "MCP032", // secret in schema defaults
    "MCP041", // SSRF url
    "MCP062", // undocumented tool
  ]) {
    it(`fires ${expected}`, () => {
      expect(ids.has(expected)).toBe(true);
    });
  }
});

describe("MCP032 secret in schema defaults", () => {
  function findingsFor(tools: AuditTarget["tools"]) {
    return audit(makeTarget({ tools })).findings.filter((f) => f.ruleId === "MCP032");
  }

  it("fires when api_key has a hardcoded secret default", () => {
    const findings = findingsFor([
      {
        name: "test_tool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: {
            api_key: { type: "string", default: "sk-live-1234567890abcdefghijkl" },
          },
        },
      },
    ]);
    expect(findings.length).toBe(1);
    expect(findings[0].location).toBe("test_tool.api_key");
  });

  it("does not fire for empty string or absent defaults", () => {
    const findings = findingsFor([
      {
        name: "test_tool",
        description: "A test tool",
        inputSchema: {
          type: "object",
          properties: {
            api_key: { type: "string", default: "" },
            other: { type: "string" },
          },
        },
      },
    ]);
    expect(findings.length).toBe(0);
  });
});
