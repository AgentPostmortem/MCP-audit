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
    "MCP020", // injection phrase
    "MCP021", // overly broad
    "MCP030", // .env resource
    "MCP031", // path traversal
    "MCP041", // SSRF url
    "MCP062", // undocumented tool
  ]) {
    it(`fires ${expected}`, () => {
      expect(ids.has(expected)).toBe(true);
    });
  }
});

describe("MCP002 exec detection", () => {
  it("flags a shell tool as critical", () => {
    const target = makeTarget({
      tools: [{ name: "run_command", description: "runs a command" }],
    });
    const findings = audit(target).findings.filter((f) => f.ruleId === "MCP002");
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
  });

  it("does not flag a benign read tool", () => {
    const target = makeTarget({
      tools: [
        {
          name: "get_weather",
          description: "returns weather",
          inputSchema: {
            type: "object",
            properties: { city: { type: "string", enum: ["london"] } },
            required: ["city"],
            additionalProperties: false,
          },
        },
      ],
    });
    expect(idsFor(target).has("MCP002")).toBe(false);
  });
});

describe("MCP040 http auth", () => {
  it("flags http transport without auth", () => {
    const target = makeTarget({
      transport: "http",
      connection: { url: "http://x", authProvided: false },
    });
    expect(idsFor(target).has("MCP040")).toBe(true);
  });
  it("passes when auth is provided", () => {
    const target = makeTarget({
      transport: "http",
      connection: { url: "http://x", authProvided: true },
    });
    expect(idsFor(target).has("MCP040")).toBe(false);
  });
});

describe("MCP030 resource secrets", () => {
  it("does not flag generic credentials wording in a description", () => {
    const target = makeTarget({
      resources: [
        {
          uri: "https://example.com/notes",
          name: "Project notes",
          description: "Project notes. Contains no credentials or secrets.",
        },
      ],
    });
    const findings = audit(target).findings.filter(
      (f) => f.ruleId === "MCP030",
    );
    expect(findings).toHaveLength(0);
  });

  it("reports URI evidence as critical and prose evidence as high", () => {
    const target = makeTarget({
      resources: [
        {
          uri: "file:///home/me/.env",
          name: "Environment backup",
          description: "Local environment backup",
        },
        {
          uri: "https://example.com/resource",
          name: "server.pem",
          description: "TLS certificate material",
        },
      ],
    });
    const findings = audit(target).findings.filter(
      (f) => f.ruleId === "MCP030",
    );
    expect(findings).toHaveLength(2);
    expect(findings.some((f) => f.severity === "critical")).toBe(true);
    expect(findings.some((f) => f.severity === "high")).toBe(true);
  });
});

describe("MCP060 tool name collision", () => {
  it("detects duplicate tool names", () => {
    const target = makeTarget({
      tools: [
        { name: "dup", description: "a" },
        { name: "dup", description: "b" },
      ],
    });
    expect(idsFor(target).has("MCP060")).toBe(true);
  });
});

describe("MCP061 capability sprawl", () => {
  it("fires when tool count exceeds the threshold", () => {
    const tools = Array.from({ length: 45 }, (_, i) => ({
      name: `t${i}`,
      description: "documented tool",
      inputSchema: {
        type: "object",
        properties: { a: { type: "string", enum: ["x"] } },
        required: ["a"],
        additionalProperties: false as const,
      },
    }));
    expect(idsFor(makeTarget({ tools })).has("MCP061")).toBe(true);
  });
});

describe("clean target", () => {
  it("produces no high or critical findings", () => {
    const target = makeTarget({
      serverInfo: { name: "clean", version: "1.0.0" },
      tools: [
        {
          name: "get_weather",
          description: "Returns the weather for a supported city.",
          inputSchema: {
            type: "object",
            properties: { city: { type: "string", enum: ["london"] } },
            required: ["city"],
            additionalProperties: false,
          },
        },
      ],
    });
    const { counts } = audit(target);
    expect(counts.critical).toBe(0);
    expect(counts.high).toBe(0);
  });
});
