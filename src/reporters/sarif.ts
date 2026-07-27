import type { AuditResult } from "../engine/engine.js";
import type { Rule, Severity } from "../types.js";

/** Map mcp-audit severities to SARIF result levels. */
function sarifLevel(sev: Severity): "error" | "warning" | "note" {
  switch (sev) {
    case "critical":
    case "high":
      return "error";
    case "medium":
    case "low":
      return "warning";
    default:
      return "note";
  }
}

/** SARIF security-severity score (0-10) for GitHub code scanning. */
function securityScore(sev: Severity): string {
  switch (sev) {
    case "critical":
      return "9.5";
    case "high":
      return "8.0";
    case "medium":
      return "5.5";
    case "low":
      return "3.0";
    default:
      return "1.0";
  }
}

/**
 * Render an audit result as a SARIF 2.1.0 document suitable for upload to
 * GitHub code scanning. Every built-in rule is declared once; findings become
 * results referencing those rules.
 */
export function renderSarif(result: AuditResult, rules: Rule[]): string {
  const usedRuleIds = new Set(result.findings.map((f) => f.ruleId));
  const ruleDescriptors = rules
    .filter((r) => usedRuleIds.has(r.id))
    .map((r) => ({
      id: r.id,
      name: r.title.replace(/\s+/g, ""),
      shortDescription: { text: r.title },
      fullDescription: { text: r.description },
      defaultConfiguration: { level: sarifLevel(r.severity) },
      properties: {
        category: r.category,
        "security-severity": securityScore(r.severity),
        tags: ["security", "mcp", r.category],
      },
    }));

  const results = result.findings.map((f) => ({
    ruleId: f.ruleId,
    level: sarifLevel(f.severity),
    message: { text: `${f.message} Remediation: ${f.remediation}` },
    properties: { "security-severity": securityScore(f.severity) },
    locations: [
      {
        logicalLocations: [
          {
            name: f.location ?? result.target.source,
            fullyQualifiedName: f.location ?? result.target.source,
          },
        ],
      },
    ],
  }));

  const doc = {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "mcp-audit",
            informationUri: "https://github.com/royalpinto007/mcp-audit",
            version: "0.1.0",
            rules: ruleDescriptors,
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(doc, null, 2);
}
