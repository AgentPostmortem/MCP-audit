import pc from "picocolors";
import type { AuditResult } from "../engine/engine.js";
import type { Severity } from "../types.js";
import { ALL_SEVERITIES } from "../types.js";

const SEV_LABEL: Record<Severity, (s: string) => string> = {
  critical: (s) => pc.bgRed(pc.white(pc.bold(` ${s} `))),
  high: (s) => pc.red(pc.bold(s)),
  medium: (s) => pc.yellow(pc.bold(s)),
  low: (s) => pc.cyan(s),
  info: (s) => pc.gray(s),
};

const SEV_ICON: Record<Severity, string> = {
  critical: "✖",
  high: "✖",
  medium: "▲",
  low: "●",
  info: "○",
};

function severityTag(sev: Severity): string {
  return SEV_LABEL[sev](sev.toUpperCase());
}

/** Render a full audit result as colored, grouped terminal output. */
export function renderTerminal(
  result: AuditResult,
  options: { color?: boolean } = {},
): string {
  const useColor = options.color ?? true;
  if (!useColor) {
    // picocolors respects NO_COLOR, but honor an explicit override too.
    process.env.NO_COLOR = "1";
  }
  const lines: string[] = [];
  const { target, findings, counts } = result;

  lines.push(
    pc.bold(`mcp-audit`) +
      pc.gray(` — ${target.transport} target `) +
      pc.underline(target.source),
  );
  const si = target.serverInfo;
  if (si.name || si.version) {
    lines.push(
      pc.gray(
        `server: ${si.name ?? "(unnamed)"} ${si.version ? `v${si.version}` : ""}`.trim(),
      ),
    );
  }
  lines.push(
    pc.gray(
      `surface: ${target.tools.length} tools, ${target.resources.length} resources, ${target.prompts.length} prompts`,
    ),
  );
  lines.push("");

  if (findings.length === 0) {
    lines.push(pc.green(pc.bold("✔ No findings. Clean audit.")));
    lines.push("");
    return lines.join("\n");
  }

  // Group by severity, highest first.
  for (const sev of [...ALL_SEVERITIES].reverse()) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    lines.push(severityTag(sev) + pc.gray(`  (${group.length})`));
    for (const f of group) {
      lines.push(
        `  ${SEV_ICON[sev]} ${pc.bold(f.ruleId)} ${f.title}` +
          (f.location ? pc.gray(`  @ ${f.location}`) : ""),
      );
      lines.push(`      ${f.message}`);
      lines.push(pc.gray(`      fix: ${f.remediation}`));
    }
    lines.push("");
  }

  lines.push(renderSummary(counts));
  lines.push("");
  return lines.join("\n");
}

/** One-line summary of severity counts. */
export function renderSummary(counts: Record<Severity, number>): string {
  const total = ALL_SEVERITIES.reduce((n, s) => n + counts[s], 0);
  const parts = [...ALL_SEVERITIES]
    .reverse()
    .filter((s) => counts[s] > 0)
    .map((s) => SEV_LABEL[s](`${counts[s]} ${s}`));
  return pc.bold(`${total} finding${total === 1 ? "" : "s"}`) +
    (parts.length ? "  " + parts.join(pc.gray(", ")) : "");
}
