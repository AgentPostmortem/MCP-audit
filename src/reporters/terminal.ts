import pc from "picocolors";
import type { AuditResult } from "../engine/engine.js";
import type { Severity } from "../types.js";
import { ALL_SEVERITIES } from "../types.js";

const SEV_ICON: Record<Severity, string> = {
  critical: "✖",
  high: "✖",
  medium: "▲",
  low: "●",
  info: "○",
};

/** Render a full audit result as colored, grouped terminal output. */
export function renderTerminal(
  result: AuditResult,
  options: { color?: boolean } = {},
): string {
  const useColor = options.color ?? pc.isColorSupported;
  const colors = pc.createColors(useColor);
  const severityLabel: Record<Severity, (s: string) => string> = {
    critical: (s) => colors.bgRed(colors.white(colors.bold(` ${s} `))),
    high: (s) => colors.red(colors.bold(s)),
    medium: (s) => colors.yellow(colors.bold(s)),
    low: (s) => colors.cyan(s),
    info: (s) => colors.gray(s),
  };
  const lines: string[] = [];
  const { target, findings, counts } = result;

  lines.push(
    colors.bold(`mcp-audit`) +
      colors.gray(` — ${target.transport} target `) +
      colors.underline(target.source),
  );
  const si = target.serverInfo;
  if (si.name || si.version) {
    lines.push(
      colors.gray(
        `server: ${si.name ?? "(unnamed)"} ${si.version ? `v${si.version}` : ""}`.trim(),
      ),
    );
  }
  lines.push(
    colors.gray(
      `surface: ${target.tools.length} tools, ${target.resources.length} resources, ${target.prompts.length} prompts`,
    ),
  );
  lines.push("");

  if (findings.length === 0) {
    lines.push(colors.green(colors.bold("✔ No findings. Clean audit.")));
    lines.push("");
    return lines.join("\n");
  }

  // Group by severity, highest first.
  for (const sev of [...ALL_SEVERITIES].reverse()) {
    const group = findings.filter((f) => f.severity === sev);
    if (group.length === 0) continue;
    lines.push(severityLabel[sev](sev.toUpperCase()) + colors.gray(`  (${group.length})`));
    for (const f of group) {
      lines.push(
        `  ${SEV_ICON[sev]} ${colors.bold(f.ruleId)} ${f.title}` +
          (f.location ? colors.gray(`  @ ${f.location}`) : ""),
      );
      lines.push(`      ${f.message}`);
      lines.push(colors.gray(`      fix: ${f.remediation}`));
    }
    lines.push("");
  }

  lines.push(renderSummary(counts, { color: useColor }));
  lines.push("");
  return lines.join("\n");
}

/** One-line summary of severity counts. */
export function renderSummary(
  counts: Record<Severity, number>,
  options: { color?: boolean } = {},
): string {
  const colors = pc.createColors(options.color ?? pc.isColorSupported);
  const severityLabel: Record<Severity, (s: string) => string> = {
    critical: (s) => colors.bgRed(colors.white(colors.bold(` ${s} `))),
    high: (s) => colors.red(colors.bold(s)),
    medium: (s) => colors.yellow(colors.bold(s)),
    low: (s) => colors.cyan(s),
    info: (s) => colors.gray(s),
  };
  const total = ALL_SEVERITIES.reduce((n, s) => n + counts[s], 0);
  const parts = [...ALL_SEVERITIES]
    .reverse()
    .filter((s) => counts[s] > 0)
    .map((s) => severityLabel[s](`${counts[s]} ${s}`));
  return colors.bold(`${total} finding${total === 1 ? "" : "s"}`) +
    (parts.length ? "  " + parts.join(colors.gray(", ")) : "");
}
