import { describe, it, expect } from "vitest";
import { normalizeConfig, DEFAULT_CONFIG } from "../src/config.js";

describe("normalizeConfig", () => {
  it("returns defaults for an empty object", () => {
    expect(normalizeConfig({})).toEqual(DEFAULT_CONFIG);
  });

  it("merges rule toggles and thresholds", () => {
    const config = normalizeConfig({
      disabledRules: ["MCP012"],
      enabledRules: ["MCP001"],
      failOn: "critical",
      ignore: ["fetch_url"],
      severityOverrides: { MCP021: "high" },
    });
    expect(config.disabledRules).toEqual(["MCP012"]);
    expect(config.enabledRules).toEqual(["MCP001"]);
    expect(config.failOn).toBe("critical");
    expect(config.ignore).toEqual(["fetch_url"]);
    expect(config.severityOverrides.MCP021).toBe("high");
  });

  it("rejects an invalid failOn severity", () => {
    expect(() => normalizeConfig({ failOn: "catastrophic" })).toThrow(
      /Invalid severity/,
    );
  });

  it("rejects an invalid severity override", () => {
    expect(() =>
      normalizeConfig({ severityOverrides: { MCP001: "nope" } }),
    ).toThrow(/Invalid severity/);
  });

  it("overlays onto a provided base config", () => {
    const base = normalizeConfig({ disabledRules: ["A"], failOn: "medium" });
    const overlaid = normalizeConfig({ disabledRules: ["B"] }, base);
    expect(overlaid.disabledRules).toEqual(["B"]);
    expect(overlaid.failOn).toBe("medium");
  });
});
