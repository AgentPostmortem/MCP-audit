import { describe, expect, it } from "vitest";
import { collectHeaders, parseArgs } from "../src/cli.js";

describe("HTTP headers", () => {
  it("collects every repeated --header flag", () => {
    const { flags } = parseArgs([
      "http",
      "https://example.com/mcp",
      "--header",
      "X-Tenant: acme",
      "--header",
      "X-Env: prod",
    ]);

    expect(collectHeaders(flags)).toEqual({
      "X-Tenant": "acme",
      "X-Env": "prod",
    });
  });

  it("preserves colons in header values", () => {
    const { flags } = parseArgs([
      "http",
      "https://example.com/mcp",
      "--header",
      "Authorization: Bearer a:b",
    ]);

    expect(collectHeaders(flags)).toEqual({ Authorization: "Bearer a:b" });
  });

  it("keeps last-wins behavior for repeated non-header flags", () => {
    const { flags } = parseArgs([
      "http",
      "https://example.com/mcp",
      "--config",
      "one.json",
      "--config",
      "two.json",
    ]);

    expect(flags.config).toBe("two.json");
  });
});
