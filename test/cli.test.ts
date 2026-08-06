import { describe, expect, it } from "vitest";
import { main } from "../src/cli.js";

describe("cli", () => {
  it("prints the version and exits 0 for --version", async () => {
    expect(await main(["--version"])).toBe(0);
  });

  it("prints usage and exits 2 with no command", async () => {
    expect(await main([])).toBe(2);
  });

  it("prints usage and exits 0 for --help", async () => {
    expect(await main(["--help"])).toBe(0);
  });
});
