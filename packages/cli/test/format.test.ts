import { describe, expect, it } from "vitest";
import {
  analyzeSession,
  riskyManifest,
  riskyPolicy,
  safeManifest,
  safePolicy,
} from "@taintweave/core";
import { formatAnalysis, formatDot, formatManifest } from "../src/format.js";

describe("CLI formatting", () => {
  it("summarizes the session manifest", () => {
    const output = formatManifest(riskyManifest);
    expect(output).toContain("5 servers");
    expect(output).toContain("vault");
  });

  it("renders risk paths", async () => {
    const analysis = await analyzeSession({ manifest: riskyManifest, policy: riskyPolicy });
    const output = formatAnalysis(analysis);
    expect(output).toContain("SESSION-LETHAL-TRIFECTA");
    expect(output).toContain("vault/read_secret");
  });

  it("renders a safe result", async () => {
    const analysis = await analyzeSession({ manifest: safeManifest, policy: safePolicy });
    expect(formatAnalysis(analysis)).toContain("No forbidden information-flow");
  });

  it("exports Graphviz DOT", async () => {
    const analysis = await analyzeSession({ manifest: safeManifest, policy: safePolicy });
    const dot = formatDot(analysis);
    expect(dot).toContain("digraph TaintWeave");
    expect(dot).toContain("\"web/search_public_docs\" -> \"local/sanitize_text\"");
  });
});
