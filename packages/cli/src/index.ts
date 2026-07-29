#!/usr/bin/env node
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import {
  analyzeSession,
  compileFlowReceipt,
  riskyManifest,
  riskyPolicy,
  safeManifest,
  safePolicy,
  verifyFlowReceipt,
} from "@taintweave/core";
import type {
  FlowReceipt,
  SessionManifest,
} from "@taintweave/core";
import { formatAnalysis, formatDot, formatManifest } from "./format.js";

const help = `TaintWeave — cross-server information-flow compiler for MCP sessions

Usage:
  taint-weave inspect <manifest.json> [--json]
  taint-weave analyze <manifest.json> --policy <policy.json> [--at <ISO date>] [--json]
  taint-weave graph <manifest.json> --policy <policy.json> [--dot]
  taint-weave explain <manifest.json> --policy <policy.json> --finding <id> [--at <ISO date>]
  taint-weave cuts <manifest.json> --policy <policy.json> [--at <ISO date>]
  taint-weave receipt <manifest.json> --policy <policy.json> --output <receipt.json> [--at <ISO date>]
  taint-weave verify <receipt.json> [--manifest <json>] [--policy <json>]
  taint-weave demo [safe|risky] [--json]
  taint-weave init [directory]

Exit codes: 0 safe/valid, 2 blocked, 3 review required, 5 invalid input.`;

const option = (args: string[], name: string): string | undefined => {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : undefined;
};
const text = async (path: string): Promise<string> => readFile(resolve(path), "utf8");
const json = async (path: string): Promise<unknown> => JSON.parse(await text(path)) as unknown;
const outputJson = (value: unknown): void => {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
};
const dateOption = (args: string[]): Date => {
  const raw = option(args, "--at");
  if (!raw) return new Date();
  const date = new Date(raw);
  if (!Number.isFinite(date.getTime())) throw new Error(`Invalid --at date: ${raw}`);
  return date;
};
const writeJson = async (path: string, value: unknown): Promise<void> => {
  await mkdir(dirname(resolve(path)), { recursive: true });
  await writeFile(resolve(path), `${JSON.stringify(value, null, 2)}\n`, "utf8");
};
const analysisInput = async (manifestPath: string, args: string[]) => {
  const policyPath = option(args, "--policy");
  if (!policyPath) throw new Error("Command requires --policy <policy.json>.");
  const manifest = await json(manifestPath);
  const policy = await json(policyPath);
  const analysis = await analyzeSession({ manifest, policy, analyzedAt: dateOption(args) });
  return { manifest, policy, analysis };
};
const statusCode = (status: "safe" | "review" | "blocked"): number =>
  status === "safe" ? 0 : status === "blocked" ? 2 : 3;

async function run(args: string[]): Promise<number> {
  const [command, first] = args;
  if (!command || ["help", "--help", "-h"].includes(command)) {
    console.log(help);
    return 0;
  }
  if (command === "inspect") {
    if (!first || first.startsWith("--")) throw new Error("inspect requires a manifest.");
    const manifest = await json(first) as SessionManifest;
    if (args.includes("--json")) outputJson(manifest);
    else console.log(formatManifest(manifest));
    return 0;
  }
  if (["analyze", "graph", "explain", "cuts", "receipt"].includes(command)) {
    if (!first || first.startsWith("--")) throw new Error(`${command} requires a manifest.`);
    const input = await analysisInput(first, args);
    if (command === "analyze") {
      if (args.includes("--json")) outputJson(input.analysis);
      else console.log(formatAnalysis(input.analysis));
    }
    if (command === "graph") {
      if (args.includes("--dot")) console.log(formatDot(input.analysis));
      else outputJson(input.analysis.graph);
    }
    if (command === "explain") {
      const id = option(args, "--finding");
      if (!id) throw new Error("explain requires --finding <id>.");
      const found = input.analysis.findings.find((item) => item.id === id);
      if (!found) throw new Error(`Unknown finding: ${id}`);
      outputJson(found);
    }
    if (command === "cuts") {
      const cuts = [...new Set(input.analysis.findings.flatMap((item) => item.remediation))];
      outputJson({ status: input.analysis.status, cuts });
    }
    if (command === "receipt") {
      const target = option(args, "--output");
      if (!target) throw new Error("receipt requires --output <receipt.json>.");
      const receipt = await compileFlowReceipt({ ...input, issuedAt: dateOption(args) });
      await writeJson(target, receipt);
      console.log(`Flow receipt: ${resolve(target)}`);
    }
    return statusCode(input.analysis.status);
  }
  if (command === "verify") {
    if (!first || first.startsWith("--")) throw new Error("verify requires a receipt.");
    const manifestPath = option(args, "--manifest");
    const policyPath = option(args, "--policy");
    const result = await verifyFlowReceipt({
      receipt: await json(first) as FlowReceipt,
      ...(manifestPath ? { manifest: await json(manifestPath) } : {}),
      ...(policyPath ? { policy: await json(policyPath) } : {}),
    });
    outputJson(result);
    return result.valid ? 0 : 2;
  }
  if (command === "demo") {
    const safe = first === "safe";
    const analysis = await analyzeSession({
      manifest: safe ? safeManifest : riskyManifest,
      policy: safe ? safePolicy : riskyPolicy,
      analyzedAt: dateOption(args),
    });
    if (args.includes("--json")) outputJson(analysis);
    else console.log(formatAnalysis(analysis));
    return statusCode(analysis.status);
  }
  if (command === "init") {
    const directory = resolve(first ?? ".taint-weave");
    await mkdir(directory, { recursive: true });
    await writeJson(resolve(directory, "session.json"), riskyManifest);
    await writeJson(resolve(directory, "policy.json"), riskyPolicy);
    console.log(`Created starter files in ${directory}`);
    return 0;
  }
  throw new Error(`Unknown command: ${command}\n\n${help}`);
}

run(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    console.error(`TaintWeave error: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 5;
  });
