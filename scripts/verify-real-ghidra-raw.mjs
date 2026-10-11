import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

import { parseEvidence } from "../dist/domain/evidence.js";
import { inspectGhidraInstallation } from "../dist/ghidra/GhidraInstallation.js";
import { requireMcpOperationResult } from "./lib/mcp-verifier-results.mjs";
import { createVerifierRun, completeVerifierRun } from "./lib/verifier-run.mjs";

if (process.argv.length !== 2)
  throw new Error("Usage: node scripts/verify-real-ghidra-raw.mjs");
if (!["linux", "darwin"].includes(process.platform))
  throw new Error(
    "Raw-binary verification requires a Linux or macOS Ghidra host.",
  );
if (process.env.GHIDRA_INSTALL_DIR === undefined)
  throw new Error(
    "Set GHIDRA_INSTALL_DIR to a bring-your-own Ghidra installation.",
  );
const installation = inspectGhidraInstallation({
  environment: process.env,
  installDir: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { javaHome: process.env.JAVA_HOME }),
});
assert.equal(installation.status, "available", JSON.stringify(installation));

const run = createVerifierRun();
const workspace = await mkdtemp(join(tmpdir(), "rea-raw-proof-"));
const runtime = join(workspace, "runtime");
await mkdir(runtime);
const bytes = Buffer.from("1eff2fe1", "hex"); // ARM little-endian bx lr.
const sha256 = createHash("sha256").update(bytes).digest("hex");
const path = join(workspace, "image.bin");
await writeFile(path, bytes);
const entrypoint = fileURLToPath(new URL("./rea.mjs", import.meta.url));
const env = {
  PATH: process.env.PATH ?? "/usr/bin:/bin",
  TMPDIR: runtime,
  REA_LOG_LEVEL: "silent",
  REA_ANALYSIS_PROVIDER: "ghidra",
  REA_PROCESS_RUN_ID: run.run_id,
  GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR,
  ...(process.env.JAVA_HOME === undefined
    ? {}
    : { JAVA_HOME: process.env.JAVA_HOME }),
  ...(process.env.GHIDRA_HEADLESS_MAXMEM === undefined
    ? {}
    : { GHIDRA_HEADLESS_MAXMEM: process.env.GHIDRA_HEADLESS_MAXMEM }),
  ...(process.env.REA_GHIDRA_DISABLED_ANALYZERS === undefined
    ? {}
    : {
        REA_GHIDRA_DISABLED_ANALYZERS:
          process.env.REA_GHIDRA_DISABLED_ANALYZERS,
      }),
};
const transport = new StdioClientTransport({
  command: process.execPath,
  args: [entrypoint, "mcp"],
  env,
  stderr: "pipe",
});
const client = new Client({ name: "rea-real-raw-proof", version: "1" });
let stderr = "";
transport.stderr?.on("data", (chunk) => {
  stderr = (stderr + chunk.toString()).slice(-65536);
});
let report;
try {
  await client.connect(transport);
  const profiles = [];
  const sessions = [];
  for (const entryPoint of ["0x08000000", "0x8000000", "0x09000000"]) {
    // Omit provider_id to exercise reuse of the current provider route.
    const opened = await call("open_binary", {
      path,
      format: "raw-binary",
      architecture: "arm",
      entry_point: entryPoint,
    });
    const entry = `0x${BigInt(entryPoint).toString(16)}`;
    assert.equal(opened.entry_point, entry);
    const image = await call("inspect_native_load_image");
    assert.equal(
      image.normalized_result.status,
      "verified",
      JSON.stringify(image),
    );
    assert.equal(image.normalized_result.base_address, entry);
    assert.equal(image.normalized_result.entry.address, entry);
    assert.equal(
      image.normalized_result.observations.language_id,
      "ARM:LE:32:v7",
    );
    assert.ok(
      image.normalized_result.observations.entry_points.includes(entry),
    );
    assert.equal(image.analysis_profile.parameters.entry_point, entry);
    profiles.push(image.analysis_profile.digest);
    const status = await call("binary_session");
    assert.equal(status.entry_point, entry);
    sessions.push(status.analysis_run.run_id);
    const memory = await call("read_bytes", {
      address: entry,
      length: bytes.length,
    });
    assert.equal(memory.normalized_result.bytes_hex, bytes.toString("hex"));
    const procedures = await call("list_procedures");
    assert.ok(
      procedures.normalized_result.some(
        (procedure) => procedure.address === entry,
      ),
    );
    const instruction = await call("inspect_native_instruction", {
      address: entry,
    });
    assert.equal(instruction.normalized_result.address, entry);
  }
  assert.equal(profiles[0], profiles[1]);
  assert.notEqual(profiles[1], profiles[2]);
  assert.equal(sessions[0], sessions[1]);
  assert.notEqual(sessions[1], sessions[2]);
  const rejected = await client.callTool({
    name: "open_binary",
    arguments: {
      path,
      format: "raw-binary",
      architecture: "arm64",
      entry_point: "0x8000001",
    },
  });
  assert.equal(rejected.isError, true);
  assert.match(JSON.stringify(rejected.content), /must be 4-byte aligned/);
  const unchanged = await call("binary_session");
  assert.equal(unchanged.analysis_run.run_id, sessions[2]);
  assert.equal(unchanged.entry_point, "0x9000000");
  await call("close_binary");

  const { stdout } = await promisify(execFile)(
    process.execPath,
    [
      entrypoint,
      "inspect-native-load-image",
      path,
      "--target-format",
      "raw-binary",
      "--architecture",
      "arm",
      "--entry-point",
      "0x08000000",
      "--provider",
      "ghidra",
      "--json",
    ],
    { env, timeout: 240000, maxBuffer: 16 * 1024 * 1024 },
  );
  const cli = parseEvidence(JSON.parse(stdout));
  assert.equal(cli.subject.digest.sha256, sha256);
  assert.equal(cli.normalized_result.status, "verified");
  assert.equal(cli.normalized_result.base_address, "0x8000000");
  assert.equal(cli.analysis_profile.digest, profiles[0]);
  assert.deepEqual(await readFile(path), bytes);
  const x86Targets = [];
  for (const architecture of ["x86", "x86_64"]) {
    const x86Bytes = Buffer.from("b82a000000c3", "hex"); // mov eax, 42; ret.
    const x86Sha256 = createHash("sha256").update(x86Bytes).digest("hex");
    const x86Path = join(workspace, `${architecture}.bin`);
    await writeFile(x86Path, x86Bytes);
    await call("open_binary", {
      path: x86Path,
      format: "raw-binary",
      architecture,
      entry_point: "0x1000",
    });
    const image = await call("inspect_native_load_image", {}, x86Sha256);
    assert.equal(
      image.normalized_result.status,
      "verified",
      JSON.stringify(image),
    );
    assert.equal(image.normalized_result.base_address, "0x1000");
    assert.equal(image.normalized_result.observations.compiler_spec_id, "gcc");
    assert.equal(image.analysis_profile.parameters.compiler_spec_id, "gcc");
    const memory = await call(
      "read_bytes",
      { address: "0x1000", length: x86Bytes.length },
      x86Sha256,
    );
    assert.equal(memory.normalized_result.bytes_hex, x86Bytes.toString("hex"));
    const pseudo = await call(
      "procedure_pseudo_code",
      { procedure: "0x1000" },
      x86Sha256,
    );
    assert.match(pseudo.normalized_result, /\b(?:42|0x2a)\b/iu);
    await call("close_binary");
    assert.deepEqual(await readFile(x86Path), x86Bytes);
    x86Targets.push({
      architecture,
      sha256: x86Sha256,
      compiler_spec_id: "gcc",
      return_42: true,
    });
  }
  report = {
    ok: true,
    mocked: false,
    lane: "ghidra-raw",
    host: process.platform,
    provider: { id: "ghidra", version: installation.providerVersion },
    target: {
      format: "raw-binary",
      architecture: "arm",
      sha256,
      bytes: bytes.length,
    },
    transport: { cli: true, stdio_mcp: true },
    canonical_entry_reuses_session: true,
    changed_entry_replaces_session: true,
    lifecycle_entry_preserved: true,
    invalid_entry_preserves_active_session: true,
    load_images_verified: true,
    original_unchanged: true,
    x86_targets: x86Targets,
  };
} catch (error) {
  if (stderr.trim()) process.stderr.write(stderr);
  throw error;
} finally {
  await client.close();
  await transport.close();
  await rm(workspace, { recursive: true, force: true });
}
const verifierRun = await completeVerifierRun(run);
assert.equal(verifierRun.process_lineage.status, "verified");
assert.deepEqual(verifierRun.process_lineage.descendants, []);
process.stdout.write(
  JSON.stringify({
    verifier_run: verifierRun,
    ...report,
    cleanup: "complete",
  }) + "\n",
);

async function call(name, args = {}, targetSha256 = sha256) {
  const result = await client.callTool(
    { name, arguments: args },
    { timeout: 240000 },
  );
  assert.notEqual(result.isError, true, JSON.stringify(result));
  const projected = requireMcpOperationResult(result, name);
  if (
    name === "open_binary" ||
    name === "close_binary" ||
    name === "binary_session"
  )
    return projected;
  const evidence = parseEvidence(result.structuredContent);
  assert.equal(evidence.subject.digest.sha256, targetSha256);
  assert.equal(evidence.subject.format, "raw-binary");
  return evidence;
}
