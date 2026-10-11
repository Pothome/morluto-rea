import { STDIO_DEFAULT_MAX_BUFFER_SIZE } from "@modelcontextprotocol/server";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { expect, it as test, vi } from "vitest";
import {
  firmwareFixture,
  assertFirmwareCleanup,
} from "../../fixtures/firmware/provider.js";
import { firmwareResultSchemas } from "../../../src/domain/firmware/firmwareAnalysis.js";
import { FirmwareAnalysisService } from "../../../src/application/firmware/FirmwareAnalysisService.js";
import { FirmwareProvider } from "../../../src/firmware/FirmwareProvider.js";
import { projectAnalysisError } from "../../../src/domain/analysisErrorProjection.js";
import { ProviderCleanupError } from "../../../src/domain/providerCleanupError.js";
import { toolContract } from "../../../src/contracts/toolContracts.js";
import { ToolResultDelivery } from "../../../src/server/toolResult.js";
import { SafeOutputTree } from "../../../src/artifacts/SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../../../src/artifacts/SafeOutputTreeCreationFailure.js";

const directoryCloseFailure = vi.hoisted(() => ({
  mode: "off" as "off" | "transient" | "persistent",
  attempts: 0,
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const filesystem = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...filesystem,
    open: async (...args: Parameters<typeof filesystem.open>) => {
      const handle = await filesystem.open(...args);
      if (
        directoryCloseFailure.mode !== "off" &&
        (await handle.stat()).isDirectory()
      ) {
        const close = handle.close.bind(handle);
        let attempted = false;
        handle.close = async () => {
          directoryCloseFailure.attempts += 1;
          if (
            directoryCloseFailure.mode === "persistent" ||
            (directoryCloseFailure.mode === "transient" && !attempted)
          ) {
            attempted = true;
            throw new Error("injected published directory close failure");
          }
          await close();
        };
      }
      return handle;
    },
  };
});

const delivery = new ToolResultDelivery(STDIO_DEFAULT_MAX_BUFFER_SIZE);

const it = test.skipIf(process.platform !== "linux");

it("keeps cleanup-failure state local to the selected factory instance", async () => {
  const failed = await firmwareFixture("cleanup-failure");
  const healthy = await firmwareFixture();
  const failure = await failed.service.execute("inspect_firmware_regions", {
    path: failed.path,
  });
  expect(failure).toMatchObject({
    ok: false,
    error: { cleanupIncomplete: true },
  });
  const result = await healthy.service.execute("inspect_firmware_regions", {
    path: healthy.path,
  });
  expect(result.ok).toBe(true);
  await assertFirmwareCleanup(healthy.launches);
});

it("binds region observations to exact bytes and preserves provider-reported uncertainty", async () => {
  const fixture = await firmwareFixture();
  const result = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  if (!result.ok) throw result.error;
  const normalized = firmwareResultSchemas.inspect_firmware_regions.parse(
    result.value.normalized_result,
  );
  expect(normalized.regions[0]).toMatchObject({
    offset: 2,
    reported_size: 4,
    size_basis: "provider_reported_validation_unknown",
  });
  expect(result.value.subject?.local_path).toBe(fixture.path);
  expect(result.value.subject?.format).toBe("file");
  expect(result.value.raw_result).toMatchObject({
    report: [{ Analysis: { file_map: [{ id: "hit" }] } }],
  });
  expect(fixture.launches[1]?.args).toEqual(
    expect.arrayContaining(["--as=1073741824", "--threads", "1"]),
  );
  await assertFirmwareCleanup(fixture.launches);
});

it.each(["wrong-input", "bounds"])(
  "rejects a mismatched or out-of-bounds inspection: %s",
  async (mode) => {
    const fixture = await firmwareFixture(mode);
    const result = await fixture.service.execute("inspect_firmware_regions", {
      path: fixture.path,
    });
    expect(result).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisOutputError" },
    });
    await assertFirmwareCleanup(fixture.launches);
  },
);

it("extracts a selected interval with verified file identity and parent-byte lineage", async () => {
  const fixture = await firmwareFixture();
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
    range: { offset: 2, length: 4 },
  });
  if (!result.ok) throw result.error;
  const normalized = firmwareResultSchemas.extract_firmware.parse(
    result.value.normalized_result,
  );
  expect(normalized.selection).toMatchObject({ offset: 2, length: 4 });
  expect(normalized.files[0]).toMatchObject({
    relative_path: "rootfs/config",
    size: 14,
    original_file_range: null,
    runtime_address: null,
  });
  expect(normalized.chunks[0]?.root_file_range).toEqual({
    offset: 2,
    length: 4,
  });
  expect(normalized.derivations[0]).toMatchObject({
    parent_path: "$input",
    child_path: "$output/rootfs/config",
    handler: "gzip",
    parent_file_range: { offset: 0, length: 4 },
  });
  expect(await readFile(normalized.files[0]?.path ?? "", "utf8")).toBe(
    "firmware=true\n",
  );
  expect(fixture.launches[1]?.args).toEqual(
    expect.arrayContaining(["--process-num", "1", "--randomness-depth", "0"]),
  );
  expect(fixture.launches[1]?.args).not.toContain("--no-sandbox");
  await assertFirmwareCleanup(fixture.launches);
});

it("retains a setup-failed publication tree for provider cleanup retry", async () => {
  const fixture = await firmwareFixture();
  const createTree = SafeOutputTree.create.bind(SafeOutputTree);
  let cleanupAttempts = 0;
  const create = vi
    .spyOn(SafeOutputTree, "create")
    .mockImplementationOnce(async (outputRoot, platform) => {
      const tree = await createTree(outputRoot, platform);
      const rollbackTree = tree.rollback.bind(tree);
      vi.spyOn(tree, "rollback").mockImplementation(async () => {
        cleanupAttempts += 1;
        if (cleanupAttempts === 1)
          throw new Error("injected first cleanup failure");
        return rollbackTree();
      });
      throw new SafeOutputTreeCreationFailure(
        new Error("injected post-acquisition setup failure"),
        tree,
      );
    });
  try {
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      range: { offset: 2, length: 4 },
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        cleanupIncomplete: true,
        diagnostics: {
          previous_error: expect.stringContaining(
            "injected post-acquisition setup failure",
          ),
        },
      },
    });
    await expect(access(fixture.output)).resolves.toBeUndefined();
  } finally {
    create.mockRestore();
  }
  await fixture.close();
  expect(cleanupAttempts).toBe(2);
  await expect(access(fixture.output)).rejects.toMatchObject({
    code: "ENOENT",
  });
});

it("returns firmware output after a transient published-directory close failure", async () => {
  const fixture = await firmwareFixture();
  const closeFailure = injectPublishedDirectoryCloseFailure(false);
  try {
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      range: { offset: 2, length: 4 },
    });
    if (!result.ok) throw result.error;
    const normalized = firmwareResultSchemas.extract_firmware.parse(
      result.value.normalized_result,
    );
    expect(normalized.output_directory).toBe(fixture.output);
    expect(await readFile(normalized.files[0]?.path ?? "", "utf8")).toBe(
      "firmware=true\n",
    );
    expect(closeFailure.attempts()).toBeGreaterThanOrEqual(4);
  } finally {
    closeFailure.restore();
  }
});

it("retains the complete firmware result when published output cleanup stays uncertain", async () => {
  const fixture = await firmwareFixture();
  const closeFailure = injectPublishedDirectoryCloseFailure(true);
  try {
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      range: { offset: 2, length: 4 },
    });
    expect(result).toMatchObject({
      ok: false,
      error: {
        cleanupIncomplete: true,
        partialObservation: {
          kind: "firmware",
          result: {
            output_directory: fixture.output,
            files: [
              expect.objectContaining({
                relative_path: "rootfs/config",
                size: 14,
              }),
            ],
          },
        },
      },
    });
    if (result.ok) throw new Error("Expected unresolved descriptor cleanup");
    expect(result.error).toBeInstanceOf(ProviderCleanupError);
    expect(projectAnalysisError(result.error)).toMatchObject({
      code: "cleanup_incomplete",
      details: {
        partial_observation: {
          kind: "firmware",
          result: { output_directory: fixture.output },
        },
      },
    });
    expect(await readFile(`${fixture.output}/rootfs/config`, "utf8")).toBe(
      "firmware=true\n",
    );
    expect(closeFailure.attempts()).toBeGreaterThanOrEqual(4);
  } finally {
    closeFailure.restore();
  }
  await fixture.close();
  expect(await readFile(`${fixture.output}/rootfs/config`, "utf8")).toBe(
    "firmware=true\n",
  );
});

const injectPublishedDirectoryCloseFailure = (persistent: boolean) => {
  directoryCloseFailure.attempts = 0;
  const commit = SafeOutputTree.prototype.commit;
  const spy = vi
    .spyOn(SafeOutputTree.prototype, "commit")
    .mockImplementation(async function (this: SafeOutputTree) {
      directoryCloseFailure.mode = persistent ? "persistent" : "transient";
      await commit.call(this);
    });
  return {
    attempts: () => directoryCloseFailure.attempts,
    restore: () => {
      directoryCloseFailure.mode = "off";
      spy.mockRestore();
    },
  };
};

it.each(["depth", "dependency", "link"])(
  "reports partial extraction for %s without losing inline results",
  async (mode) => {
    const fixture = await firmwareFixture(mode);
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
    });
    if (!result.ok) throw result.error;
    const normalized = firmwareResultSchemas.extract_firmware.parse(
      result.value.normalized_result,
    );
    expect(normalized.coverage).toBe("partial");
    expect(normalized.files).toHaveLength(1);
    if (mode === "depth")
      expect(normalized.depth_limited_paths).toEqual(["$output/rootfs/config"]);
    if (mode === "depth")
      expect(normalized.extraction_gaps).toEqual([
        {
          kind: "depth-limited",
          input_path: "$output/rootfs/config",
          relative_path: null,
          handler: null,
          provider_id: null,
          range: null,
          root_file_range: null,
          dependencies: [],
          continuation: expect.stringContaining("max_depth"),
        },
      ]);
    if (mode === "dependency")
      expect(normalized.diagnostics).toEqual([
        {
          input_path: "$input",
          report: {
            __typename__: "ExtractorDependencyNotFoundReport",
            severity: "ERROR",
            dependencies: ["sasquatch"],
          },
        },
      ]);
    if (mode === "dependency")
      expect(normalized.extraction_gaps).toEqual([
        {
          kind: "missing-extractor-dependency",
          input_path: "$input",
          relative_path: null,
          handler: "gzip",
          provider_id: "gzip-id",
          range: { offset: 0, length: 18 },
          root_file_range: { offset: 0, length: 18 },
          dependencies: ["sasquatch"],
          continuation: expect.stringContaining("installs nothing"),
        },
      ]);
    if (mode === "link") {
      expect(normalized.unpublished_entries).toEqual([
        {
          relative_path: "escape",
          kind: "symlink",
          link_target: "/etc/passwd",
        },
      ]);
      expect(normalized.extraction_gaps).toEqual([
        {
          kind: "unpublished-entry",
          input_path: "$output/escape",
          relative_path: "escape",
          handler: null,
          provider_id: null,
          range: null,
          root_file_range: null,
          dependencies: [],
          continuation: expect.stringContaining("metadata"),
        },
      ]);
      await expect(access(`${fixture.output}/escape`)).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
    await assertFirmwareCleanup(fixture.launches);
  },
);

it("distinguishes a real output file named $input from the selected original", async () => {
  const fixture = await firmwareFixture("reserved-name");
  const outcome = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (!outcome.ok) throw outcome.error;
  const result = firmwareResultSchemas.extract_firmware.parse(
    outcome.value.normalized_result,
  );
  expect(result.files[0]?.relative_path).toBe("$input");
  expect(result.derivations[0]).toMatchObject({
    parent_path: "$input",
    child_path: "$output/$input",
  });
  expect(await readFile(`${fixture.output}/$input`, "utf8")).toBe(
    "firmware=true\n",
  );
  await assertFirmwareCleanup(fixture.launches);
});

it.each(["hash", "malformed", "budget", "missing-file"])(
  "rejects invalid or over-budget extraction and rolls back output: %s",
  async (mode) => {
    const fixture = await firmwareFixture(mode);
    const result = await fixture.service.execute("extract_firmware", {
      path: fixture.path,
      output_directory: fixture.output,
      ...(mode === "budget" ? { max_output_bytes: 1000 } : {}),
    });
    expect(result.ok).toBe(false);
    await expect(access(fixture.output)).rejects.toMatchObject({
      code: "ENOENT",
    });
    await assertFirmwareCleanup(fixture.launches);
  },
);

it("preserves existing output and rejects invalid intervals before invoking extraction", async () => {
  const fixture = await firmwareFixture();
  await mkdir(fixture.output);
  await writeFile(`${fixture.output}/existing`, "keep");
  const existing = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  expect(existing.ok).toBe(false);
  expect(await readFile(`${fixture.output}/existing`, "utf8")).toBe("keep");
  const previous = fixture.launches.length;
  const invalid = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
    range: { offset: 100, length: 1 },
  });
  expect(invalid).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisInputError" },
  });
  expect(fixture.launches).toHaveLength(previous);
  await assertFirmwareCleanup(fixture.launches);
});

it("retains startup stderr when Unblob exits 1 without a report", async () => {
  const fixture = await firmwareFixture("startup");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  if (result.ok) throw new Error("Expected startup failure");
  const details = {
    diagnostics: {
      stderr: expect.stringContaining("Landlock sandbox is not available"),
      exit_code: 1,
    },
  };
  expect(projectAnalysisError(result.error)).toMatchObject({ details });
  expect(
    delivery.toCallToolResult(result, toolContract("extract_firmware"))
      .structuredContent,
  ).toMatchObject({ error: { details } });
  expect(result).toMatchObject({
    ok: false,
    error: {
      _tag: "ProviderAdapterError",
      diagnostics: {
        exit_code: 1,
        stderr: expect.stringContaining("Landlock sandbox is not available"),
        report_failure: expect.stringContaining("ENOENT"),
      },
    },
  });
  await expect(access(fixture.output)).rejects.toMatchObject({
    code: "ENOENT",
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("distinguishes a successful process with missing output from startup failure", async () => {
  const fixture = await firmwareFixture("missing-report");
  const result = await fixture.service.execute("extract_firmware", {
    path: fixture.path,
    output_directory: fixture.output,
  });
  expect(result).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisOutputError",
      reason: expect.stringContaining("expected complete report"),
    },
  });
  if (result.ok) throw new Error("Expected missing-output failure");
  expect(projectAnalysisError(result.error)).toMatchObject({
    details: { reason: expect.stringContaining("Producer forgot its report") },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("cancels an owned active process and permits the next queued operation", async () => {
  const fixture = await firmwareFixture("stall");
  const controller = new AbortController();
  const pending = fixture.service.execute(
    "inspect_firmware_regions",
    { path: fixture.path },
    { signal: controller.signal },
  );
  await expect.poll(() => fixture.launches.length).toBe(2);
  controller.abort();
  expect(await pending).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
  const cancelled = await fixture.service.execute(
    "inspect_firmware_regions",
    { path: fixture.path },
    { signal: AbortSignal.abort() },
  );
  expect(cancelled).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
  expect(fixture.launches).toHaveLength(2);
  await assertFirmwareCleanup(fixture.launches);
});

it("cancels a waiting request promptly while keeping later launches behind the active operation", async () => {
  const fixture = await firmwareFixture("stall");
  const activeController = new AbortController();
  const active = fixture.service.execute(
    "inspect_firmware_regions",
    { path: fixture.path },
    { signal: activeController.signal },
  );
  await expect.poll(() => fixture.launches.length).toBe(2);
  const queuedController = new AbortController();
  const queued = fixture.service.execute(
    "inspect_firmware_regions",
    { path: fixture.path },
    { signal: queuedController.signal },
  );
  queuedController.abort();
  expect(await queued).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCancelledError" },
  });
  expect(fixture.launches).toHaveLength(2);
  activeController.abort();
  expect((await active).ok).toBe(false);
  await assertFirmwareCleanup(fixture.launches);
});

it("retains an uncertain worker's workspace and blocks later launches", async () => {
  const fixture = await firmwareFixture("cleanup-failure");
  const first = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  expect(first).toMatchObject({
    ok: false,
    error: { cleanupIncomplete: true },
  });
  const workspace = fixture.launches[0]?.cwd;
  expect(workspace).toBeDefined();
  if (workspace === undefined) throw new Error("Expected retained workspace");
  await access(workspace);
  const originalLaunches = [...fixture.launches];
  const next = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  expect(next).toMatchObject({ ok: false, error: { cleanupIncomplete: true } });
  expect(fixture.launches).toEqual(originalLaunches);
  await access(workspace);
  fixture.restoreCleanup();
  const resumed = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  if (!resumed.ok) throw resumed.error;
  expect(resumed.value.subject?.local_path).toBe(fixture.path);
  await assertFirmwareCleanup(fixture.launches);
});

it("accepts another build on the verified release line and reports it", async () => {
  const fixture = await firmwareFixture("normal", "binwalk 3.1.2");
  const result = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  if (!result.ok) throw result.error;
  expect(result.value.provider.version).toBe("3.1.2");
  expect(result.value.limitations.join("\n")).toContain(
    "verified against 3.1.0",
  );
  expect(result.value.normalized_result).toMatchObject({
    engine: { version: "3.1.2" },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("names the accepted release line when the banner is another line", async () => {
  const fixture = await firmwareFixture("normal", "binwalk 3.2.0");
  const result = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  expect(result).toMatchObject({
    ok: false,
    error: {
      _tag: "AnalysisCapabilityUnavailableError",
      reason: expect.stringContaining("Binwalk 3.1.x"),
    },
  });
  await assertFirmwareCleanup(fixture.launches);
});

it("rejects absent or unsupported engines without installing anything", async () => {
  const missing = await new FirmwareAnalysisService(
    new FirmwareProvider({}),
  ).execute("inspect_firmware_regions", { path: "/tmp/unused" });
  expect(missing).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCapabilityUnavailableError" },
  });
  const fixture = await firmwareFixture("version");
  const result = await fixture.service.execute("inspect_firmware_regions", {
    path: fixture.path,
  });
  expect(result).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisCapabilityUnavailableError" },
  });
  await assertFirmwareCleanup(fixture.launches);
});
