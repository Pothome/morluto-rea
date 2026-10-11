import { createReadStream } from "node:fs";
import { open, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Readable } from "node:stream";
import { Uint8ArrayReader, Uint8ArrayWriter, ZipWriter } from "@zip.js/zip.js";
import { expect, it, onTestFinished, vi } from "vitest";

import {
  aotFixtureImage,
  buildElf64Image,
  REFERENCE_HASH,
} from "./FlutterTestFixtures.js";
import { snapshotSection } from "./DartElf.js";
import { FlutterBuildProvider } from "./FlutterBuildProvider.js";
import { projectAnalysisError } from "../domain/analysisErrorProjection.js";
import {
  AnalysisCancelledError,
  AnalysisResourceConstraintError,
} from "../domain/analysisErrorCore.js";
import {
  flutterResultSchemas,
  type FlutterOperation,
} from "../domain/flutter/flutterBuildAnalysis.js";
import { ZipArtifactReader } from "../artifacts/ZipArtifactReader.js";
import { createTestTempDirectory } from "../../tests/fixtures/temporaryDirectory.js";

vi.mock("node:fs", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:fs")>();
  return { ...original, createReadStream: vi.fn(original.createReadStream) };
});

const buildIdNote = (): Buffer =>
  Buffer.concat([
    Buffer.from([4, 0, 0, 0, 20, 0, 0, 0, 3, 0, 0, 0, 0x47, 0x4e, 0x55, 0]),
    Buffer.from([
      0xe8, 0xd9, 0x07, 0xef, 0x7c, 0x17, 0x5e, 0xc4, 0x31, 0x3f, 0x47, 0x11,
      0x10, 0x19, 0xad, 0xc9, 0x58, 0x8c, 0x5f, 0x61,
    ]),
  ]);

const TOOLCHAIN_LINE =
  "Android (5900059 based on r365631c) clang version 9.0.8 (based on LLVM 9.0.8svn)";

const libapp = aotFixtureImage;

const libflutter = (): Buffer =>
  Buffer.concat([
    Buffer.from("ELF-payload-prefix\x00"),
    buildIdNote(),
    Buffer.from(`\x00${TOOLCHAIN_LINE}\x00`),
  ]);

/**
 * Self-contained Dart AOT image: a synthetic ELF64 carrying the four
 * snapshot symbols, two snapshot sections, and a string pool, so goldens
 * do not depend on any file outside the repository.
 */
const aotImage = aotFixtureImage;

/** Two data symbols at one offset and size: aliased exports. */
const aliasedDataImage = (): Buffer => {
  const elf = buildElf64Image([
    { name: "_kDartVmSnapshotData", value: 0x1000, size: 52 },
    { name: "_kDartIsolateSnapshotData", value: 0x1000, size: 52 },
  ]);
  return Buffer.concat([
    elf,
    Buffer.alloc(0x1000 - elf.length),
    snapshotSection(REFERENCE_HASH),
  ]);
};

/** Two data symbols whose snapshot hashes disagree. */
const conflictingHashImage = (): Buffer => {
  const elf = buildElf64Image([
    { name: "_kDartVmSnapshotData", value: 0x1000, size: 52 },
    { name: "_kDartIsolateSnapshotData", value: 0x1200, size: 52 },
  ]);
  const vm = snapshotSection("11111111111111111111111111111111");
  const isolate = snapshotSection("22222222222222222222222222222222");
  return Buffer.concat([
    elf,
    Buffer.alloc(0x1000 - elf.length),
    vm,
    Buffer.alloc(0x1200 - 0x1000 - vm.length),
    isolate,
  ]);
};

/** Build a real APK-shaped ZIP through the portable ZIP implementation. */
const buildApk = async (
  name: string,
  files: ReadonlyArray<{ readonly path: string; readonly bytes: Buffer }>,
): Promise<string> => {
  const root = await createTestTempDirectory("rea-flutter-");
  const writer = new ZipWriter(new Uint8ArrayWriter(), {
    useWebWorkers: false,
  });
  for (const file of files) {
    await writer.add(file.path, new Uint8ArrayReader(file.bytes));
  }
  await writeFile(join(root, name), await writer.close());
  return join(root, name);
};

const analyzeImage = async (bytes: Buffer, operation: FlutterOperation) => {
  const path = await buildApk("image.apk", [
    { path: "lib/arm64-v8a/libapp.so", bytes },
    { path: "lib/arm64-v8a/libflutter.so", bytes: libflutter() },
  ]);
  const provider = new FlutterBuildProvider({ environment: {} });
  onTestFinished(() => provider.close());
  const result = await provider.execute({ operation, input: { path } });
  if (!result.ok) throw result.error;
  return result.value;
};

it("projects each payload shape through the owned snapshot", async () => {
  const hash = REFERENCE_HASH;
  const agreeBoth = await buildApk("agree.apk", [
    { path: "lib/arm64-v8a/libapp.so", bytes: libapp(hash) },
    { path: "lib/arm64-v8a/libflutter.so", bytes: libflutter() },
    { path: "lib/x86_64/libapp.so", bytes: libapp(hash) },
    { path: "lib/x86_64/libflutter.so", bytes: libflutter() },
  ]);
  const half = await buildApk("half.apk", [
    { path: "lib/arm64-v8a/libapp.so", bytes: libapp(hash) },
  ]);
  const disagree = await buildApk("disagree.apk", [
    {
      path: "lib/arm64-v8a/libapp.so",
      bytes: Buffer.concat([
        snapshotSection("11111111111111111111111111111111"),
        snapshotSection("22222222222222222222222222222222"),
      ]),
    },
    { path: "lib/arm64-v8a/libflutter.so", bytes: libflutter() },
  ]);
  const plain = await buildApk("plain.apk", [
    { path: "classes.dex", bytes: Buffer.from("dex\n0123456789") },
    { path: "lib/arm64-v8a/libnative.so", bytes: Buffer.from("plain-elf") },
  ]);
  const provider = new FlutterBuildProvider({ environment: {} });
  const identify = async (apk: string) => {
    const outcome = await provider.execute({
      operation: "identify_flutter_build",
      input: { path: apk },
    });
    if (!outcome.ok) throw new Error(outcome.error.message);
    return outcome.value.result as {
      flutter_detected: boolean;
      coverage: string;
      abis: {
        abi: string;
        libapp: {
          present: boolean;
          snapshot_hash: string | null;
          snapshot_hash_sources: number;
          snapshot_hash_candidates: string[];
        };
        libflutter: { present: boolean; build_id: string | null };
      }[];
    };
  };

  const both = await identify(agreeBoth);
  expect(both.flutter_detected).toBe(true);
  expect(both.coverage).toBe("complete");
  expect(both.abis.map((abi) => abi.abi)).toEqual(["arm64-v8a", "x86_64"]);
  for (const abi of both.abis) {
    expect(abi.libapp.snapshot_hash).toBe(hash);
    expect(abi.libapp.snapshot_hash_sources).toBe(2);
    expect(abi.libflutter.build_id).toBe(
      "e8d907ef7c175ec4313f47111019adc9588c5f61",
    );
  }

  const engineless = await identify(half);
  expect(engineless.coverage).toBe("partial");
  expect(engineless.abis[0]?.libapp.present).toBe(true);
  expect(engineless.abis[0]?.libflutter.present).toBe(false);

  const conflicted = await identify(disagree);
  expect(conflicted.coverage).toBe("partial");
  expect(conflicted.abis[0]?.libapp.snapshot_hash).toBeNull();
  expect(conflicted.abis[0]?.libapp.snapshot_hash_candidates).toEqual([
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
  ]);

  const negative = await identify(plain);
  expect(negative.flutter_detected).toBe(false);
  expect(negative.abis).toEqual([]);
  expect(negative.coverage).toBe("complete");
});

it("rejects a target that is not a readable file", async () => {
  const projected = await (async () => {
    const result = await new FlutterBuildProvider({
      environment: {},
    }).execute({
      operation: "identify_flutter_build",
      input: { path: "/nonexistent/app.apk" },
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("expected a refusal");
    return projectAnalysisError(result.error);
  })();
  expect(projected).toMatchObject({ code: "invalid_request" });
});

it("refuses an APK without a Dart payload", async () => {
  const apk = await buildApk("noflutter.apk", [
    { path: "classes.dex", bytes: Buffer.from("dex\n0123456789") },
  ]);
  const result = await new FlutterBuildProvider({ environment: {} }).execute({
    operation: "inspect_dart_aot",
    input: { path: apk },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error)).toMatchObject({
    code: "unsupported_target",
  });
});

it("refuses a requested ABI the payload does not carry", async () => {
  const apk = await buildApk("oneabi.apk", [
    {
      path: "lib/arm64-v8a/libapp.so",
      bytes: libapp(REFERENCE_HASH),
    },
  ]);
  const result = await new FlutterBuildProvider({ environment: {} }).execute({
    operation: "inspect_dart_aot",
    input: { path: apk, abi: "x86_64" },
  });
  expect(result.ok).toBe(false);
  if (result.ok) return;
  expect(projectAnalysisError(result.error)).toMatchObject({
    code: "unsupported_target",
  });
  expect(result.error.message).toContain("arm64-v8a");
});

it("inspects a full synthetic AOT image end to end", async () => {
  const apk = await buildApk("realgallery.apk", [
    { path: "lib/arm64-v8a/libapp.so", bytes: aotImage() },
  ]);
  const result = await new FlutterBuildProvider({
    environment: {},
  }).execute({
    operation: "inspect_dart_aot",
    input: { path: apk },
  });
  if (!result.ok) throw new Error(result.error.message);
  const value = result.value.result as {
    abi: string;
    libapp: {
      snapshot_hash: string | null;
      snapshot_hash_candidates: string[];
      snapshot_hash_sources: number;
      sections: { name: string; magic_valid: boolean }[];
    };
    string_pool: {
      package_uri_count_at_least: number;
      dart_uri_count_at_least: number;
    };
    coverage: string;
  };
  expect(value.abi).toBe("arm64-v8a");
  expect(value.libapp.snapshot_hash).toBe(REFERENCE_HASH);
  expect(value.libapp.snapshot_hash_candidates).toEqual([REFERENCE_HASH]);
  expect(value.libapp.snapshot_hash_sources).toBe(2);
  expect(value.libapp.sections.map((section) => section.name)).toEqual([
    "_kDartVmSnapshotData",
    "_kDartVmSnapshotInstructions",
    "_kDartIsolateSnapshotData",
    "_kDartIsolateSnapshotInstructions",
  ]);
  expect(
    value.libapp.sections
      .filter((section) => section.name.endsWith("Data"))
      .every((section) => section.magic_valid),
  ).toBe(true);
  expect(value.string_pool.package_uri_count_at_least).toBe(2);
  expect(value.string_pool.dart_uri_count_at_least).toBe(2);
  // All four symbols present, both data magics valid, pool under budget:
  // the honest answer for a complete payload is complete coverage.
  expect(value.coverage).toBe("complete");
});

it("reports aliased snapshot data symbols as partial coverage", async () => {
  const apk = await buildApk("aliased.apk", [
    { path: "lib/arm64-v8a/libapp.so", bytes: aliasedDataImage() },
  ]);
  const result = await new FlutterBuildProvider({ environment: {} }).execute({
    operation: "inspect_dart_aot",
    input: { path: apk },
  });
  if (!result.ok) throw new Error(result.error.message);
  const value = result.value.result as {
    coverage: string;
    libapp: {
      snapshot_hash: string | null;
      snapshot_hash_candidates: string[];
      snapshot_hash_sources: number;
    };
  };
  // The aliased range is scanned once, so one candidate no longer counts
  // as two agreeing sources.
  expect(value.coverage).toBe("partial");
  expect(value.libapp.snapshot_hash_sources).toBe(1);
  expect(value.libapp.snapshot_hash_candidates).toEqual([REFERENCE_HASH]);
  expect(result.value.limitations).toContain(
    "Two or more snapshot data symbols share one header offset; its hash counts as one source instead of two agreeing ones",
  );
});

it("preserves conflicting snapshot hash candidates from the AOT image", async () => {
  const apk = await buildApk("conflicted.apk", [
    { path: "lib/arm64-v8a/libapp.so", bytes: conflictingHashImage() },
  ]);
  const result = await new FlutterBuildProvider({ environment: {} }).execute({
    operation: "inspect_dart_aot",
    input: { path: apk },
  });
  if (!result.ok) throw new Error(result.error.message);
  const value = result.value.result as {
    coverage: string;
    libapp: {
      snapshot_hash: string | null;
      snapshot_hash_candidates: string[];
      snapshot_hash_sources: number;
    };
  };
  expect(value.coverage).toBe("partial");
  expect(value.libapp.snapshot_hash).toBeNull();
  expect(value.libapp.snapshot_hash_sources).toBe(2);
  expect(value.libapp.snapshot_hash_candidates).toEqual([
    "11111111111111111111111111111111",
    "22222222222222222222222222222222",
  ]);
});

it("accepts an APK whose path contains spaces through the owned snapshot", async () => {
  const apk = await buildApk("flutter spaced.apk", [
    {
      path: "lib/arm64-v8a/libapp.so",
      bytes: libapp(REFERENCE_HASH),
    },
    { path: "lib/arm64-v8a/libflutter.so", bytes: libflutter() },
  ]);
  expect(apk).toContain(" ");
  const result = await new FlutterBuildProvider({
    environment: {},
  }).execute({
    operation: "identify_flutter_build",
    input: { path: apk },
  });
  if (!result.ok) throw new Error(result.error.message);
  const value = result.value.result as { flutter_detected: boolean };
  expect(value.flutter_detected).toBe(true);
});

it("retains failed snapshot cleanup and retries it on close", async () => {
  const apk = await buildApk("cleanup.apk", [
    {
      path: "lib/arm64-v8a/libapp.so",
      bytes: libapp(REFERENCE_HASH),
    },
  ]);
  const spaces: string[] = [];
  let failing = true;
  const provider = new FlutterBuildProvider({
    environment: {},
    removeRoot: async (path) => {
      if (failing) throw new Error("cleanup refused");
      spaces.push(path);
      await rm(path, { recursive: true, force: true });
    },
  });
  const result = await provider.execute({
    operation: "identify_flutter_build",
    input: { path: apk },
  });
  expect(result.ok).toBe(true);
  await expect(provider.close()).rejects.toThrow(/snapshot cleanup failed/u);
  failing = false;
  await provider.close();
  expect(spaces.length).toBeGreaterThanOrEqual(1);
});

it("cancels before creating any snapshot root", async () => {
  const apk = await buildApk("cancel.apk", [
    {
      path: "lib/arm64-v8a/libapp.so",
      bytes: libapp(REFERENCE_HASH),
    },
  ]);
  const controller = new AbortController();
  controller.abort();
  const provider = new FlutterBuildProvider({ environment: {} });
  const result = await provider.execute(
    { operation: "identify_flutter_build", input: { path: apk } },
    { signal: controller.signal },
  );
  expect(result.ok).toBe(false);
  await provider.close();
});

it.each([1, 20, 47, 48, 61])(
  "identifies a valid ELF when ZIP chunks are only %i bytes",
  async (chunkBytes) => {
    const originalOpen = ZipArtifactReader.prototype.open;
    const spy = vi
      .spyOn(ZipArtifactReader.prototype, "open")
      .mockImplementation(async function (
        this: ZipArtifactReader,
        entry,
        signal,
      ) {
        const source = await originalOpen.call(this, entry, signal);
        return Readable.from(
          (async function* () {
            for await (const chunk of source) {
              const bytes = chunk as Buffer;
              for (let offset = 0; offset < bytes.length; offset += chunkBytes)
                yield bytes.subarray(offset, offset + chunkBytes);
            }
          })(),
        );
      });
    onTestFinished(() => spy.mockRestore());
    const execution = await analyzeImage(aotImage(), "identify_flutter_build");
    const value = flutterResultSchemas.identify_flutter_build.parse(
      execution.result,
    );
    expect(value.coverage).toBe("complete");
    expect(value.abis[0]?.libapp).toMatchObject({
      elf_header_valid: true,
      snapshot_hash: REFERENCE_HASH,
      snapshot_hash_sources: 2,
    });
  },
);

it.each([
  {
    name: "zeroed offsets",
    corrupt: (image: Buffer) => image.fill(0, 0x20, 0x30),
  },
  {
    name: "program table past EOF",
    corrupt: (image: Buffer) =>
      image.writeBigUInt64LE(BigInt(image.length + 1), 0x20),
  },
  {
    name: "section table past EOF",
    corrupt: (image: Buffer) =>
      image.writeBigUInt64LE(BigInt(image.length - 1), 0x28),
  },
  {
    name: "zero program entry width",
    corrupt: (image: Buffer) => image.writeUInt16LE(0, 0x36),
  },
  {
    name: "short section entry width",
    corrupt: (image: Buffer) => image.writeUInt16LE(1, 0x3a),
  },
  {
    name: "absent program table",
    corrupt: (image: Buffer) => image.writeUInt16LE(0, 0x38),
  },
  {
    name: "unsupported class",
    corrupt: (image: Buffer) => image.writeUInt8(3, 4),
  },
  {
    name: "unsupported byte order",
    corrupt: (image: Buffer) => image.writeUInt8(2, 5),
  },
  {
    name: "unsafe table offset",
    corrupt: (image: Buffer) => image.writeBigUInt64LE(1n << 63n, 0x20),
  },
  {
    name: "table inside header",
    corrupt: (image: Buffer) => image.writeBigUInt64LE(1n, 0x20),
  },
  {
    name: "extended section count",
    corrupt: (image: Buffer) => image.writeUInt16LE(0, 0x3c),
  },
])(
  "retains hash observations with partial coverage for $name",
  async ({ corrupt }) => {
    const image = aotImage();
    corrupt(image);
    const execution = await analyzeImage(image, "identify_flutter_build");
    const value = flutterResultSchemas.identify_flutter_build.parse(
      execution.result,
    );
    expect(value.coverage).toBe("partial");
    expect(value.abis[0]?.libapp).toMatchObject({
      elf_header_valid: false,
      snapshot_hash: REFERENCE_HASH,
      snapshot_hash_sources: 2,
    });
    expect(execution.limitations.join("\n")).toContain(
      "ELF header or table extent",
    );
  },
);

it.each([0, 4, 20, 47, 61])(
  "reports a %i-byte ELF prefix as partial without throwing",
  async (length) => {
    const execution = await analyzeImage(
      aotImage().subarray(0, length),
      "identify_flutter_build",
    );
    const value = flutterResultSchemas.identify_flutter_build.parse(
      execution.result,
    );
    expect(value.coverage).toBe("partial");
    expect(value.abis[0]?.libapp.elf_header_valid).toBe(false);
  },
);

it("accepts a section-stripped ELF32 header and bounds its program table", async () => {
  const image = Buffer.alloc(52 + 32 + 104);
  image.writeUInt32LE(0x464c457f);
  image.set([1, 1, 1], 4); // ELF32, little-endian, version 1
  image.writeUInt16LE(3, 0x10); // ET_DYN
  image.writeUInt32LE(1, 0x14);
  image.writeUInt32LE(52, 0x1c);
  image.writeUInt16LE(52, 0x28);
  image.writeUInt16LE(32, 0x2a);
  image.writeUInt16LE(1, 0x2c);
  image.writeUInt32LE(1, 52); // PT_LOAD
  image.writeUInt32LE(image.length, 52 + 16);
  snapshotSection(REFERENCE_HASH).copy(image, 84);
  snapshotSection(REFERENCE_HASH).copy(image, 136);
  const good = await analyzeImage(image, "identify_flutter_build");
  expect(
    flutterResultSchemas.identify_flutter_build.parse(good.result).coverage,
  ).toBe("complete");
  image.writeUInt32LE(image.length - 31, 0x1c); // One byte short of the table.
  const bad = await analyzeImage(image, "identify_flutter_build");
  expect(
    flutterResultSchemas.identify_flutter_build.parse(bad.result).coverage,
  ).toBe("partial");
});

it.each([0n, 15n, 47n, 49n, 1n << 63n])(
  "retains malformed snapshot length %s as partial evidence",
  async (length) => {
    const image = aotImage();
    image.writeBigUInt64LE(length, 0x1004);
    const execution = await analyzeImage(image, "inspect_dart_aot");
    const value = flutterResultSchemas.inspect_dart_aot.parse(execution.result);
    expect(value.coverage).toBe("partial");
    expect(value.libapp.snapshot_hash).toBe(REFERENCE_HASH);
    expect(value.libapp.sections[0]).toMatchObject({
      magic_valid: true,
      header_length:
        length > BigInt(Number.MAX_SAFE_INTEGER) ? null : Number(length),
    });
    expect(execution.limitations.join("\n")).toContain(
      "_kDartVmSnapshotData has an incomplete or invalid snapshot header",
    );
  },
);

it("does not let two VM records replace a missing isolate header hash", async () => {
  const image = aotImage();
  const elf = buildElf64Image([
    { name: "_kDartVmSnapshotData", value: 0x1000, size: 104 },
    { name: "_kDartVmSnapshotInstructions", value: 0x1800, size: 16 },
    { name: "_kDartIsolateSnapshotData", value: 0x2000, size: 0x600 },
    { name: "_kDartIsolateSnapshotInstructions", value: 0x2600, size: 16 },
  ]);
  elf.copy(image);
  snapshotSection(REFERENCE_HASH).copy(image, 0x1000 + 52);
  image[0x2000 + 20] = 0x78; // Keep the isolate magic but invalidate its hash.
  const execution = await analyzeImage(image, "inspect_dart_aot");
  const value = flutterResultSchemas.inspect_dart_aot.parse(execution.result);
  expect(value.libapp.sections).toHaveLength(4);
  expect(value.coverage).toBe("partial");
  expect(value.libapp.snapshot_hash_sources).toBe(1);
  expect(value.libapp.snapshot_hash_candidates).toEqual([REFERENCE_HASH]);
  expect(execution.limitations.join("\n")).toContain(
    "_kDartIsolateSnapshotData has an incomplete or invalid snapshot header",
  );
});

it.each(["identify_flutter_build", "inspect_dart_aot"] as const)(
  "%s preserves an oversized APK refusal as a resource constraint",
  async (operation) => {
    const root = await createTestTempDirectory("rea-flutter-size-");
    const path = join(root, "oversized.apk");
    const file = await open(path, "wx");
    try {
      await file.truncate(2 * 1024 ** 3 + 1); // Sparse file: no multi-GiB allocation.
    } finally {
      await file.close();
    }
    const provider = new FlutterBuildProvider({ environment: {} });
    onTestFinished(() => provider.close());
    const result = await provider.execute({ operation, input: { path } });
    if (result.ok) throw new Error("expected a size refusal");
    expect(result.error).toBeInstanceOf(AnalysisResourceConstraintError);
    expect(projectAnalysisError(result.error).code).toBe("resource_constraint");
    expect(result.error).toMatchObject({
      operation,
      reportedLimits: {
        max_apk_bytes: 2 * 1024 ** 3,
        observed_bytes: 2 * 1024 ** 3 + 1,
      },
    });
  },
);

it.each([
  { operation: "identify_flutter_build", phase: "copy" },
  { operation: "inspect_dart_aot", phase: "digest" },
] as const)(
  "preserves native stream aborts during $operation $phase",
  async ({ operation, phase }) => {
    const path = await buildApk("abort.apk", [
      { path: "lib/arm64-v8a/libapp.so", bytes: aotImage() },
    ]);
    const controller = new AbortController();
    const nativeFs = await vi.importActual<typeof import("node:fs")>("node:fs");
    const streamMock = vi.mocked(createReadStream);
    let abortCode: string | undefined;
    streamMock.mockImplementation((streamPath, options) => {
      const stream = nativeFs.createReadStream(streamPath, options);
      if ((streamPath === path) === (phase === "copy")) {
        stream.once("error", (cause: NodeJS.ErrnoException) => {
          abortCode = cause.code;
        });
        stream.once("open", () =>
          controller.abort(new Error("caller requested stop")),
        );
      }
      return stream;
    });
    onTestFinished(() => {
      streamMock.mockReset();
    });
    const removedRoots: string[] = [];
    const provider = new FlutterBuildProvider({
      environment: {},
      removeRoot: async (root) => {
        await rm(root, { recursive: true, force: true });
        removedRoots.push(root);
      },
    });
    onTestFinished(() => provider.close());
    const result = await provider.execute(
      { operation, input: { path } },
      { signal: controller.signal },
    );
    if (result.ok) throw new Error("expected cancellation");
    expect(abortCode).toBe("ABORT_ERR");
    expect(result.error).toBeInstanceOf(AnalysisCancelledError);
    expect(result.error).toMatchObject({ operation });
    expect(projectAnalysisError(result.error).code).toBe("cancelled");
    expect(removedRoots).toHaveLength(1);
  },
);
