import { createReadStream } from "node:fs";
import { join } from "node:path";
import type { z } from "zod";
import { SafeOutputTree } from "../artifacts/SafeOutputTree.js";
import { SafeOutputTreeCreationFailure } from "../artifacts/SafeOutputTreeCreationFailure.js";
import { AnalysisOutputError } from "../domain/analysisErrorCore.js";
import { ProviderCleanupError } from "../domain/providerCleanupError.js";
import { jsonValueSchema } from "../domain/jsonValue.js";
import { firmwareResultSchemas } from "../domain/firmware/firmwareAnalysis.js";
import { hashFirmwareFile, type FirmwareEntry } from "./FirmwareFiles.js";
import type { normalizeUnblobReport } from "./FirmwareReports.js";
import type { extractionGap } from "../domain/firmware/firmwareAnalysis.js";

type ExtractionGap = z.infer<typeof extractionGap>;

/** Static, truthful continuations that use already configured capabilities. */
const GAP_CONTINUATIONS: Record<ExtractionGap["kind"], string> = {
  "missing-extractor-dependency":
    "REA installs nothing. Add the named dependency to your own environment and rerun extract_firmware on the same immutable input to re-evaluate the affected region; otherwise it stays unextracted.",
  "unknown-chunk-handler":
    "Run inspect_firmware_regions on the same input for signature hypotheses, or select a narrower range with extract_firmware; the region is not decoded content.",
  "encrypted-chunk":
    "No static extraction continues past encryption; treat the region as unexamined rather than empty or corrupt.",
  "depth-limited":
    "Rerun extract_firmware with a higher max_depth (up to 10) to descend into this path.",
  "unpublished-entry":
    "The entry is retained as metadata; only regular files are published, without executable permission bits.",
};

/** The depth ceiling cannot be raised past the input schema maximum. */
const MAX_EXTRACTION_DEPTH = 10;

const depthContinuation = (maxDepth: number): string =>
  maxDepth >= MAX_EXTRACTION_DEPTH
    ? "This extraction already ran at the lane's maximum depth; no deeper rerun is possible. Treat the region as unexamined below this path."
    : GAP_CONTINUATIONS["depth-limited"];

const emptyGap = {
  relative_path: null,
  handler: null,
  provider_id: null,
  range: null,
  root_file_range: null,
  dependencies: [],
};

const gapSortKey = (gap: ExtractionGap): string =>
  [
    gap.input_path,
    gap.kind,
    gap.provider_id ?? "",
    gap.relative_path ?? "",
  ].join("\u0000");

/** Publish verified regular files, preserving links as metadata and rolling back failed writes. */
export const publishFirmwareExtraction = async (context: {
  outputDirectory: string;
  entries: readonly FirmwareEntry[];
  normalized: ReturnType<typeof normalizeUnblobReport>;
  selection: { offset: number; length: number; sha256: string };
  /** Caller-selected extraction depth, for boundary-aware continuations. */
  maxDepth: number;
  engine: z.infer<typeof firmwareResultSchemas.extract_firmware>["engine"];
  signal: AbortSignal;
  retainCleanup: (tree: SafeOutputTree) => void;
}) => {
  let tree: SafeOutputTree | undefined;
  let result:
    | z.infer<typeof firmwareResultSchemas.extract_firmware>
    | undefined;
  try {
    const materialized = new Set(
      context.entries
        .filter((entry) => entry.kind === "file")
        .map((entry) => `$output/${entry.relativePath}`),
    );
    for (const path of context.normalized.files.keys()) {
      if (path !== "$input" && !materialized.has(path))
        throw new AnalysisOutputError(
          "extract_firmware",
          `Reported regular file is absent from materialized output: ${path}`,
        );
    }
    const files = [];
    const unpublished = [];
    tree = await SafeOutputTree.create(context.outputDirectory);
    for (const entry of context.entries) {
      if (entry.kind !== "file") {
        unpublished.push({
          relative_path: entry.relativePath,
          kind: entry.kind,
          link_target: entry.linkTarget,
        });
        continue;
      }
      const logicalPath = `$output/${entry.relativePath}`;
      const reported = context.normalized.files.get(logicalPath);
      const sha256 = await hashFirmwareFile(entry.path, context.signal);
      if (
        (reported?.sha256 !== null &&
          reported?.sha256 !== undefined &&
          reported.sha256 !== sha256) ||
        (context.normalized.sizes.has(logicalPath) &&
          context.normalized.sizes.get(logicalPath) !== entry.size)
      )
        throw new AnalysisOutputError(
          "extract_firmware",
          `Extracted bytes disagree with provider report: ${entry.relativePath}`,
        );
      await tree.write(
        entry.relativePath,
        createReadStream(entry.path),
        { sha256, bytes: entry.size },
        context.signal,
      );
      files.push({
        relative_path: entry.relativePath,
        path: join(tree.outputRoot, entry.relativePath),
        size: entry.size,
        sha256,
        reported_sha256: reported?.sha256 ?? null,
        mime_type: reported?.mimeType ?? null,
        analysis_depth: reported?.depth ?? null,
        runtime_address: null,
        original_file_range: null,
      });
    }
    result = firmwareResultSchemas.extract_firmware.parse({
      engine: context.engine,
      selection: context.selection,
      output_directory: tree.outputRoot,
      coverage:
        unpublished.length > 0 ? "partial" : context.normalized.coverage,
      files,
      unpublished_entries: unpublished,
      chunks: context.normalized.chunks,
      derivations: context.normalized.derivations,
      depth_limited_paths: context.normalized.depth_limited_paths,
      diagnostics: context.normalized.diagnostics,
      extraction_gaps: extractionGaps(
        unpublished,
        context.normalized,
        context.maxDepth,
      ),
      published_bytes: files.reduce((sum, file) => sum + file.size, 0),
    });
    context.signal.throwIfAborted();
    await tree.commit();
    return result;
  } catch (cause: unknown) {
    if (cause instanceof SafeOutputTreeCreationFailure) tree = cause.tree;
    try {
      await tree?.rollback();
    } catch (cleanupCause: unknown) {
      if (tree !== undefined) context.retainCleanup(tree);
      const publishedResult =
        tree?.published === true && result !== undefined
          ? {
              kind: "firmware" as const,
              result: jsonValueSchema.parse(result),
            }
          : undefined;
      throw new ProviderCleanupError(
        "unblob",
        [context.outputDirectory],
        {
          reason:
            cleanupCause instanceof Error
              ? cleanupCause.message
              : String(cleanupCause),
          previous_error:
            cause instanceof Error ? cause.message : String(cause),
        },
        {
          cause: cleanupCause,
          operation: "extract_firmware",
          ...(publishedResult === undefined
            ? {}
            : { partialObservation: publishedResult }),
        },
      );
    }
    if (tree?.published === true && result !== undefined) return result;
    throw cause;
  }
};

/** Derive explicit recovery rows from retained report facts; no new claims. */
/** Gap rows for missing-dependency reports: chunk-nested rows keep their owning chunk. */
const dependencyExtractionGaps = (
  normalized: ReturnType<typeof normalizeUnblobReport>,
): ExtractionGap[] => {
  // Chunk-nested dependency reports name the chunk that could not extract;
  // task-wide reports (standalone or multi-file) attach to the task.
  const chunkDependencies = new Set(
    normalized.chunk_missing_dependencies.map(({ input_path, provider_id }) =>
      JSON.stringify([input_path, provider_id]),
    ),
  );
  return [
    ...normalized.chunk_missing_dependencies.flatMap(
      ({ input_path, provider_id, dependencies }): ExtractionGap[] => {
        const affected = normalized.chunks.find(
          (chunk) =>
            chunk.input_path === input_path &&
            chunk.provider_id === provider_id,
        );
        return [
          {
            kind: "missing-extractor-dependency",
            input_path,
            ...emptyGap,
            ...(affected === undefined
              ? {}
              : {
                  handler: affected.handler,
                  provider_id,
                  range: affected.range,
                  root_file_range: affected.root_file_range,
                }),
            dependencies,
            continuation: GAP_CONTINUATIONS["missing-extractor-dependency"],
          },
        ];
      },
    ),
    ...normalized.missing_dependencies.flatMap(
      ({ input_path, dependencies }): ExtractionGap[] => {
        // Chunk-specific rows already covered this task's named chunks.
        const affected = normalized.chunks.filter(
          (chunk) =>
            chunk.input_path === input_path &&
            !chunkDependencies.has(
              JSON.stringify([chunk.input_path, chunk.provider_id]),
            ),
        );
        return (affected.length === 0 ? [null] : affected).map((chunk) => ({
          kind: "missing-extractor-dependency",
          input_path,
          ...emptyGap,
          ...(chunk === null
            ? {}
            : {
                handler: chunk.handler,
                provider_id: chunk.provider_id,
                range: chunk.range,
                root_file_range: chunk.root_file_range,
              }),
          dependencies,
          continuation: GAP_CONTINUATIONS["missing-extractor-dependency"],
        }));
      },
    ),
  ];
};

const extractionGaps = (
  unpublished: z.infer<
    typeof firmwareResultSchemas.extract_firmware
  >["unpublished_entries"],
  normalized: ReturnType<typeof normalizeUnblobReport>,
  maxDepth: number,
): ExtractionGap[] => {
  const dependencyGaps: ExtractionGap[] = dependencyExtractionGaps(normalized);
  const chunkGaps = (
    kind: ExtractionGap["kind"],
    matches: (chunk: (typeof normalized.chunks)[number]) => boolean,
  ): ExtractionGap[] =>
    normalized.chunks.filter(matches).map((chunk) => ({
      kind,
      input_path: chunk.input_path,
      ...emptyGap,
      handler: chunk.handler,
      provider_id: chunk.provider_id,
      range: chunk.range,
      root_file_range: chunk.root_file_range,
      dependencies: [],
      continuation: GAP_CONTINUATIONS[kind],
    }));
  const gaps: ExtractionGap[] = [
    ...dependencyGaps,
    ...chunkGaps("unknown-chunk-handler", (chunk) => chunk.handler === null),
    ...chunkGaps("encrypted-chunk", (chunk) => chunk.encrypted === true),
    ...normalized.depth_limited_paths.map((input_path): ExtractionGap => ({
      kind: "depth-limited",
      input_path,
      ...emptyGap,
      dependencies: [],
      continuation: depthContinuation(maxDepth),
    })),
    ...unpublished.map((entry): ExtractionGap => ({
      kind: "unpublished-entry",
      input_path: `$output/${entry.relative_path}`,
      ...emptyGap,
      relative_path: entry.relative_path,
      dependencies: [],
      continuation: GAP_CONTINUATIONS["unpublished-entry"],
    })),
  ];
  return gaps.sort((left, right) =>
    gapSortKey(left) < gapSortKey(right)
      ? -1
      : gapSortKey(left) > gapSortKey(right)
        ? 1
        : 0,
  );
};
