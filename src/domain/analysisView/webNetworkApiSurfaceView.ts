import { z } from "zod";
import { uniqueSorted } from "../canonicalOrdering.js";
import { compareUnicodeCodePoints as compare } from "../unicodeCodePointOrder.js";
import {
  AnalysisResourceConstraintError,
  AnalysisUnsupportedTargetError,
} from "../analysisErrorCore.js";
import type { AnalysisError } from "../analysisErrorBase.js";
import { err, ok, type Result } from "../result.js";
import {
  WEB_NETWORK_CAPTURE_LIMITS,
  webNetworkCaptureSchema,
} from "../webNetworkCapture.js";
import {
  analysisViewInputError,
  type AnalysisViewParent,
  type AnalysisViewRequest,
  type UnsignedAnalysisView,
} from "./analysisView.js";
import { pageViewCoverage } from "./analysisViewCoverage.js";

export const apiSurfaceViewSchema = z.strictObject({
  kind: z.literal("api-surface"),
  offset: z.number().int().nonnegative().default(0),
  limit: z.number().int().positive().default(50),
});
const ruleSchema = z.enum(["numeric", "uuid", "hex", "iso-date"]);
const groupSchema = z.strictObject({
  method: z.string(),
  origin: z.string(),
  path_template: z.string(),
  templated_segments: z.array(
    z.strictObject({
      segment_index: z.number().int().nonnegative(),
      rule: ruleSchema,
      basis: z.literal("inferred"),
      observed_values: z.array(z.string()),
    }),
  ),
  record_ordinals: z.array(z.number().int().nonnegative()),
  statuses: z.array(z.number()),
  content_types: z.array(z.string()),
  flags: z.array(
    z.enum(["single-sample", "mixed-statuses", "mixed-content-types"]),
  ),
});
export const apiSurfaceFields = {
  records: z.strictObject({
    examined: z.number().int().nonnegative(),
    total: z.number().int().nonnegative(),
    excluded: z.number().int().nonnegative(),
  }),
  groups: z.array(groupSchema),
  excluded_records: z.array(
    z.strictObject({
      ordinal: z.number().int().nonnegative(),
      reason: z.enum([
        "url-redacted",
        "url-unparseable",
        "request-unavailable",
        "method-unavailable",
      ]),
    }),
  ),
};
type Group = z.output<typeof groupSchema>;
type Surface = Extract<UnsignedAnalysisView, { kind: "api-surface" }>;
const requestSchema = z.object({
  request: z.object({ url: z.unknown(), method: z.unknown() }),
});
const contentSchema = z.object({ mimeType: z.unknown().optional() });
const responseSchema = z.object({
  response: z.object({
    status: z.unknown().optional(),
    content: z.unknown().optional(),
  }),
});

// Upper bound of serialized bytes one templated segment adds to a group.
const TEMPLATED_SEGMENT_BYTES = 128;

/** Recorded path before WHATWG dot-segment removal; query and fragment excluded. */
const recordedPath = (url: string): string => {
  const authority = url.indexOf("//");
  const start = authority < 0 ? url.indexOf(":") + 1 : authority + 2;
  const tail = url.slice(start);
  const end = tail.search(/[?#]/u);
  const beforeQuery = end < 0 ? tail : tail.slice(0, end);
  const slash = authority < 0 ? 0 : beforeQuery.indexOf("/");
  return slash < 0 ? "/" : beforeQuery.slice(slash);
};

const segmentRule = (value: string): z.output<typeof ruleSchema> | null => {
  if (/^[0-9]+$/.test(value)) return "numeric";
  if (
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      value,
    )
  )
    return "uuid";
  if (/^[0-9a-f]{32,}$/i.test(value)) return "hex";
  if (/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value)) {
    const date = new Date(`${value}T00:00:00.000Z`);
    if (
      Number.isFinite(date.getTime()) &&
      date.toISOString().slice(0, 10) === value
    )
      return "iso-date";
  }
  return null;
};

/** Group retained HAR request lines; format matches do not establish handler identity. */
export const projectWebNetworkApiSurfaceView = (
  parent: AnalysisViewParent,
  view: AnalysisViewRequest,
): Result<UnsignedAnalysisView, AnalysisError> => {
  const unsupported = (reason: string) =>
    err(
      new AnalysisUnsupportedTargetError(
        "inspect_analysis_view",
        parent.evidenceId,
        reason,
      ),
    );
  if (
    parent.operation !== "inspect_web_network_capture" ||
    view.kind !== "api-surface"
  )
    return unsupported(
      `View ${view.kind} is unsupported for parent operation ${parent.operation}; api-surface requires inspect_web_network_capture.`,
    );
  const parsed = webNetworkCaptureSchema.safeParse(parent.normalizedResult);
  if (!parsed.success)
    return err(
      analysisViewInputError([
        {
          path: ["source"],
          reason: "invalid_value",
          message:
            "Parent Evidence result does not match inspect_web_network_capture.",
        },
      ]),
    );
  const capture = parsed.data;
  if (capture.format !== "har")
    return unsupported(
      `api-surface does not support capture format ${capture.format}.`,
    );
  const declarations = z
    .object({ sensitive_value_count: z.number().int().nonnegative() })
    .safeParse(parent.parameters);
  if (!declarations.success || declarations.data.sensitive_value_count > 0)
    return unsupported(
      "api-surface authors path templates and limitation text that cannot be checked against sensitive_values declarations, which the parent Evidence does not retain. Project a capture inspected without declarations.",
    );
  const buckets = new Map<string, Group>();
  const excluded: Surface["excluded_records"] = [];
  let unavailableResponse = false;
  let projectedBytes = 0;
  for (const record of capture.records) {
    const request = requestSchema.safeParse(record.reported);
    if (!request.success) {
      excluded.push({ ordinal: record.ordinal, reason: "request-unavailable" });
      continue;
    }
    const { url, method } = request.data.request;
    if (url === null) {
      excluded.push({ ordinal: record.ordinal, reason: "url-redacted" });
      continue;
    }
    let parsedUrl: URL;
    try {
      if (typeof url !== "string") throw new TypeError("Unavailable URL");
      parsedUrl = new URL(url);
      if (parsedUrl.origin === "null") throw new TypeError("URL has no origin");
    } catch {
      excluded.push({ ordinal: record.ordinal, reason: "url-unparseable" });
      continue;
    }
    if (typeof method !== "string" || method.length === 0) {
      excluded.push({ ordinal: record.ordinal, reason: "method-unavailable" });
      continue;
    }
    const path = recordedPath(url);
    const segments: Group["templated_segments"] = [];
    let overBudget = false;
    const template = path
      .split("/")
      .map((value, index) => {
        const rule = segmentRule(value);
        if (rule === null || overBudget) return value;
        projectedBytes += TEMPLATED_SEGMENT_BYTES + value.length;
        if (projectedBytes > WEB_NETWORK_CAPTURE_LIMITS.outputBytes) {
          overBudget = true;
          return value;
        }
        segments.push({
          segment_index: index - 1,
          rule,
          basis: "inferred",
          observed_values: [value],
        });
        return `{${rule}}`;
      })
      .join("/");
    if (overBudget)
      return err(
        new AnalysisResourceConstraintError(
          "inspect_analysis_view",
          "memory",
          "Retained templated segments would exceed the capture reply budget.",
          { output_bytes: WEB_NETWORK_CAPTURE_LIMITS.outputBytes },
        ),
      );
    const key = JSON.stringify([method, parsedUrl.origin, template]);
    let group = buckets.get(key);
    if (group === undefined) {
      group = {
        method,
        origin: parsedUrl.origin,
        path_template: template,
        templated_segments: segments,
        record_ordinals: [],
        statuses: [],
        content_types: [],
        flags: [],
      };
      buckets.set(key, group);
    } else {
      // Equal templates have the same ordered rule positions.
      const existingSegments = group.templated_segments;
      segments.forEach((segment, index) => {
        existingSegments[index]?.observed_values.push(
          ...segment.observed_values,
        );
      });
    }
    group.record_ordinals.push(record.ordinal);
    const response = responseSchema.safeParse(record.reported);
    const status = response.success ? response.data.response.status : undefined;
    const content = contentSchema.safeParse(
      response.success ? response.data.response.content : undefined,
    );
    const mime = content.success ? content.data.mimeType : undefined;
    // HAR uses status 0 and an empty mimeType for an unavailable response.
    if (typeof status === "number" && status !== 0) group.statuses.push(status);
    else unavailableResponse = true;
    const essence =
      typeof mime === "string" ? mime.split(";", 1).join("").trim() : "";
    if (essence.length > 0) group.content_types.push(essence);
    else unavailableResponse = true;
  }
  const groups = [...buckets.values()].sort(
    (a, b) =>
      compare(a.origin, b.origin) ||
      compare(a.path_template, b.path_template) ||
      compare(a.method, b.method),
  );
  for (const group of groups) {
    group.statuses = [...new Set(group.statuses)].sort((a, b) => a - b);
    group.content_types = uniqueSorted(group.content_types);
    for (const segment of group.templated_segments)
      segment.observed_values = uniqueSorted(segment.observed_values);
    if (group.record_ordinals.length === 1) group.flags.push("single-sample");
    if (group.statuses.length > 1) group.flags.push("mixed-statuses");
    if (group.content_types.length > 1) group.flags.push("mixed-content-types");
  }
  const page = groups.slice(view.offset, view.offset + view.limit);
  return ok({
    kind: "api-surface",
    view,
    parent_evidence_id: parent.evidenceId,
    parent_operation: "inspect_web_network_capture",
    parent_digest: parent.evidenceId.slice(3),
    artifact: { path: capture.artifact.path, sha256: capture.artifact.sha256 },
    coverage: pageViewCoverage(view.offset, page.length, groups.length),
    records: {
      examined: capture.records.length,
      total: capture.total_records,
      excluded: excluded.length,
    },
    groups: page,
    excluded_records: excluded,
    limitations: [
      ...parent.limitations,
      "Grouping does not establish handler identity, URL-space schemas or causality.",
      ...(capture.records.length < capture.total_records
        ? [
            "Parent contains an ordinal subset; the surface covers only retained records.",
          ]
        : []),
    ],
    unknowns: unavailableResponse
      ? [
          "Some retained records have unavailable status or content type values.",
        ]
      : [],
  });
};
