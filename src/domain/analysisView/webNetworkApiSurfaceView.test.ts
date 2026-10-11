import { expect, it } from "vitest";
import {
  analysisViewCaptureFixture,
  analysisViewCaptureEvidence,
} from "../../../tests/fixtures/analysisView.js";
import { projectAnalysisView } from "./analysisView.js";

const project = (
  capture = analysisViewCaptureFixture(),
  offset = 0,
  limit = 50,
  parameters: unknown = { sensitive_value_count: 0 },
) => {
  const parent = analysisViewCaptureEvidence(capture);
  return projectAnalysisView(
    {
      evidenceId: parent.evidence_id,
      operation: parent.operation,
      normalizedResult: parent.normalized_result,
      limitations: [],
      parameters,
    },
    { kind: "api-surface", offset, limit },
  );
};
it("groups only exact formats, preserves literal routes, excludes URLs and produces deterministic digests", () => {
  const result = project();
  if (!result.ok || result.value.kind !== "api-surface")
    throw new Error("Expected surface");
  expect(project()).toEqual(result);
  const surface = result.value;
  expect(surface.groups.map((group) => group.path_template)).toEqual([
    "/api/CreateDocument",
    "/api/ListDocuments",
    "/api/Report2",
    "/api/Report3",
    "/api/v1/users",
    "/api/v2/users",
    "/dates/2023-02-29",
    "/dates/{iso-date}",
    "/ids/abc123",
    "/ids/{hex}",
    "/ids/{uuid}",
    "/users/{numeric}",
  ]);
  expect(surface.groups.at(-1)).toMatchObject({
    record_ordinals: [0, 1],
    statuses: [200, 404],
    content_types: ["application/json", "text/plain"],
    flags: ["mixed-statuses", "mixed-content-types"],
    templated_segments: [
      {
        segment_index: 1,
        rule: "numeric",
        basis: "inferred",
        observed_values: ["8812", "9031"],
      },
    ],
  });
  expect(surface.excluded_records).toEqual([
    { ordinal: 13, reason: "url-redacted" },
    { ordinal: 14, reason: "url-unparseable" },
  ]);
  expect(JSON.stringify(surface)).not.toContain("not-in-view");
  expect(JSON.stringify(surface)).not.toContain("雪");
});
it("pages groups independently of record completeness and preserves null digests", () => {
  const capture = analysisViewCaptureFixture();
  capture.artifact.sha256 = null;
  capture.total_records = 30;
  const result = project(capture, 10, 2);
  if (!result.ok) throw result.error;
  expect(result.value).toMatchObject({
    artifact: { sha256: null },
    coverage: { examined: 2, total: 12, exhausted: true, next_offset: null },
    records: { examined: 15, total: 30, excluded: 2 },
  });
  expect(result.value.limitations.join(" ")).toContain("ordinal subset");
  expect(project(capture, 50, 2)).toMatchObject({
    ok: true,
    value: {
      coverage: { status: "empty", exhausted: true, next_offset: null },
    },
  });
});
it("rejects native captures and malformed parents with typed errors", () => {
  const capture = analysisViewCaptureFixture();
  capture.format = "mitmproxy";
  expect(project(capture)).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisUnsupportedTargetError" },
  });
  expect(
    projectAnalysisView(
      {
        evidenceId: `ev_${"a".repeat(64)}`,
        operation: "inspect_web_network_capture",
        normalizedResult: {},
        limitations: [],
      },
      { kind: "api-surface", offset: 0, limit: 1 },
    ),
  ).toMatchObject({ ok: false, error: { _tag: "AnalysisInputError" } });
});

it("preserves partial response facts and explains unavailable requests", () => {
  const capture = analysisViewCaptureFixture();
  capture.records = capture.records.slice(0, 5);
  const values = [
    {
      request: {
        method: "GET",
        url: "https://user:password@api.example.test/1/2?private=value",
      },
      response: { status: 200, content: null },
    },
    { request: { method: null, url: "https://api.example.test/" } },
    null,
    { request: { method: "GET", url: "data:text/plain,hello" } },
    {
      request: { method: "GET", url: "https://api.example.test/1/2" },
      response: { status: null, content: { mimeType: "application/json" } },
    },
  ];
  capture.records.forEach((record, index) => {
    record.reported = values[index] ?? null;
  });
  const result = project(capture);
  if (!result.ok || result.value.kind !== "api-surface")
    throw new Error("Expected surface");
  expect(result.value.groups).toMatchObject([
    {
      origin: "https://api.example.test",
      path_template: "/{numeric}/{numeric}",
      statuses: [200],
      content_types: ["application/json"],
      templated_segments: [
        { segment_index: 0, observed_values: ["1"] },
        { segment_index: 1, observed_values: ["2"] },
      ],
    },
  ]);
  expect(result.value.excluded_records).toEqual([
    { ordinal: 1, reason: "method-unavailable" },
    { ordinal: 2, reason: "request-unavailable" },
    { ordinal: 3, reason: "url-unparseable" },
  ]);
  expect(result.value.unknowns).not.toEqual([]);
  expect(JSON.stringify(result.value)).not.toContain("password");
  expect(JSON.stringify(result.value)).not.toContain("private");
});

it("keeps encoded segments literal and distinguishes origin and method", () => {
  const capture = analysisViewCaptureFixture();
  capture.records = capture.records.slice(0, 4);
  const urls = [
    "https://a.test/%31",
    "https://a.test/1",
    "https://b.test/1",
    "https://a.test/1",
  ];
  capture.records.forEach((record, index) => {
    record.reported = {
      request: { method: index === 3 ? "POST" : "GET", url: urls[index]! },
      response: {
        status: 200,
        content: { mimeType: "application/json; charset=utf-8" },
      },
    };
  });
  const result = project(capture, 0, 2);
  if (!result.ok || result.value.kind !== "api-surface")
    throw new Error("Expected surface");
  expect(result.value.coverage).toMatchObject({
    total: 4,
    next_offset: 2,
    exhausted: false,
  });
  expect(result.value.groups[0]?.path_template).toBe("/%31");
});

it("refuses parents whose sensitive declarations it cannot check", () => {
  for (const parameters of [{ sensitive_value_count: 1 }, {}, null])
    expect(
      project(analysisViewCaptureFixture(), 0, 50, parameters),
    ).toMatchObject({
      ok: false,
      error: { _tag: "AnalysisUnsupportedTargetError" },
    });
});

it("treats HAR missing-response sentinels as unknown", () => {
  const capture = analysisViewCaptureFixture();
  capture.records = capture.records.slice(0, 1);
  capture.records[0]!.reported = {
    request: { method: "GET", url: "https://api.example.test/a" },
    response: { status: 0, content: { mimeType: " ; charset=utf-8" } },
  };
  const result = project(capture);
  if (!result.ok || result.value.kind !== "api-surface")
    throw new Error("Expected surface");
  expect(result.value.groups[0]).toMatchObject({
    statuses: [],
    content_types: [],
  });
  expect(result.value.unknowns).not.toEqual([]);
});

it("budgets path segment expansion before grouping", () => {
  const capture = analysisViewCaptureFixture();
  capture.records = capture.records.slice(0, 1);
  capture.records[0]!.reported = {
    request: {
      method: "GET",
      url: `https://api.example.test${"/1".repeat(800_000)}`,
    },
  };
  expect(project(capture)).toMatchObject({
    ok: false,
    error: { _tag: "AnalysisResourceConstraintError" },
  });
});

it("charges only templated segments and keeps recorded dot segments", () => {
  const capture = analysisViewCaptureFixture();
  capture.records = capture.records.slice(0, 3);
  const urls = [
    `https://api.example.test${"/a".repeat(800_000)}`,
    "https://api.example.test/a/%2e%2e/admin",
    "https://api.example.test/admin",
  ];
  capture.records.forEach((record, index) => {
    record.reported = { request: { method: "GET", url: urls[index] ?? null } };
  });
  const result = project(capture);
  if (!result.ok || result.value.kind !== "api-surface")
    throw new Error("Expected surface");
  expect(result.value.groups.map((group) => group.path_template)).toEqual(
    expect.arrayContaining(["/a/%2e%2e/admin", "/admin"]),
  );
  expect(result.value.groups).toHaveLength(3);
});
