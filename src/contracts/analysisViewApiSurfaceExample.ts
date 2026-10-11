/** Generated from the two-request apiSurfaceHar fixture through the HAR decoder and view service. */
export const API_SURFACE_EXAMPLE = {
  input: {
    source: {
      kind: "retained-evidence",
      evidence_id:
        "ev_9e218c18bc6159ec9c8492a9130c286496fb1b6d9f03ec2f4ea3321ce2b15097",
    },
    view: {
      kind: "api-surface",
      offset: 0,
      limit: 50,
    },
  },
  output: {
    parent_evidence_id:
      "ev_9e218c18bc6159ec9c8492a9130c286496fb1b6d9f03ec2f4ea3321ce2b15097",
    parent_operation: "inspect_web_network_capture",
    parent_digest:
      "9e218c18bc6159ec9c8492a9130c286496fb1b6d9f03ec2f4ea3321ce2b15097",
    view_digest:
      "61d5d54d2de92af05775f19e7460ab7a2b645a8ffc7d5bb8f7da18c5d2cba0b8",
    artifact: {
      path: "/fixtures/api-surface.har",
      sha256:
        "bf58e2c06e55bfe7e0628157c4ad027ce0aeb81a10e8edef8a7f95b8e5f14225",
    },
    coverage: {
      status: "page",
      examined: 1,
      total: 1,
      next_offset: null,
      exhausted: true,
    },
    limitations: [
      "Grouping does not establish handler identity, URL-space schemas or causality.",
    ],
    unknowns: [],
    records: {
      examined: 2,
      total: 2,
      excluded: 0,
    },
    groups: [
      {
        method: "GET",
        origin: "https://api.example.test",
        path_template: "/users/{numeric}",
        templated_segments: [
          {
            segment_index: 1,
            rule: "numeric",
            basis: "inferred",
            observed_values: ["8812", "9031"],
          },
        ],
        record_ordinals: [0, 1],
        statuses: [200, 404],
        content_types: ["application/json", "text/plain"],
        flags: ["mixed-statuses", "mixed-content-types"],
      },
    ],
    excluded_records: [],
    kind: "api-surface",
    view: {
      kind: "api-surface",
      offset: 0,
      limit: 50,
    },
  },
} as const;
