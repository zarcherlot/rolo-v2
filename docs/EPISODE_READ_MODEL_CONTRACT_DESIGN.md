<!-- status: archived; authority: reference; owner: docs maintainers; last_reviewed: 2026-09-02; source_of_truth: docs/README.md -->

# Episode read-model contract design

Status: E2 server implementation available; public contract remains review-controlled
Target consumer: rolo-vis Episode Studio  
Base compatibility boundary: `rolo-vis-mvp-read-model-v1`

Implementation status: the control plane currently exposes the bounded collection, detail and
revision-pinned timeline surfaces and advertises `workbench.episode-read-model/v1`. This does not
imply that the full Episode Studio, live streaming, compare, replay or remediation surfaces exist.

## 1. Decision

Episode Studio requires a dedicated public read model. It must not consume internal
artifact manifests, `episode.inspect` tool results, `RobotUseRequest`, or model-provider
responses directly.

Three contract layers remain separate:

1. `episode.list`, `episode.inspect`, and `episode.export` are Canonical Operations for
   bounded control-plane access.
2. Episode, Observation Bundle, and `robot_use` artifacts are internal immutable
   producer records.
3. `rolo-episode-*/v1` is the sanitized Web read model owned by the control plane.

The first vertical slice covers published Episode metadata, bounded timeline events,
asset metadata, and evidence-linked findings. It does not expose artifact contents or
claim live streaming.

## 2. V1 contract family

| Model | Schema | Purpose |
| --- | --- | --- |
| Episode collection | `rolo-episode-collection/v1` | Bounded newest-first list |
| Episode summary | `rolo-episode-summary/v1` | Identity, lifecycle, outcome, coverage |
| Episode detail | `rolo-episode-detail/v1` | Timebase, lanes, expected/observed, findings |
| Timeline page | `rolo-episode-timeline-page/v1` | Cursor-paged events pinned to one revision |
| Timeline event | `rolo-episode-timeline-event/v1` | Safe event metadata and evidence links |
| Asset summary | `rolo-episode-asset-summary/v1` | Modality/provenance without artifact location |
| Finding summary | `rolo-episode-finding-summary/v1` | Fact, inference, human confirmation, verification |

The machine-readable design catalog is
`schemas/rolo-episode-contract-design-v1.json`.

## 3. API surface

```text
GET /v1/robots/{robot_id}/episodes
GET /v1/robots/{robot_id}/episodes/{episode_id}
GET /v1/robots/{robot_id}/episodes/{episode_id}/timeline
```

Collection filters are bounded to `since`, `until`, `state`, `limit`, and `offset`.
Timeline reads use an opaque cursor and require a `revision` returned by Episode
detail. This prevents page drift while a producer is still publishing an Episode.

The control plane advertises this surface as `workbench.episode-read-model/v1` in
`/health`. A client must not expose Episode navigation before that feature is present.

### E1 publication boundary

E1 reads only a server-owned, already sanitized persistence envelope:

```text
episodes/{robot_id}/published/{episode_id}.json
```

The envelope schema is `rolo-episode-published-projection/v1`; it contains one detail
projection and its bounded event metadata. It is not an API response and is not the
raw Episode manifest. Unknown fields or enums, mismatched identities/revisions,
symlinks, artifact references, URIs, host paths, payloads, prompts, credentials, and
unbounded values make the entire publication unavailable with an integrity error.

The E1 reference implementation consumes this publication boundary. E2 now creates it
from a committed producer record through a deliberate control-plane projection step.

### E2 committed record and projection

E2 accepts the internal `rolo-episode-producer-record/v1` contract at:

```text
episodes/{robot_id}/records/{episode_id}/revision-{revision}.json
```

Each record is bounded, content-digested, revision-linked, and created atomically
without overwriting an existing committed revision. A terminal immutable publication
cannot be superseded. Publication is idempotent only when the record and projected
content are identical.

The projector:

- maps internal evidence references to opaque Evidence IDs and registers sanitized
  records with the unified Evidence read model;
- excludes raw event payloads, raw analysis, command data, model prompts/responses,
  artifact references, and storage locations;
- downgrades unsupported non-declared events to declared missing-evidence alerts;
- withholds findings that have neither evidence nor an available observation asset;
- preserves `INFERRED / UNVERIFIED` for candidate causes regardless of confidence;
- keeps unavailable asset metadata visible while withholding bytes and locations;
- downgrades coverage and exposes limitations when clocks, assets, or evidence are
  incomplete.

The E2 mentorpi reference fixture is derived from the diagnostic semantics in the
local `rolo-data` snapshot: ROS 2 Humble is detected, runtime graph CLI probes are
unavailable, installed RMW candidates are not runtime proof, discovery remains
partial, the observation clock is degraded, and camera evidence is missing. No source
host path or raw payload is copied into the fixture's public projection.

V1 intentionally omits:

- WebSocket or server-sent live streams;
- raw telemetry series and arbitrary event payloads;
- asset-content or arbitrary artifact download endpoints;
- Episode compare;
- recollection, replay, invoke, cancel, or remediation actions.

## 4. Identity and lifecycle

Every model is bound to `robot_id` and `episode_id`. An Episode may additionally
reference safe product identities such as `execution_id`, `test_case_id`, lifecycle
`run_id`, and operation names. References are identifiers, never file paths or
artifact URIs.

Episode state and outcome are distinct:

- state: `RUNNING | COMPLETED | FAILED | CANCELLED | PARTIAL`
- outcome: `SUCCEEDED | FAILED | CANCELLED | UNKNOWN`
- verification: `VERIFIED | UNVERIFIED | NOT_AVAILABLE`

`COMPLETED` means collection ended. It does not imply task success. `SUCCEEDED` is the
producer's execution outcome. Only `VERIFIED` represents a separate verification
result, and it still carries evidence IDs and limitations.

Each detail response publishes an integer `revision`, `as_of`, and `immutable` flag.
A completed, fully committed Episode must be immutable. A running Episode may publish
a newer revision, but a timeline page never mixes revisions.

## 5. Time model

`started_at` is the Episode UTC anchor. Every timeline event has:

- `sequence`: unique monotonic integer inside a revision;
- `offset_ms`: non-negative offset from `started_at`;
- `occurred_at`: sanitized UTC timestamp;
- optional `duration_ms` for intervals;
- `clock_domain` and `synchronization` metadata.

Synchronization is `SYNCED | DEGRADED | UNSYNCED | UNKNOWN`. The UI must use
`offset_ms` for ordering and use `occurred_at` for display. It must never manufacture
precision when clock synchronization is degraded or unknown.

## 6. Timeline semantics

Timeline lanes are bounded product concepts:

- `COMMAND`
- `STATE`
- `TELEMETRY`
- `OBSERVATION`
- `ALERT`
- `AGENT`
- `CONFIGURATION`
- `CHECKPOINT`
- `GATE`
- `OUTCOME`

Events contain title, bounded summary, severity, evidence IDs, asset IDs, related
event IDs, and optional safe metric scalars. They never contain command input/output,
model prompts, model responses, arbitrary JSON payloads, secret values, or source
paths.

Authority is independent from lane:

- `DECLARED`: task/config intent;
- `OBSERVED`: machine observation;
- `INFERRED`: Agent or heuristic interpretation;
- `HUMAN_CONFIRMED`: explicit human assessment;
- `VERIFIED`: Verify-stage outcome.

An acknowledgement event cannot use `VERIFIED` authority unless a separate verified
outcome record exists.

## 7. Observation assets

V1 publishes asset metadata inline with Episode detail, but not bytes or locations.
Each asset summary includes:

- stable `asset_id`, modality, capture time, Episode offset, and source label;
- `PHYSICAL | SIMULATED | REPLAYED` world kind;
- `RAW | NORMALIZED | RENDERED | GUI_SCREENSHOT` evidence kind;
- frame, clock domain, synchronization, media type, byte count, and digest;
- data classification, evidence ID, availability, and limitations.

Forbidden fields include `artifact_ref`, local/remote path, probe runner identity,
credentials, signed URLs, raw hostnames, and arbitrary renderer configuration.

Media delivery requires a separately reviewed endpoint with server-owned
classification and authorization checks. Until then, rolo-vis shows asset metadata and
opens its sanitized Evidence record.

## 8. Findings and `robot_use`

Findings are projections, not raw `RobotUseSupervision` payloads:

- `OBSERVED_FACT`
- `CANDIDATE_CAUSE`
- `HUMAN_CONFIRMATION`
- `VERIFIED_OUTCOME`

Every finding binds to an Episode interval and at least one supporting evidence or
asset ID. Candidate causes may also list contradicting evidence. Confidence is shown
only where meaningful and never upgrades an inference to an observed or verified fact.

`RobotUseRequest/Supervision v1` remains unchanged. Future Observation Bundle and
Supervision v2 work may feed the projection, but is not a prerequisite for the first
metadata-only read model.

## 9. Safety and privacy invariants

- All Episode models are read-only and fail closed on unknown schemas or enums.
- `SECRET` records contribute only redacted counts and limitations; no payload appears.
- Paths, artifact URIs, model prompts/responses, credentials, and command payloads are
  forbidden recursively.
- Asset world kind is mandatory; simulated or replayed evidence cannot prove a
  physical outcome.
- Missing synchronization, calibration, or opposing evidence remains visible.
- The Web client cannot invoke `episode.export`, replay, collection, or remediation.

## 10. Resolved design choices

1. Episode public contracts belong to the control-plane read-model layer.
2. V1 reuses existing observation Operations; it adds no visualization Operation.
3. Internal Observation Bundles use immutable full manifests with an optional parent
   revision; the Web model exposes only the committed projection revision.
4. Diagnosis owns any future supplementary-check orchestration; `robot_use` remains an
   analysis service without execution authority.
5. The first reference fixture is a ROS 2 navigation Episode with camera, external
   pose, TF/odometry, costmap, lidar rendering, and a fixed RViz recipe.
6. A deterministic renderer is a Provider responsibility. A GUI screenshot is an
   explicit fallback and is unavailable without a pre-registered trusted session.
7. Observation Bundle is an Episode input/evidence component, not the Episode itself.
8. Agent findings remain advisory until independently confirmed or verified.

## 11. Delivery slices

### E1: Contract skeleton

- [x] Pydantic read models and generated JSON Schemas;
- [x] empty collection and one completed metadata-only Episode fixture;
- [x] collection/detail/timeline endpoints;
- [x] recursive unsafe-reference rejection tests.

### E2: Timeline and evidence projection

- [x] bounded lane projection from committed internal events;
- [x] stable cursor/revision rules;
- [x] asset metadata and finding summaries;
- [x] `rolo-data` fixture with clock degradation and missing evidence.

### E3: rolo-vis read-only shell

- Episode list, empty/unavailable states, timeline lanes, metadata inspector;
- fact/inference/verification labels;
- Evidence drawer integration;
- no media bytes, compare, live stream, or write actions.

### E4: Observation assets and diagnosis handoff

- separately reviewed media delivery contract;
- Observation Bundle/Supervision v2 projection;
- expected-versus-observed and diagnosis handoff.

Episode compare starts only after E1–E4 establish immutable identities and time
semantics.

## 12. Contract acceptance

- A client can order every event without trusting source-array order.
- Pagination cannot mix Episode revisions or robot identities.
- State, execution outcome, and verification remain independent.
- Facts, causes, human confirmation, and verified outcomes remain distinguishable.
- Every non-declared conclusion has evidence or asset support.
- No public response contains raw artifacts, paths, credentials, prompts, or payloads.
- Simulated/replayed assets never appear as physical proof.
- Unsupported contracts fail closed without falling back to demo data.
