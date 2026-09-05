<!-- status: archived; authority: reference; owner: docs maintainers; last_reviewed: 2026-09-02; source_of_truth: docs/README.md -->

# Episode Observation Bundle public contract design

Status: E22A approved; E22B producer implemented and review-controlled; E22C consumer deferred

Target consumer: rolo-vis Episode Studio

Base contract: `workbench.episode-read-model/v1`

Candidate feature: `workbench.episode-observation-bundle/v1`

Implementation status: the control plane exposes the reviewed read-only producer/projection and
advertises `workbench.episode-observation-bundle/v1`. E22B does not add capture, media delivery,
recollection, replay, export or write authority; those surfaces remain deferred to later review.

## 1. Decision

An Observation Bundle is an immutable input/evidence component of an Episode. It is
not a second Episode, an asset-content envelope, a model request, or a verification
result.

The public contract exposes only a revision-pinned, sanitized summary of which source
classes and already-published Episode assets participated in a model observation
window. Internal bundle manifests, provider records, renderer configuration, raw
telemetry, prompts, responses, host identities, artifact references, and bytes remain
behind the control-plane projection boundary.

E22 extends the existing Episode v1 family instead of changing its seven frozen
schemas. Existing `rolo-episode-asset-summary/v1` records remain the authority for
asset metadata. A bundle references those records by `asset_id`; it cannot replace or
silently enrich them.

## 2. Candidate contract family

| Model | Schema | Purpose |
| --- | --- | --- |
| Bundle collection | `rolo-episode-observation-bundle-collection/v1` | Revision-pinned, bounded bundle history |
| Bundle summary | `rolo-episode-observation-bundle-summary/v1` | Immutable observation window and safe evidence references |
| Source coverage | `rolo-episode-observation-source-coverage/v1` | Sanitized source availability, time/spatial quality, and limitations |

The machine-readable decision catalog is
`schemas/rolo-episode-observation-bundle-contract-design-v1.json`.

## 3. Candidate API surface

```text
GET /v1/robots/{robot_id}/episodes/{episode_id}/observation-bundles
    ?revision={revision}&limit={1..20}&cursor={opaque}
```

The endpoint is unavailable unless `/health` advertises
`workbench.episode-observation-bundle/v1`. `revision` is mandatory and must identify
the exact immutable Episode projection used to resolve every referenced asset and
Evidence record. Pages must not mix Episode revisions, robot identities, or bundle
sequences.

An unknown Episode is `404`; a missing, future, or non-current requested revision is
`409`; malformed paging input is `422`; and a publication-integrity failure is `500`.
The endpoint is read-only and provides no content, capture, recollection, replay, or
export action.

## 4. Bundle summary

`rolo-episode-observation-bundle-summary/v1` exposes only:

- `robot_id`, `episode_id`, and `episode_revision`;
- stable `bundle_id`, positive monotonic `sequence`, and optional `parent_bundle_id`;
- `trigger_kind`: `INITIAL | SUPPLEMENTARY`;
- `status`: `COMPLETE | PARTIAL | UNAVAILABLE`;
- sanitized `created_at`, `window_start_offset_ms`, and `window_end_offset_ms`;
- `synchronization`: `SYNCED | DEGRADED | UNSYNCED | UNKNOWN`;
- `spatial_alignment`: `ALIGNED | DEGRADED | UNALIGNED | UNKNOWN`;
- `world_scope`: `NONE | PHYSICAL_ONLY | SIMULATED_ONLY | REPLAYED_ONLY | MIXED`;
- bounded source-coverage records, existing Episode `asset_ids`, safe `evidence_ids`,
  and bounded limitations;
- literal `influences_verification: false`.

Sequence is the ordering authority. Pages are newest-first with strictly descending
sequence values; `created_at` is display metadata and must not be used to repair an
invalid sequence. A parent, when present, must have a lower sequence in the same robot,
Episode, and Episode revision. A page may reference a parent on an older page, but a
complete traversal must resolve the chain and reject cycles or dangling parents.

`SUPPLEMENTARY` says only that the bundle followed an earlier observation window. It
does not reveal who requested it, prove that an Agent acted correctly, or grant a Web
client authority to request another capture.

## 5. Source coverage

`rolo-episode-observation-source-coverage/v1` exposes only:

- stable sanitized `source_id` and bounded `label`;
- `source_kind`: `ONBOARD_SENSOR | EXTERNAL_MEASUREMENT | ROBOT_STATE |
  SPATIAL_MODEL | DETERMINISTIC_RENDER | TRUSTED_GUI_CAPTURE | SIMULATION`;
- bounded `modality` and mandatory `world_kind`;
- `availability`: `AVAILABLE | MISSING | STALE | REJECTED | UNAVAILABLE`;
- synchronization and spatial-alignment states owned by the producer;
- references to assets already published in the same Episode revision;
- bounded limitations.

`source_id` is a product identity, never a probe runner, hostname, process, credential,
adapter, topic, device path, or storage identity. `REJECTED` indicates a policy or
contract refusal, not a physical failure. `MISSING`, `STALE`, and `UNAVAILABLE` remain
distinct and visible. `AVAILABLE` and `STALE` may reference published assets;
`MISSING`, `REJECTED`, and `UNAVAILABLE` must have empty asset lists.

## 6. Cross-model integrity

- Every `asset_id` must resolve to exactly one `rolo-episode-asset-summary/v1` in the
  same Episode revision.
- Every source-level asset must also occur in the bundle-level bounded `asset_ids`.
- Every Evidence ID must resolve through the existing sanitized Evidence read model.
- Bundle window offsets are closed-open and must remain inside the Episode interval.
- `world_scope` is derived only from asset-bearing participating source world kinds;
  it is `NONE` when the bundle has no assets, and `MIXED` never proves a physical
  result. Missing or rejected declared sources do not change the scope.
- Bundle and source synchronization or alignment limitations cannot be omitted when
  their state is degraded, unsynchronized, unaligned, or unknown.
- `COMPLETE` means the declared bundle inputs were assembled. It does not mean the
  task succeeded, the observation was sufficient, or any finding was verified.

## 7. Projection and rejection boundary

The projector may read an internal immutable full manifest with an optional parent
revision. The public model must recursively reject or omit the complete publication
when it encounters:

- artifact references, local/remote paths, URIs, signed URLs, raw hostnames, device or
  topic names, probe runner/provider identity, credentials, or storage locations;
- raw command, telemetry, state, TF, point-cloud, map, calibration, renderer, or model
  payloads;
- prompts, model responses, arbitrary JSON, image bytes, media URLs, or content keys;
- unbounded text, source lists, asset lists, Evidence lists, or limitations;
- unknown schemas or enums, duplicate IDs/sequences, mixed Episode revisions, unsafe
  parent links, missing asset references, or `influences_verification: true`.

## 8. Authority boundary

Observation Bundle metadata may explain the input coverage of an Episode finding. It
does not establish execution outcome, causal correctness, human confirmation,
verification, release authority, or readiness. Simulated and replayed sources remain
visually and semantically separate from physical sources.

E22A added no runtime surface. E22B implements only the reviewed read-only producer
record, server-owned projection, feature advertisement, and exact-revision endpoint.
It still adds no asset-content delivery, live stream, browser storage, identity,
capture request, supplementary-check orchestration, recollection, replay, export,
remediation, deployment, verification influence, or robot write authority.

## 9. Delivery slices

### E22A: cross-repository contract design

- freeze the public schemas, endpoint shape, revision rules, enums, and rejection
  boundary;
- freeze the rolo-vis consumer and trust-language contract;
- add no runtime feature advertisement or UI.

### E22B: rolo producer and safe projection

- [x] add bounded, digest-validated internal producer records and a server-owned
  projection;
- [x] implement exact-revision reads, opaque pagination, and cross-model integrity
  checks;
- [x] publish one ROS navigation fixture with degraded synchronization plus missing and
  policy-rejected sources;
- [x] generate and pin the producer, publication-envelope, and public collection JSON
  Schemas.

### E22C: rolo-vis consumer and Perspective Tray

- add feature-negotiated parser/client support;
- render source coverage, time/spatial quality, world kind, assets, and limitations;
- reuse the existing Evidence/asset metadata surfaces without fetching bytes.

### E22D: validation and `v0.37.0` baseline candidate

- run complete two-repository and live `rolo-data` gates;
- prove partial, unavailable, mixed-world, stale-reference, and unsafe-field failure;
- promote only after explicit review; production deployment remains separate.

## 10. Acceptance decisions

E22A is ready for review when both repositories agree that:

1. Bundle history is exact-revision, bounded, immutable, and ordered only by sequence.
2. Existing Episode assets and Evidence records remain authoritative.
3. Time synchronization and spatial alignment are independent producer-owned facts.
4. Physical, simulated, replayed, and mixed inputs cannot be collapsed.
5. Missing, stale, rejected, and unavailable sources remain distinguishable.
6. Bundle completeness never upgrades outcome, finding authority, or verification.
7. The Web client receives no raw content, location, identity, or capture authority.
