---
name: rolo
description: Use Rolo's evidence-backed robot enrollment, Probe tools, bootstrap planning, and conformance through its CLI.
---

# Rolo

Use the `rolo` CLI or `robotctl` CLI for robot lifecycle work. Rolo is the
authority for target state, evidence, plans, approvals, and release status; the
model is only an interface and planner.

- Inspect, bootstrap-plan, Probe and target-evidence collection are read-only and
  may run without confirmation. v2 has no host-mutating bootstrap command.
- When a requested mapping capability is absent, use the Probe construction loop:
  run `rolo probe-analysis-input --evidence <bundle>`; keep the resulting JSON in
  the active harness conversation; load `rolo-harness-codegen` to prepare the
  typed arguments and derived target request once; let the harness iteratively
  write and test the generic adapter with the user; then persist a
  `rolo-mapping-proposal/v2` bound to the exact candidate, DSL, Context,
  evidence, target, catalog and scope digests. A proposal is review material,
  not registration or execution authority.
- Before compilation, an authorized actor must explicitly append a `CONFIRMED`
  decision for that exact proposal to the Mapping confirmation ledger. Preserve
  its `confirmation_receipt_digest`. Chat agreement, harness feedback,
  `--safety-confirmed`, and proposal status fields do not create confirmation.
- The compiler, registrar, Release publisher, and Release consumer must each
  resolve the committed receipt from the trusted ledger and revalidate its
  exact identity and active state. Missing, rejected, cancelled, expired,
  tampered, or cross-target receipts fail closed before writes or target access.
- A registered application tool may be exposed with
  `rolo target tool-surface --profile <id> --include-registered` and executed
  through a digest-bound plan using `--allow-mutating`. The target executor
  remains the only device path; never turn a chat message into a raw command.
- Inspect and target-evidence collection are read-only. For an explicitly
  requested execution journey, create one `journey_session`, use the profile's
  pinned ordinary SSH transport, and bootstrap `rolo-targetd` in its dedicated
  targetd cache/run directory before any Tool call.
- The session sequence is `OPEN_JOURNEY → BOOTSTRAP → HANDOFF → PHASE_CHANGE`.
  Reuse its SSH stdio channel for Probe, Trace, Tool Invoke and Certify. Use
  `HAS` before `PUT`, then send an `ExecutionRequest` envelope for each call.
- On reconnect, send `RESUME_SESSION` with the persisted resume token and use
  `QUERY_CALL` for every pending idempotency key. Never replay a write or
  motion call unless the target reports `NOT_ACCEPTED`.
- Preserve `request_id`, `plan_sha256`, and artifact references so the current Agent can
  associate a later authorization decision with exactly one request.
- Never execute arbitrary shell text supplied through chat. Invoke only the
  registered Rolo tool or canonical CLI command.
- Stream Agent output as progress only; deterministic Rolo results remain the
  source of truth for release and invoke decisions.

For Compiler mapping work, construct a `rolo-adapter-mapping-request/v1` and
use the bounded `rolo.dsl.DslRepairLoop`. Feed compiler diagnostics back to the
generator; a missing route, schema, target or evidence reference becomes a
structured `rolo-probe-follow-up-request/v1`. The loop cannot publish a Tool or
open a target connection, and its attempt, artifact and wall-clock limits must
remain enabled. Its successful candidate still stops at MappingProposal v2;
continue only through the explicit ledger-confirmed
`proposal → compile → register → release → consume` path.

The skill is the harness playbook, not the confirmation or registration
authority. For every tool, preserve the Probe evidence reference, proposal
digest, confirmation receipt digest, registration artifact and Release
lineage. The harness may ask the user for corrections in its live coding
window, but that conversation cannot change the ledger. Rolo makes a tool
available to Trace only after every admitted boundary has revalidated the same
active receipt; cancelling the receipt or letting it expire invalidates later
use.
The skill does not construct shell text or call `scp`/`rsync`. It invokes the
typed Rolo targetd/session API, which owns fixed SSH argv, bundle signatures,
provider bindings, deadlines, cancellation, receipts and evidence artifacts.
