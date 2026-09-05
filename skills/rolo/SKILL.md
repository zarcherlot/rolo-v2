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
- When a requested capability is absent, use the Probe construction loop:
  run `rolo probe-analysis-input --evidence <bundle>`; keep the resulting JSON in
  the active harness conversation; load `rolo-harness-codegen` to prepare the
  typed arguments and derived target request once; let the harness iteratively
  write and test the generic adapter with the user; then submit its typed `ToolRegistrationProposal` with
  `rolo register-tool --proposal <proposal> --evidence <bundle>`. Registration
  is the harness interaction boundary in the MVP, so there is no second GUI
  approval step.
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

The skill is the harness playbook, not the registration authority. For every
tool, preserve the Probe evidence reference, proposal digest and registration
artifact. The harness may ask the user for corrections in its live coding
window; Rolo only accepts the resulting typed proposal, validates its target,
evidence and descriptor, and then makes the registered tool available to Trace.
The skill does not construct shell text or call `scp`/`rsync`. It invokes the
typed Rolo targetd/session API, which owns fixed SSH argv, bundle signatures,
provider bindings, deadlines, cancellation, receipts and evidence artifacts.
