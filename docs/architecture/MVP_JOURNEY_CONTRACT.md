status: frozen
authority: normative

# Rolo v2 LanderPi Agent Journey MVP contract

This document freezes the boundary between Probe evidence and the external
Agent, Trace, and Certify consumers.  The machine readable models live in
`rolo.mvp.contracts` and use versioned `rolo-mvp-*/v1` schema identifiers.

## Consumer actions

* `discover_target(target_id)` returns a target-bound `TargetCatalog`.  A tool
  is callable only when its Probe conformance is `PASS`, its catalog digest
  matches the session request, and `agent_callable` is true.
* `read_rkb(query)` returns `KNOWN`, `STALE`, or `UNKNOWN` and always carries
  evidence IDs and limitations.  Unknown values are never synthesized.
* `invoke_tool(tool_id, arguments, session_id)` is only available through a
  live Trace or Certify session.  The adapter does not expose a shell, topic
  publisher, arbitrary argv, or a generic proxy.
* `get_run(run_id)` returns the immutable event and artifact view for a run.

## Trace modes and refusal codes

`OBSERVATION_ONLY` permits read tools. `SUPERVISED_FIELD_DEBUG` additionally
permits Probe registered `experimental_write` tools, including write and motion
operations, when the user task, operator identity, and safety confirmation are
present. The MVP does not require an R1 pilot or a separate R3 canary contract;
the registered Tool remains the only execution path. `UNATTENDED_REMOTE` is
blocked in this MVP. Implementations use these stable refusal codes:

`TRACE_BLOCKED`, `CAPABILITY_NOT_OBSERVED`, `TOOL_NOT_CALLABLE`,
`WRITE_MODE_REQUIRED`, `SESSION_EXPIRED`, `TRACE_BUDGET_EXHAUSTED`, and
`RECOVERY_FAILED`.

Every call produces a `TraceEvent` with sequence, state, arguments, result,
and evidence ID. A failed call must either produce a bounded diagnosis and
recovery attempt or finish `UNKNOWN`/`BLOCKED` with an explanation.

## Certify report

The suite is target-bound and digest-addressed. Each case records expected and
actual values, status (`PASS`, `FAIL`, `BLOCKED`, `UNKNOWN`), operation ID,
evidence IDs, artifact digests, timing, and failure class. The runner emits a
JSON report and a Markdown projection from the same report object; Markdown is
never a second source of facts.
