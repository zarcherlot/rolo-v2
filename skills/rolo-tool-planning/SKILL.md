---
name: rolo-tool-planning
description: Turn a user goal and Rolo's discovered tool surface into a bounded, typed ToolPlan.
---

# Rolo Tool Planning

Use this skill after Rolo has produced a target-bound Tool Surface or Adapter Bundle. The
agent may choose tools and fill typed arguments, but Rolo remains the authority for discovery,
policy, execution, evidence, conformance, and release.

## Input

Require a Rolo target/session identity, the tool-surface digest, and the user's goal. If the
surface is absent or stale, ask Rolo for a fresh inspect/bootstrap result before planning.

## Output

Emit a bounded `rolo-tool-plan/v1` containing:

- `goal` and ordered `steps`;
- each step's exact `tool_id`, typed `arguments`, and expected observation;
- `mode` (`readonly` or `mutating`); registered experimental tools use `mutating`
  and the MVP CLI requires the explicit `--allow-mutating` execution switch;
- `surface_digest`, `target_id`, `session_id`, and a deterministic `plan_sha256`.
- `session_nonce` copied from the Tool Surface; it binds the plan to the exact session issuance.

Never emit shell text, free-form argv, guessed tool IDs, or a route that is not present in the
surface. A capability gap is a typed result (`CAPABILITY_GAP`) that points back to the missing
semantic contract; it is not permission to improvise a command. The orchestrator may then start
a bounded Probe gap path, where Rolo probes, verifies, conforms, and publishes only the new tool.

## Probe construction loop

When a capability is absent, the harness owns an interactive coding loop with
the user. Request `rolo probe-analysis-input --evidence <bundle>`, inspect its
  software-stack observations and evidence references, load `rolo-harness-codegen`
  to prepare the typed operation arguments and derived target request once, and
  implement the adapter in the current harness workspace. For a write-capable application Tool, emit an
evidence-bound `ExecutionBinding` describing the observed transport, bounded
parameters, feedback and stop strategy. Revise it with the user's feedback and
emit a typed `rolo-tool-registration-proposal/v1`; submit it with
`rolo register-tool --proposal <proposal> --evidence <bundle>`.

Rolo validates target identity, evidence references, binding endpoints against
Probe observations, descriptor schema, risk and digests, then persists the
registered application Tool. No pre-existing route is required; transport
execution remains inside Rolo's typed provider boundary. The harness
conversation is the MVP review loop, so there is no second rolo-vis approval
step. Every registered Tool remains callable only through a target-bound Rolo
session and typed ToolPlan. The same protocol applies to rotation, mapping,
navigation and future application adapters.
