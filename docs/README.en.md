<!-- status: active; authority: guide; owner: docs maintainers; last_reviewed: 2026-09-02 -->

# Rolo v2 documentation

Rolo v2 is a small, evidence-backed target tool layer for Codex-like Agents. The product chain is:

```text
TargetProfile → SSH Connector → TargetEvidenceBundle
             → NativeToolSession → Agent ToolPlan → Conformance
             ↘ application Candidate → Adapter bundle → application Conformance (named gaps only)
```

## Core documents

- [v2 architecture](architecture/ARCHITECTURE.md): user, Agent, Rolo, and robot responsibilities;
- [engineering status](reference/ENGINEERING_STATUS.md): implementation maturity and evidence;
- [Agent-native Tool standard](probe/AGENT_NATIVE_TOOLS.md): the four small Tool Surface contracts;
- [Application gap bundles](probe/APPLICATION_GAP_BUNDLES.md): narrow startup/navigation/mapping/manipulation loops;
- [v1 application operation inventory](probe/APPLICATION_OPERATION_V1_INVENTORY.md): the 137-operation backlog and first LanderPi slice;
- [implementation map](reference/IMPLEMENTATION_MAP.md): code, schemas, artifacts, and tests;
- [physical target enrollment record](validation/ROLO_V2_TARGET_ENROLLMENT_20260902.md): one real-target verification.

## Next phase (RKB drafts)

- [RKB design](architecture/ROBOT_KNOWLEDGE_BASE_FOR_AGENT_DEBUGGING_ZH.md): fact layers,
  provenance, and freshness rules;
- [plan review](review/ROLO_V2_RKB_DEVELOPMENT_PLAN_REVIEW_ZH.md): baseline corrections and blockers;
- [executable development plan](architecture/ROLO_V2_RKB_EXECUTION_PLAN_ZH.md): the single RKB
  scheduling entry point.
- [Probe post-controlled write execution plan (RKB read-only prerequisite)](architecture/ROLO_V2_RKB_WRITE_TRANSITION_PLAN_ZH.md):
  gates for a future, explicitly authorized write-execution pilot; RKB itself never executes device writes.

The root `OPERATION_CONTRACTS.md`, `CANONICAL_OPERATIONS.md`, and Episode contract files, plus
`architecture/WORKBENCH_PLUGIN_HOST_CONTRACT.md`, are retained only because generators or existing
tests reference them. They are not entry points for new feature design.

## Directory responsibilities

| Directory | Scope |
|---|---|
| `architecture/` | Current architecture, engineering principles, and RKB design/plan drafts |
| `getting-started/` | Copyable installation and Probe journeys |
| `probe/` | Agent-native Tools, application gaps, and operation reference |
| `reference/` | Engineering status and implementation map |
| `setup/` | Configuration and runtime prerequisites |
| `target/` | Target evidence deployment and binding boundaries |
| `validation/` | Current fixed-target enrollment evidence |
| `review/` | Design reviews and unresolved blockers, not normative contracts |

## Four stable standards

Rolo exposes four platform-neutral semantic families: hardware, OS, Middleware, and application.
The MVP may implement a concrete provider for only part of this surface. Provider IDs, commands,
and runtime dependencies are implementation details; they must not change the family contracts or
turn an unobserved target capability into a fact.

## User entry points

```bash
rolo target profile init ssh://user@target.example/path/to/workspace --robot my-robot
rolo target inspect-profile --profile my-robot
rolo target tool-surface --profile my-robot
rolo target tool-plan --profile my-robot PLAN.json
robotctl probe target-evidence --help
```

Normal use names only a profile. Rolo selects an approved host key, SSH agent, or pinned identity;
the Agent interprets the target and writes a plan, while Rolo owns fixed argv, target binding,
budgets, evidence, and Conformance.

## Documentation governance

This directory keeps only the entry points, contracts, status, and validation material needed to
develop v2. Older Registry, lifecycle, platform-specific plans, and historical evidence were
removed from the working tree; their full contents remain available in Git history and are not
implementation authority.
