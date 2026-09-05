<!-- status: active; authority: normative; owner: rolo maintainers; last_reviewed: 2026-09-02 -->

# Target Evidence Deployment (Rolo v2)

Target evidence is a bounded, signed snapshot of what exists on the enrolled robot at collection
time. It is not a claim that the robot is physically safe or that a behavior is correct.

## Deployment modes

Rolo supports local collection and a controller-plus-target SSH Probe Runner. Both produce the same
target-bound `TargetEvidenceBundle`; only the execution location changes. A normal user does not
choose commands or runtime paths: the profile selects the target, and Rolo auto-assembles the
connector.

```text
TargetProfile
  → pinned SSH Connector (or local target)
  → bounded Probe in the target OS/Middleware environment
  → signed TargetEvidenceBundle
```

The MVP provider set is deliberately small. Hardware, OS and Middleware providers may be
implemented concretely on one target today; a future provider for another OS or Middleware uses
the same request, bundle, freshness and verification contracts. Application CLI help is optional
and must use an enrollment-time allowlist.

## Trust and failure boundaries

- Requests are read-only, target-bound, nonce-bound and short-lived.
- Bundles bind robot identity, probe runner identity, host fingerprint, request nonce, collection
  time, provider results, payload digest and HMAC signature.
- Rolo verifies the normalized payload, signature, freshness and exact provider set before any
  Agent planning uses it.
- The controller never substitutes its own OS, package, dynamic-library or Middleware environment
  for a missing target dependency. Missing tools and incomplete runtime context stay explicit
  (`UNAVAILABLE`, `PARTIAL`, `FAILED` or `TIMEOUT`).
- SSH uses `BatchMode=yes`, a dedicated pinned `known_hosts`, `StrictHostKeyChecking=yes`,
  `IdentitiesOnly=yes` for a pinned identity, no forwarding and no password fallback.
- Re-enrollment or probe runner rotation is explicit; changing a host key, identity, probe runner or
  provider setup invalidates the old pin instead of silently overwriting it.

## User-facing commands

```bash
rolo target profile init ssh://user@target.example/path/to/workspace --robot my-robot
rolo target inspect-profile --profile my-robot
rolo probe --profile my-robot --evidence-timeout 60
rolo target tool-surface --profile my-robot
```

Enrollment reuses the profile's ordinary SSH credential reference. Rolo does not install or
generate a second key for Probe, Trace, Certify or Tool execution; subsequent runs resolve the
same SSH agent or pinned identity reference automatically.

## Probe runner implementation boundary

The target probe runner may source only setup files explicitly pinned at enrollment. Each path and
digest is verified before collection; interactive shell profiles and Agent-selected paths are
never sourced. The probe runner returns bounded stdout/stderr and preserves failures and environment
limits as evidence. The current provider implementation has concrete setup handling, but the
bundle contract names only OS/Middleware semantics so other providers can be added without
changing the Agent ToolPlan or Conformance boundary.
