<!-- status: active; authority: guide -->

# Rolo skill bootstrap

1. Install the pinned Rolo distribution from the approved source and retain its version/digest.
2. Run `rolo --version`, `robotctl runtime health` and the contract/version check.
3. Configure or select a target profile, then run a read-only target-evidence preflight.
4. Load `skills/rolo/SKILL.md` and `skills/rolo-tool-planning/SKILL.md` before routing an intent.

A failed install, health check, contract check or preflight produces a structured `BLOCKED` result;
the harness must not execute a target operation. Upgrades are staged and reversible, and secrets
remain in the harness/provider environment. Rolo never calls back into the Agent.
