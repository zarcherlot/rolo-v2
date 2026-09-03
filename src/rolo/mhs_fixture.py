"""No-load safety test-fixture evidence for MHS W3/W4.

This module records observations; it does not operate GPIO, serial, ROS, or
any actuator.  A deployment-specific fixture adapter can feed the same record
format after an operator has performed the physical test.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .mhs_manifest_records import MhsSafetyEvidence, MhsSafetyEvidenceBundle


_TESTS = ("external_estop", "stop", "rollback", "watchdog", "no_load")


class MhsBenchFixture:
    """Evidence recorder with fail-closed defaults for an isolated bench."""

    def __init__(self, fixture_id: str, *, resource_id: str) -> None:
        self.fixture_id = fixture_id
        self.resource_id = resource_id
        self._evidence = {
            key: MhsSafetyEvidence(
                status="NOT_OBSERVED",
                notes="test has not been performed",
            )
            for key in _TESTS
        }

    def record(
        self,
        test: str,
        *,
        status: str,
        source_refs: list[str] | None = None,
        notes: str = "",
    ) -> MhsSafetyEvidence:
        if test not in _TESTS:
            raise ValueError(f"unknown fixture test: {test}")
        evidence = MhsSafetyEvidence(
            status=status,  # type: ignore[arg-type]
            source_refs=list(source_refs or []),
            notes=notes,
        )
        self._evidence[test] = evidence
        return evidence

    def bundle(self) -> MhsSafetyEvidenceBundle:
        return MhsSafetyEvidenceBundle(**self._evidence)

    def evidence_id(self, test: str) -> str:
        if test not in _TESTS:
            raise ValueError(f"unknown fixture test: {test}")
        return f"fixture:{self.fixture_id}:{self.resource_id}:{test}"

    def snapshot(self) -> dict[str, object]:
        return {
            "fixture_id": self.fixture_id,
            "resource_id": self.resource_id,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "evidence": {key: value.model_dump(mode="json") for key, value in self._evidence.items()},
            "write_ready": self.bundle().is_write_ready(),
        }


__all__ = ["MhsBenchFixture"]
