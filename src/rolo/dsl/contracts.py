"""Frozen handoff versions shared by the adapter, Compiler and targetd.

The post-Compiler layers must negotiate these identifiers before consuming an
artifact.  Keeping the table in code makes the compatibility matrix executable
without importing targetd into the standalone Compiler runtime.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

from rolo.security.authority import (
    ACL_DECISION_SCHEMA_VERSION,
    LEDGER_HEAD_SCHEMA_VERSION,
    OPERATOR_ASSERTION_SCHEMA_VERSION,
)

DSL_SCHEMA_VERSION: Final = "rolo-dsl/v1"
COMPILE_CONTEXT_SCHEMA_VERSION: Final = "rolo-compile-context/v1"
TARGETD_PROTOCOL_SCHEMA_VERSION: Final = "rolo-targetd/v1"
CANONICAL_IR_SCHEMA_VERSION: Final = "rolo-canonical-ir/v1"
LEGACY_BUNDLE_PLAN_SCHEMA_VERSION: Final = "rolo-bundle-plan/v1"
BUNDLE_PLAN_SCHEMA_VERSION: Final = "rolo-bundle-plan/v2"
LEGACY_COMPILE_REQUEST_SCHEMA_VERSION: Final = "rolo-dsl-compile-request/v1"
COMPILE_REQUEST_SCHEMA_VERSION: Final = "rolo-dsl-compile-request/v2"
LEGACY_COMPILE_RESULT_SCHEMA_VERSION: Final = "rolo-dsl-compile-result/v1"
COMPILE_RESULT_SCHEMA_VERSION: Final = "rolo-dsl-compile-result/v2"
DIAGNOSTICS_SCHEMA_VERSION: Final = "rolo-diagnostics/v1"
LEGACY_BACKEND_SPI_VERSION: Final = "rolo-backend-spi/v1"
BACKEND_SPI_VERSION: Final = "rolo-backend-spi/v2"
TARGETD_FRAME_SCHEMA_VERSION: Final = "rolo-targetd-dsl-frame/v1"
TARGETD_PUT_SCHEMA_VERSION: Final = "rolo-targetd-dsl-put/v1"
LEGACY_TARGETD_COMPILE_SCHEMA_VERSION: Final = "rolo-targetd-dsl-compile/v1"
TARGETD_COMPILE_SCHEMA_VERSION: Final = "rolo-targetd-dsl-compile/v2"
MAPPING_REQUEST_SCHEMA_VERSION: Final = "rolo-adapter-mapping-request/v1"
MAPPING_PROPOSAL_SCHEMA_VERSION: Final = "rolo-mapping-proposal/v2"
MAPPING_CONFIRMATION_RECEIPT_SCHEMA_VERSION: Final = "rolo-mapping-confirmation-receipt/v1"
MAPPING_AUTHORITY_COMMAND_SCHEMA_VERSION: Final = "rolo-mapping-authority-command/v1"
MAPPING_AUTHORITY_RECEIPT_SCHEMA_VERSION: Final = "rolo-mapping-authority-receipt/v1"
MAPPING_AUTHORITY_PENDING_SCHEMA_VERSION: Final = "rolo-mapping-authority-pending/v1"
PROBE_FOLLOW_UP_SCHEMA_VERSION: Final = "rolo-probe-follow-up-request/v1"
LEGACY_TARGET_CONFORMANCE_SCHEMA_VERSION: Final = "rolo-target-conformance/v2"
TARGET_CONFORMANCE_SCHEMA_VERSION: Final = "rolo-target-conformance/v3"
RELEASE_BINDING_SCHEMA_VERSION: Final = "rolo-release-binding/v1"
LEGACY_JOURNEY_RESULT_SCHEMA_VERSION: Final = "rolo-post-compiler-journey-result/v1"
JOURNEY_RESULT_SCHEMA_VERSION: Final = "rolo-post-compiler-journey-result/v2"
RELEASE_READ_MODEL_SCHEMA_VERSION: Final = "rolo-release-read-model/v1"

CONTRACT_VERSIONS: Final[dict[str, str]] = {
    "dsl": DSL_SCHEMA_VERSION,
    "compile_context": COMPILE_CONTEXT_SCHEMA_VERSION,
    "targetd_protocol": TARGETD_PROTOCOL_SCHEMA_VERSION,
    "canonical_ir": CANONICAL_IR_SCHEMA_VERSION,
    "bundle_plan": BUNDLE_PLAN_SCHEMA_VERSION,
    "compile_request": COMPILE_REQUEST_SCHEMA_VERSION,
    "compile_result": COMPILE_RESULT_SCHEMA_VERSION,
    "diagnostics": DIAGNOSTICS_SCHEMA_VERSION,
    "backend_spi": BACKEND_SPI_VERSION,
    "targetd_frame": TARGETD_FRAME_SCHEMA_VERSION,
    "targetd_put": TARGETD_PUT_SCHEMA_VERSION,
    "targetd_compile": TARGETD_COMPILE_SCHEMA_VERSION,
    "mapping_request": MAPPING_REQUEST_SCHEMA_VERSION,
    "mapping_proposal": MAPPING_PROPOSAL_SCHEMA_VERSION,
    "mapping_confirmation_receipt": MAPPING_CONFIRMATION_RECEIPT_SCHEMA_VERSION,
    "mapping_authority_command": MAPPING_AUTHORITY_COMMAND_SCHEMA_VERSION,
    "mapping_authority_receipt": MAPPING_AUTHORITY_RECEIPT_SCHEMA_VERSION,
    "mapping_authority_pending": MAPPING_AUTHORITY_PENDING_SCHEMA_VERSION,
    "operator_assertion": OPERATOR_ASSERTION_SCHEMA_VERSION,
    "acl_decision": ACL_DECISION_SCHEMA_VERSION,
    "ledger_head": LEDGER_HEAD_SCHEMA_VERSION,
    "probe_follow_up": PROBE_FOLLOW_UP_SCHEMA_VERSION,
    "target_conformance": TARGET_CONFORMANCE_SCHEMA_VERSION,
    "release_binding": RELEASE_BINDING_SCHEMA_VERSION,
    "journey_result": JOURNEY_RESULT_SCHEMA_VERSION,
    "release_read_model": RELEASE_READ_MODEL_SCHEMA_VERSION,
}


class ContractVersionError(ValueError):
    """Raised when a producer/consumer handoff is outside the frozen window."""


def require_version(
    payload: Mapping[str, object],
    field: str,
    expected: str,
    *,
    optional: bool = True,
) -> str:
    """Validate one version field and return the normalized value.

    Legacy offline fixtures may omit a newly introduced envelope field; when
    ``optional`` is true the expected version is returned.  A supplied but
    different version is never silently downgraded.
    """

    value = payload.get(field)
    if value is None and optional:
        return expected
    if not isinstance(value, str) or value != expected:
        raise ContractVersionError(f"{field.upper()}_VERSION_UNSUPPORTED")
    return value


def contract_manifest() -> dict[str, object]:
    """Return a JSON-safe manifest used by CI and replay artifacts."""

    return {
        "schema_version": "rolo-contract-manifest/v1",
        "versions": dict(sorted(CONTRACT_VERSIONS.items())),
    }


__all__ = [
    "BACKEND_SPI_VERSION",
    "BUNDLE_PLAN_SCHEMA_VERSION",
    "CANONICAL_IR_SCHEMA_VERSION",
    "COMPILE_CONTEXT_SCHEMA_VERSION",
    "COMPILE_REQUEST_SCHEMA_VERSION",
    "COMPILE_RESULT_SCHEMA_VERSION",
    "CONTRACT_VERSIONS",
    "DIAGNOSTICS_SCHEMA_VERSION",
    "DSL_SCHEMA_VERSION",
    "JOURNEY_RESULT_SCHEMA_VERSION",
    "LEGACY_COMPILE_RESULT_SCHEMA_VERSION",
    "LEGACY_JOURNEY_RESULT_SCHEMA_VERSION",
    "LEGACY_COMPILE_REQUEST_SCHEMA_VERSION",
    "LEGACY_BACKEND_SPI_VERSION",
    "LEGACY_BUNDLE_PLAN_SCHEMA_VERSION",
    "LEGACY_TARGETD_COMPILE_SCHEMA_VERSION",
    "LEGACY_TARGET_CONFORMANCE_SCHEMA_VERSION",
    "MAPPING_CONFIRMATION_RECEIPT_SCHEMA_VERSION",
    "MAPPING_AUTHORITY_COMMAND_SCHEMA_VERSION",
    "MAPPING_AUTHORITY_RECEIPT_SCHEMA_VERSION",
    "MAPPING_AUTHORITY_PENDING_SCHEMA_VERSION",
    "MAPPING_PROPOSAL_SCHEMA_VERSION",
    "MAPPING_REQUEST_SCHEMA_VERSION",
    "PROBE_FOLLOW_UP_SCHEMA_VERSION",
    "RELEASE_BINDING_SCHEMA_VERSION",
    "RELEASE_READ_MODEL_SCHEMA_VERSION",
    "TARGETD_PROTOCOL_SCHEMA_VERSION",
    "TARGETD_COMPILE_SCHEMA_VERSION",
    "TARGETD_FRAME_SCHEMA_VERSION",
    "TARGETD_PUT_SCHEMA_VERSION",
    "TARGET_CONFORMANCE_SCHEMA_VERSION",
    "ContractVersionError",
    "contract_manifest",
    "require_version",
]
