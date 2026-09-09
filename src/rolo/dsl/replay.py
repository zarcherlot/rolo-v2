"""Deterministic offline replay helpers."""

from pathlib import Path
from tempfile import TemporaryDirectory

from .admission import MappingConfirmationStore
from .canonical import ir_digest
from .compiler import CompileResult, compile_text


def replay(
    value,
    context: dict | None = None,
    *,
    confirmation_store: MappingConfirmationStore | None = None,
    confirmation_receipt_digest: str | None = None,
    journey_session_id: str | None = None,
) -> tuple[CompileResult, CompileResult]:
    admission = {
        "confirmation_store": confirmation_store,
        "confirmation_receipt_digest": confirmation_receipt_digest,
        "journey_session_id": journey_session_id,
    }
    with TemporaryDirectory(prefix="rolo-dsl-replay-") as temporary_root:
        root = Path(temporary_root)
        first = compile_text(
            value,
            root / "first",
            context=context,
            **admission,
        )
        second = compile_text(
            value,
            root / "second",
            context=context,
            **admission,
        )
    return first, second


def replay_stable(
    value,
    context: dict | None = None,
    *,
    confirmation_store: MappingConfirmationStore | None = None,
    confirmation_receipt_digest: str | None = None,
    journey_session_id: str | None = None,
) -> bool:
    first, second = replay(
        value,
        context,
        confirmation_store=confirmation_store,
        confirmation_receipt_digest=confirmation_receipt_digest,
        journey_session_id=journey_session_id,
    )
    if not (first.ok and second.ok):
        return False
    return first.dsl_digest == second.dsl_digest and ir_digest(first.ir) == ir_digest(second.ir) and first.bundle.digest == second.bundle.digest
