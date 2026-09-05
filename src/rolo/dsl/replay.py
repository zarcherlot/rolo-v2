"""Deterministic offline replay helpers."""
from pathlib import Path
from .compiler import CompileResult, compile_text
from .canonical import ir_digest

def replay(value, context: dict | None = None) -> tuple[CompileResult, CompileResult]:
    first = compile_text(value, Path(".rolo-replay-1"), context=context)
    second = compile_text(value, Path(".rolo-replay-2"), context=context)
    return first, second

def replay_stable(value, context: dict | None = None) -> bool:
    first, second = replay(value, context)
    if not (first.ok and second.ok): return False
    return first.dsl_digest == second.dsl_digest and ir_digest(first.ir) == ir_digest(second.ir) and first.bundle.digest == second.bundle.digest
