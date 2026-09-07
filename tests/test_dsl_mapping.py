from rolo.dsl import OPERATION_PROMPTS, AdapterMappingRequest, DslRepairLoop, render_mapping_prompt
from rolo.dsl.canonical import context_digest


def _context():
    return {
        "robot_id": "r",
        "target_fingerprint": "fp",
        "evidence_digest": "sha256:e",
        "evidence_refs": ["route:/state"],
    }


def _request(context):
    return AdapterMappingRequest(
        journey_session_id="journey-001",
        user_goal="read state",
        context_digest=context_digest(context),
        available_tool_catalog_digest="sha256:catalog",
        operation_candidates=("app.state",),
    )


def test_repair_loop_returns_compilable_candidate():
    context = _context()
    calls = []

    def generate(request, diagnostics):
        calls.append(diagnostics)
        return {
            "tool_id": "app.state",
            "kind": "OBSERVE",
            "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
            "binding": {"resource_id": "route:/state"},
        }

    result = DslRepairLoop(generate).run(_request(context), context=context)
    assert result.status == "PASS"
    assert result.dsl and result.dsl["tool_id"] == "app.state"
    assert result.attempts == 1
    assert calls == [()]


def test_repair_loop_blocks_with_bounded_probe_follow_up(tmp_path):
    context = _context()

    def generate(request, diagnostics):
        return {
            "tool_id": "app.state",
            "kind": "OBSERVE",
            "target": {"robot_id": "r", "evidence_digest": "sha256:e"},
            "binding": {"resource_id": "route:/missing"},
        }

    result = DslRepairLoop(generate, max_attempts=3).run(
        _request(context), context=context, output_dir=str(tmp_path / "compile")
    )
    assert result.status == "BLOCKED"
    assert "RESOURCE_NOT_OBSERVED" in result.diagnostics
    assert result.probe_follow_up is not None
    assert result.probe_follow_up.requested_items == ("route:/missing",)


def test_repair_loop_rejects_context_digest_drift():
    context = _context()
    request = _request(context).model_copy(update={"context_digest": "sha256:" + "0" * 64})
    result = DslRepairLoop(lambda *_: {}).run(request, context=context)
    assert result.status == "BLOCKED"
    assert result.diagnostics == ("CONTEXT_DIGEST_MISMATCH",)


def test_mapping_prompt_is_digest_bound_and_covers_four_operations():
    context = _context()
    request = _request(context)
    prompt = render_mapping_prompt(request, context_summary={"freshness": "fresh", "robot_id": "r", "secret": "omit"})
    assert request.context_digest in prompt
    assert request.available_tool_catalog_digest in prompt
    assert "secret" not in prompt
    assert set(OPERATION_PROMPTS) == {"OBSERVE", "COMPOSE", "INVOKE", "EXECUTE"}


def test_repair_loop_blocks_when_context_identity_is_missing():
    context = {}
    request = AdapterMappingRequest(
        journey_session_id="journey-001",
        user_goal="read state",
        context_digest=context_digest(context),
        available_tool_catalog_digest="sha256:catalog",
    )
    result = DslRepairLoop(lambda *_: {}).run(request, context=context)
    assert result.status == "BLOCKED"
    assert result.attempts == 0
    assert result.diagnostics == ("CONTEXT_REQUIRED",)
