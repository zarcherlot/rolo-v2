import hashlib
import hmac
import json
import multiprocessing
import os
from contextlib import contextmanager
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from rolo.releases import (
    CatalogMutation,
    ReleaseCatalog,
    ReleaseCatalogError,
    ReleasePublisher,
    ReleaseSignatureError,
    TargetReleaseSignature,
    TargetSignatureVerification,
    ToolRelease,
    release_payload_digest,
    signature_message,
    statement_digest,
    tool_release_digest,
)


class _TestTargetVerifier:
    """Test-only authority; production code deliberately ships no signer."""

    provider_id = "test-target-verifier"
    authority_class = "PRODUCTION_EXTERNAL"

    def __init__(self, key: bytes = b"test-target-authority") -> None:
        self.key = key

    def sign(self, mutation: CatalogMutation) -> TargetReleaseSignature:
        statement = mutation.model_dump(mode="json")
        message = signature_message(
            statement,
            target_id="robot-1",
            key_id="test-key-1",
            algorithm="EdDSA",
        )
        signature = hmac.new(
            self.key,
            message,
            hashlib.sha256,
        ).hexdigest()
        return TargetReleaseSignature(
            target_id=mutation.target_id,
            key_id="test-key-1",
            algorithm="EdDSA",
            signed_digest=statement_digest(statement),
            signature=signature,
        )

    def verify(
        self,
        *,
        target_id,
        key_id,
        algorithm,
        message,
        message_digest,
        signed_digest,
        signature,
    ):
        metadata_rejected = (
            target_id != "robot-1"
            or key_id != "test-key-1"
            or algorithm != "EdDSA"
        )
        expected = hmac.new(self.key, message, hashlib.sha256).hexdigest()
        verified = not metadata_rejected and hmac.compare_digest(signature, expected)
        return TargetSignatureVerification(
            provider_id=self.provider_id,
            authority_class=self.authority_class,
            target_id=target_id,
            key_id=key_id,
            algorithm=algorithm,
            signed_digest=signed_digest,
            message_digest=message_digest,
            trust_root_digest="sha256:" + "a" * 64,
            key_status="ACTIVE",
            status="VERIFIED" if verified else "REJECTED",
        )


def _release(marker: str) -> tuple[str, dict]:
    payload = {
        "tool_id": "app.test",
        "target_id": "robot-1",
        "operation_kind": "OBSERVE",
        "compile_context_digest": "sha256:" + "c" * 64,
        "generated_bundle_digest": "sha256:" + "b" * 64,
        "marker": marker,
    }
    return release_payload_digest(payload), payload


def _proposal(
    catalog: ReleaseCatalog,
    release: tuple[str, dict],
    *,
    operation="PUBLISH",
    expected_head=None,
    expected_current=None,
):
    digest, payload = release
    return catalog.propose(
        operation=operation,
        tool_id="app.test",
        target_id="robot-1",
        release_digest=digest,
        context_digest=payload["compile_context_digest"],
        manifest_digest=payload["generated_bundle_digest"],
        release=payload,
        expected_catalog_head_digest=expected_head,
        expected_current_release_digest=expected_current,
    )


def _commit_in_process(root, mutation, signature, start, output) -> None:
    catalog = ReleaseCatalog(root, signature_verifier=_TestTargetVerifier())
    if not start.wait(timeout=10):
        output.put("START_TIMEOUT")
        return
    try:
        transaction = catalog.commit(mutation, target_signature=signature)
    except Exception as exc:  # noqa: BLE001 - child reports stable outcome to parent
        output.put(str(exc))
    else:
        output.put(transaction.transaction_digest)


def test_signed_catalog_cas_chain_and_monotonic_explicit_rollback(tmp_path: Path) -> None:
    verifier = _TestTargetVerifier()
    catalog = ReleaseCatalog(tmp_path / "catalog", signature_verifier=verifier)
    first = _release("first")
    second = _release("second")

    publish_first = _proposal(catalog, first)
    first_tx = catalog.commit(
        publish_first,
        target_signature=verifier.sign(publish_first),
    )
    assert (
        catalog.commit(
            publish_first,
            target_signature=verifier.sign(publish_first),
        )
        == first_tx
    )
    publish_second = _proposal(
        catalog,
        second,
        expected_head=first_tx.transaction_digest,
        expected_current=first[0],
    )
    second_tx = catalog.commit(
        publish_second,
        target_signature=verifier.sign(publish_second),
    )
    rollback = _proposal(
        catalog,
        first,
        operation="ROLLBACK",
        expected_head=second_tx.transaction_digest,
        expected_current=second[0],
    )
    rollback_tx = catalog.commit(
        rollback,
        target_signature=verifier.sign(rollback),
    )

    assert rollback_tx.mutation.sequence == 3
    assert rollback_tx.mutation.previous_transaction_digest == second_tx.transaction_digest
    assert catalog.head().transaction_digest == rollback_tx.transaction_digest
    assert catalog.snapshot()["tools"]["app.test"]["current"] == first[0]
    records = (tmp_path / "catalog" / "catalog-transactions.jsonl").read_text(
        encoding="utf-8"
    ).splitlines()
    assert len(records) == 3
    assert [json.loads(line)["mutation"]["operation"] for line in records] == [
        "PUBLISH",
        "PUBLISH",
        "ROLLBACK",
    ]


def test_catalog_rejects_stale_cas_and_old_transaction_replay(tmp_path: Path) -> None:
    verifier = _TestTargetVerifier()
    catalog = ReleaseCatalog(tmp_path / "catalog", signature_verifier=verifier)
    first = _release("first")
    candidate_a = _release("candidate-a")
    candidate_b = _release("candidate-b")
    initial = _proposal(catalog, first)
    initial_tx = catalog.commit(initial, target_signature=verifier.sign(initial))
    stale = _proposal(
        catalog,
        candidate_a,
        expected_head=initial_tx.transaction_digest,
        expected_current=first[0],
    )
    winner = _proposal(
        catalog,
        candidate_b,
        expected_head=initial_tx.transaction_digest,
        expected_current=first[0],
    )
    winner_tx = catalog.commit(winner, target_signature=verifier.sign(winner))

    with pytest.raises(ReleaseCatalogError, match="RELEASE_CATALOG_CAS_FAILED"):
        catalog.commit(stale, target_signature=verifier.sign(stale))
    with pytest.raises(
        ReleaseCatalogError,
        match="RELEASE_CATALOG_TRANSACTION_REPLAYED",
    ):
        catalog.commit(initial, target_signature=verifier.sign(initial))
    assert catalog.head().transaction_digest == winner_tx.transaction_digest
    assert catalog.snapshot()["tools"]["app.test"]["current"] == candidate_b[0]


def test_catalog_cross_process_writers_cannot_lose_current_update(tmp_path: Path) -> None:
    verifier = _TestTargetVerifier()
    root = tmp_path / "catalog"
    catalog = ReleaseCatalog(root, signature_verifier=verifier)
    initial_release = _release("initial")
    initial = _proposal(catalog, initial_release)
    initial_tx = catalog.commit(initial, target_signature=verifier.sign(initial))
    first = _proposal(
        catalog,
        _release("first-writer"),
        expected_head=initial_tx.transaction_digest,
        expected_current=initial_release[0],
    )
    second = _proposal(
        catalog,
        _release("second-writer"),
        expected_head=initial_tx.transaction_digest,
        expected_current=initial_release[0],
    )
    context = multiprocessing.get_context("spawn")
    start = context.Event()
    output = context.Queue()
    processes = [
        context.Process(
            target=_commit_in_process,
            args=(
                root,
                mutation.model_dump(mode="json"),
                verifier.sign(mutation).model_dump(mode="json"),
                start,
                output,
            ),
        )
        for mutation in (first, second)
    ]
    for process in processes:
        process.start()
    start.set()
    for process in processes:
        process.join(timeout=15)
        assert process.exitcode == 0
    outcomes = [output.get(timeout=2) for _ in processes]

    assert sum(value.startswith("sha256:") for value in outcomes) == 1
    assert outcomes.count("RELEASE_CATALOG_CAS_FAILED") == 1
    assert catalog.head().sequence == 2
    assert len((root / "catalog-transactions.jsonl").read_text(encoding="utf-8").splitlines()) == 2


def test_catalog_never_age_steals_transaction_lock(
    tmp_path: Path,
    monkeypatch,
) -> None:
    import rolo.releases.catalog as catalog_module

    stale_policies = []

    @contextmanager
    def recording_lock(_target, *, stale_after_s="MISSING", **_kwargs):
        stale_policies.append(stale_after_s)
        yield

    monkeypatch.setattr(catalog_module, "interprocess_lock", recording_lock)
    verifier = _TestTargetVerifier()
    catalog = ReleaseCatalog(tmp_path / "catalog", signature_verifier=verifier)

    assert catalog.head().sequence == 0
    assert catalog.snapshot()["tools"] == {}
    mutation = _proposal(catalog, _release("no-age-steal"))
    catalog.commit(mutation, target_signature=verifier.sign(mutation))

    assert stale_policies == [None, None, None, None]


def test_catalog_requires_real_verifier_and_rejects_signature_tamper(tmp_path: Path) -> None:
    verifier = _TestTargetVerifier()
    catalog = ReleaseCatalog(tmp_path / "catalog", signature_verifier=verifier)
    mutation = _proposal(catalog, _release("signed"))

    with pytest.raises(
        ReleaseSignatureError,
        match="RELEASE_TARGET_SIGNATURE_REQUIRED",
    ):
        catalog.commit(mutation)
    untrusted = verifier.sign(mutation).model_copy(update={"signature": "0" * 64})
    with pytest.raises(
        ReleaseSignatureError,
        match="RELEASE_TARGET_SIGNATURE_UNTRUSTED",
    ):
        catalog.commit(mutation, target_signature=untrusted)
    assert catalog.head().sequence == 0

    transaction = catalog.commit(
        mutation,
        target_signature=verifier.sign(mutation),
    )
    log_path = tmp_path / "catalog" / "catalog-transactions.jsonl"
    record = json.loads(log_path.read_text(encoding="utf-8"))
    record["mutation"]["release"]["marker"] = "tampered"
    log_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    with pytest.raises(ReleaseCatalogError, match="RELEASE_CATALOG_LOG_INVALID"):
        catalog.head()
    assert transaction.transaction_digest


def test_signature_provider_exception_is_not_classified_as_rejection(
    tmp_path: Path,
) -> None:
    class _UnavailableVerifier(_TestTargetVerifier):
        def verify(self, **_kwargs):
            raise RuntimeError("test provider unavailable")

    signer = _TestTargetVerifier()
    catalog = ReleaseCatalog(
        tmp_path / "catalog",
        signature_verifier=_UnavailableVerifier(),
    )
    mutation = _proposal(catalog, _release("signed"))
    with pytest.raises(
        ReleaseSignatureError,
        match="RELEASE_TARGET_SIGNATURE_VERIFICATION_FAILED",
    ):
        catalog.commit(mutation, target_signature=signer.sign(mutation))


def test_catalog_detects_truncated_history_but_recovers_stale_snapshot(tmp_path: Path) -> None:
    verifier = _TestTargetVerifier()
    root = tmp_path / "catalog"
    catalog = ReleaseCatalog(root, signature_verifier=verifier)
    first = _release("first")
    second = _release("second")
    mutation = _proposal(catalog, first)
    first_tx = catalog.commit(mutation, target_signature=verifier.sign(mutation))
    first_snapshot = catalog.snapshot()
    mutation = _proposal(
        catalog,
        second,
        expected_head=first_tx.transaction_digest,
        expected_current=first[0],
    )
    second_tx = catalog.commit(mutation, target_signature=verifier.sign(mutation))

    (root / "tool-catalog.json").write_text(
        json.dumps(first_snapshot),
        encoding="utf-8",
    )
    recovered = catalog.snapshot()
    assert recovered["catalog_head_digest"] == second_tx.transaction_digest
    assert json.loads((root / "tool-catalog.json").read_text(encoding="utf-8")) == recovered

    log_path = root / "catalog-transactions.jsonl"
    log_path.write_text(
        log_path.read_text(encoding="utf-8").splitlines()[0] + "\n",
        encoding="utf-8",
    )
    with pytest.raises(
        ReleaseCatalogError,
        match="RELEASE_CATALOG_SNAPSHOT_MISMATCH",
    ):
        catalog.head()


def test_signed_catalog_rejects_every_unsigned_legacy_snapshot_shape(
    tmp_path: Path,
) -> None:
    root = tmp_path / "catalog"
    root.mkdir()
    for snapshot in (
        {
            "schema_version": "rolo-tool-catalog/v1",
            "tools": {"app.test": {"current": "sha256:" + "0" * 64}},
        },
        {
            "schema_version": "rolo-tool-catalog/v1",
            "tools": {},
            "catalog_sequence": 1,
            "catalog_head_digest": "sha256:" + "0" * 64,
        },
    ):
        (root / "tool-catalog.json").write_text(
            json.dumps(snapshot),
            encoding="utf-8",
        )
        catalog = ReleaseCatalog(root, signature_verifier=_TestTargetVerifier())
        with pytest.raises(
            ReleaseCatalogError,
            match="RELEASE_CATALOG_LEGACY_MIGRATION_REQUIRED",
        ):
            catalog.snapshot()


def test_catalog_recovers_only_uncommitted_tail_after_snapshot_validation(
    tmp_path: Path,
) -> None:
    verifier = _TestTargetVerifier()
    root = tmp_path / "catalog"
    catalog = ReleaseCatalog(root, signature_verifier=verifier)
    mutation = _proposal(catalog, _release("committed"))
    transaction = catalog.commit(mutation, target_signature=verifier.sign(mutation))
    log_path = root / "catalog-transactions.jsonl"
    committed = log_path.read_bytes()
    (root / "tool-catalog.json").unlink()
    assert catalog.head().transaction_digest == transaction.transaction_digest
    repaired = json.loads((root / "tool-catalog.json").read_text(encoding="utf-8"))
    assert repaired["catalog_head_digest"] == transaction.transaction_digest
    log_path.write_bytes(committed + b'{"crash_partial":')

    assert catalog.head().transaction_digest == transaction.transaction_digest
    assert log_path.read_bytes() == committed

    # If the snapshot claims bytes from the unterminated tail are committed,
    # preserve the evidence and fail instead of truncating before validation.
    unterminated = committed.removesuffix(b"\n")
    log_path.write_bytes(unterminated)
    with pytest.raises(ReleaseCatalogError):
        catalog.snapshot()
    assert log_path.read_bytes() == unterminated


def test_catalog_detects_root_replacement_and_hardlinked_log(tmp_path: Path) -> None:
    verifier = _TestTargetVerifier()
    root = tmp_path / "catalog"
    root.mkdir()
    catalog = ReleaseCatalog(root, signature_verifier=verifier)
    mutation = _proposal(catalog, _release("committed"))
    catalog.commit(mutation, target_signature=verifier.sign(mutation))
    moved = tmp_path / "catalog-old"
    root.rename(moved)
    root.mkdir()
    with pytest.raises(
        ReleaseCatalogError,
        match="RELEASE_CATALOG_DIRECTORY_REPLACED",
    ):
        catalog.head()

    root.rmdir()
    moved.rename(root)
    fresh = ReleaseCatalog(root, signature_verifier=verifier)
    try:
        os.link(root / "catalog-transactions.jsonl", root / "linked-log")
    except OSError:
        pytest.skip("filesystem does not support hard links")
    with pytest.raises(
        ReleaseCatalogError,
        match="RELEASE_CATALOG_UNTRUSTED_PATH",
    ):
        fresh.head()


def test_catalog_constructor_rejects_symlinked_ancestor(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linked"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("filesystem does not permit directory symlinks")
    with pytest.raises(
        ReleaseCatalogError,
        match="RELEASE_CATALOG_UNTRUSTED_PATH",
    ):
        ReleaseCatalog(link / "catalog", signature_verifier=_TestTargetVerifier())


def test_target_signature_binds_all_catalog_release_identity_fields(
    tmp_path: Path,
) -> None:
    verifier = _TestTargetVerifier()
    catalog = ReleaseCatalog(tmp_path / "catalog", signature_verifier=verifier)
    mutation = _proposal(catalog, _release("signed"))
    signature = verifier.sign(mutation)

    changes = (
        {"previous_transaction_digest": "sha256:" + "1" * 64},
        {"target_id": "robot-2", "release": {**mutation.release, "target_id": "robot-2"}},
        {
            "context_digest": "sha256:" + "2" * 64,
            "release": {
                **mutation.release,
                "compile_context_digest": "sha256:" + "2" * 64,
            },
        },
        {
            "manifest_digest": "sha256:" + "3" * 64,
            "release": {
                **mutation.release,
                "generated_bundle_digest": "sha256:" + "3" * 64,
            },
        },
        {"release": {**mutation.release, "marker": "substituted"}},
    )
    for update in changes:
        payload = {**mutation.model_dump(mode="python"), **update}
        if "release" in update:
            payload["release_digest"] = release_payload_digest(payload["release"])
        changed = CatalogMutation.model_validate(payload)
        with pytest.raises(
            ReleaseSignatureError,
            match="RELEASE_TARGET_SIGNATURE_(?:DIGEST|IDENTITY)_MISMATCH",
        ):
            catalog.commit(changed, target_signature=signature)

    bypassed_algorithm = signature.model_copy(update={"algorithm": "none"})
    with pytest.raises(
        ReleaseSignatureError,
        match="RELEASE_TARGET_SIGNATURE_INVALID",
    ):
        catalog.commit(mutation, target_signature=bypassed_algorithm)


def test_release_catalog_and_signature_schemas_are_valid() -> None:
    schema_root = Path(__file__).parents[1] / "schemas"
    for name in (
        "TargetReleaseSignature.schema.json",
        "TargetSignatureVerification.schema.json",
        "ReleaseCatalogTransaction.schema.json",
    ):
        schema = json.loads((schema_root / name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)


def test_publisher_immutable_release_no_replace_preserves_peer_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import rolo.releases.publisher as publisher_module

    publisher = ReleasePublisher(tmp_path / "catalog")
    release = ToolRelease(
        tool_id="app.test",
        target_id="robot-1",
        operation_kind="OBSERVE",
        dsl_digest="sha256:" + "d" * 64,
        ir_digest="sha256:" + "i" * 64,
        probe_evidence_digest="sha256:" + "e" * 64,
        compiler_version="test",
        generated_bundle_digest="sha256:" + "b" * 64,
        conformance_digest="sha256:" + "c" * 64,
        target_fingerprint="target",
        compile_context_digest="sha256:" + "a" * 64,
    )
    digest = tool_release_digest(release)
    expected_path = publisher.releases / f"{digest[7:]}.json"

    def collide(_source, destination, *, follow_symlinks=False):
        del follow_symlinks
        Path(destination).write_bytes(b"peer-owned")
        raise FileExistsError(destination)

    monkeypatch.setattr(publisher_module.os, "link", collide)
    with pytest.raises(
        ReleaseCatalogError,
        match="RELEASE_IMMUTABLE_OBJECT_CONFLICT",
    ):
        publisher._write_immutable_release(digest, release)
    assert expected_path.read_bytes() == b"peer-owned"
