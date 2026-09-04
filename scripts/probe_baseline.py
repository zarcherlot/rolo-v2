"""Create and validate the Probe B0 baseline artifacts.

Examples:
  python scripts/probe_baseline.py create --output artifacts/probe-baseline
  python scripts/probe_baseline.py validate --directory artifacts/probe-baseline/probe-readonly
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from rolo.probe_baseline import (
    BaselineArtifactIndex,
    ProbeBaselineManifest,
    audit_read_only,
    build_artifact_index,
    build_manifest,
    validate_baseline,
)


def _dump(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )


def create(root: Path, output: Path) -> dict[str, object]:
    manifest = build_manifest(root)
    # Inputs are immutable repository contracts.  The generated files are
    # intentionally excluded from the index to avoid a self-referential digest.
    paths = [
        root / "pyproject.toml",
        root / ".github" / "workflows" / "ci.yml",
        *sorted((root / "schemas").glob("*.schema.json")),
    ]
    index = build_artifact_index(root, manifest, paths)
    completion = audit_read_only(manifest, index)
    destination = output / manifest.baseline_id
    _dump(destination / "probe-baseline-manifest.json", manifest.model_dump(mode="json"))
    _dump(destination / "artifact-manifest.json", index.model_dump(mode="json"))
    _dump(destination / "read-only-completion.json", completion.model_dump(mode="json"))
    return {
        "status": completion.decision.value,
        "directory": str(destination),
        "manifest_digest": manifest.digest,
        "artifact_index_digest": index.digest,
        "completion": completion.model_dump(mode="json"),
    }


def validate(directory: Path, root: Path) -> dict[str, object]:
    manifest = ProbeBaselineManifest.model_validate_json(
        (directory / "probe-baseline-manifest.json").read_text(encoding="utf-8")
    )
    index = BaselineArtifactIndex.model_validate_json(
        (directory / "artifact-manifest.json").read_text(encoding="utf-8")
    )
    errors = validate_baseline(root, manifest, index)
    return {"status": "PASS" if not errors else "BLOCKED", "errors": errors}


def main() -> None:
    parser = argparse.ArgumentParser(description="Probe B0 baseline manifest and W0 audit")
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    create_parser.add_argument("--output", type=Path, required=True)
    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    validate_parser.add_argument("--directory", type=Path, required=True)
    args = parser.parse_args()
    result = (
        create(args.root, args.output)
        if args.command == "create"
        else validate(args.directory, args.root)
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True, default=str))
    if result["status"] not in {"PASS", "READ_ONLY_COMPLETE"}:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
