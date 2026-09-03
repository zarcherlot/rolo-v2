"""Generate the portable LanderPi MHS sampling bundle."""

from __future__ import annotations

import json
from pathlib import Path

from rolo.mhs_bundle import landerpi_mhs_bundle


def main() -> None:
    output = Path(__file__).with_name("mhs-bundle-20260902.json")
    bundle = landerpi_mhs_bundle()
    output.write_text(
        json.dumps(bundle.model_dump(mode="json"), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(output)


if __name__ == "__main__":
    main()
