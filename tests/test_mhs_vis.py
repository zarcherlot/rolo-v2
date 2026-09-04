from rolo.rkb.mhs_read_models import build_probe_evidence_view
from rolo.rkb.mhs_vis import render_probe_evidence_cards


def test_vis_cards_keep_provisional_status_visible() -> None:
    view = build_probe_evidence_view(
        target_fingerprint="a" * 64,
        references=[
            {
                "candidate_id": "c1",
                "target_fingerprint": "a" * 64,
                "source_kind": "TEST_FIXTURE",
                "authority": "PROVISIONAL",
                "status": "MHS_PROVISIONAL_FIXTURE",
                "access": "READ_ONLY",
            }
        ],
    )
    payload = render_probe_evidence_cards(view)
    assert payload["access"] == "READ_ONLY"
    assert payload["cards"][0]["authority"] == "PROVISIONAL"
    assert payload["write_operations"] == 0
