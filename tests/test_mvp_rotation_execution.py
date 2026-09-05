import json
from types import SimpleNamespace

from typer.testing import CliRunner

import rolo.product_cli as cli
from rolo.mvp.rotation import rotation_tool_proposal
from rolo.targets.models import TargetConnectionState


def test_execute_without_operator_id_preserves_authorization_and_distinct_audits(tmp_path, monkeypatch):
    proposal = rotation_tool_proposal(target_id='mentorpi', evidence_ref='target-evidence:' + 'a' * 64)
    proposal_path = tmp_path / 'proposal.json'
    proposal_path.write_text(proposal.model_dump_json(), encoding='utf-8')
    evidence_path = tmp_path / 'evidence.json'
    evidence_path.write_text('{}', encoding='utf-8')
    bundle = SimpleNamespace(robot_id='mentorpi', payload_sha256='a' * 64, target_host_fingerprint='b' * 64, probes={'ros': None})
    monkeypatch.setattr(cli, 'TargetEvidenceBundle', SimpleNamespace(model_validate_json=lambda _: bundle))
    monkeypatch.setattr(cli, 'get_settings', lambda: SimpleNamespace(rolo_config_dir=tmp_path, rolo_artifact_dir=tmp_path / 'artifacts'))
    monkeypatch.setattr(cli, 'load_registered_proposals', lambda *_: [proposal])
    monkeypatch.setattr(cli, 'load_deployment', lambda *_: None)
    monkeypatch.setattr(cli, 'verify_evidence_bundle', lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli, 'observed_probe_routes', lambda _: [
        SimpleNamespace(resource_id='ros_topic:/cmd_vel', interface_type='geometry_msgs/msg/Twist'),
        SimpleNamespace(resource_id='ros_topic:/odom_raw', interface_type='nav_msgs/msg/Odometry'),
        SimpleNamespace(resource_id='ros_topic:/odom_rf2o', interface_type='nav_msgs/msg/Odometry'),
    ])
    monkeypatch.setattr(cli, 'create_profile_target_executor', lambda *_args, **_kwargs: SimpleNamespace(
        inspect=lambda: SimpleNamespace(state=TargetConnectionState.READY)))
    calls = []

    class Provider:
        def __init__(self, *_):
            pass

        def rotate(self, binding, arguments):
            files = list((tmp_path / 'artifacts').rglob('*.json'))
            assert any(json.loads(path.read_text())['result']['status'] == 'PENDING' for path in files)
            calls.append(arguments)
            return {'status': 'SUCCEEDED', 'measured_angle_degrees': 15, 'stop_published': True, 'stopped_observed': True}

    monkeypatch.setattr(cli, 'RosBindingExecutor', Provider)
    args = ['execute-rotation', '--profile', 'mentorpi', '--proposal', str(proposal_path), '--evidence', str(evidence_path),
            '--angle-degrees', '15', '--max-speed-rad-s', '0.2']
    rejected = CliRunner().invoke(cli.app, [*args, '--safety-not-confirmed'])
    assert rejected.exit_code == 2
    assert calls == []
    for _ in range(2):
        executed = CliRunner().invoke(cli.app, [*args, '--safety-confirmed'])
        assert executed.exit_code == 0, executed.output
    files = list((tmp_path / 'artifacts').rglob('*.json'))
    assert len(files) == 2
    for path in files:
        audit = json.loads(path.read_text())
        assert audit['operator_id'] is None
        assert audit['safety_confirmed'] is True
        assert audit['result']['status'] == 'SUCCEEDED'
