from pathlib import Path

from rolo.target_ref import parse_target_ref
from rolo.targetd import JourneySession
from rolo.targetd.controller import TargetdJourneyController
from rolo.targetd.installer import TargetdInstaller
from rolo.targets.executor import SshTargetExecutor


def test_stdio_argv_reuses_pinned_ssh_options_without_command_marker(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("example.test ssh-ed25519 AAAATEST\n", encoding="utf-8")
    identity = tmp_path / "id_ed25519"
    identity.write_text("private-key\n", encoding="utf-8")
    target = parse_target_ref("ssh://pi@example.test:2222/home/pi")
    executor = SshTargetExecutor(target, known_hosts=known_hosts, identity_file=identity)
    argv = executor.stdio_argv(["python3", "-m", "rolo.targetd.daemon"])
    assert "--" not in argv
    assert argv[-3:] == ["python3", "-m", "rolo.targetd.daemon"]
    assert "StrictHostKeyChecking=yes" in argv
    assert "IdentitiesOnly=yes" in argv


def test_targetd_controller_persists_call_artifact(tmp_path: Path):
    target = parse_target_ref("ssh://pi@example.test/home/pi")
    executor = SshTargetExecutor(target, known_hosts=tmp_path / "known_hosts")
    session = JourneySession.create(
        session_id="artifact-session", target_id="mentorpi", profile_id="landerpi"
    )
    controller = TargetdJourneyController(
        executor, session, remote_root="/opt/rolo", state_root="/var/lib/rolo-targetd",
        signing_key="secret", artifact_root=tmp_path / "artifacts"
    )
    assert controller.last_receipt_ref is None


def test_targetd_installer_archive_contains_rolo_package(tmp_path: Path):
    package = tmp_path / "src" / "rolo"
    (package / "targetd").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "targetd" / "daemon.py").write_text("print('ok')\n", encoding="utf-8")
    executor = SshTargetExecutor(
        parse_target_ref("ssh://pi@example.test/home/pi"), known_hosts=tmp_path / "known_hosts"
    )
    archive = TargetdInstaller(executor, package_root=tmp_path / "src").build_archive()
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r") as tar:
        assert sorted(tar.getnames()) == ["rolo/__init__.py", "rolo/targetd/daemon.py"]
