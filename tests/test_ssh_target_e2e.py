from __future__ import annotations

import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rolo.cli import app
from rolo.stages.adapt.target_evidence import (
    EvidenceDeploymentMode,
    collect_over_ssh,
    configure_deployment,
    initialize_probe_runner,
    new_request,
    verify_evidence_bundle,
)

pytestmark = [
    pytest.mark.ssh,
    pytest.mark.skipif(
        os.environ.get("ROLO_RUN_SSH_E2E") != "1",
        reason="set ROLO_RUN_SSH_E2E=1 to run the real sshd integration test",
    ),
    pytest.mark.skipif(os.name == "nt", reason="the embedded sshd fixture requires POSIX"),
]


def _run(*command: str) -> None:
    subprocess.run(command, check=True, capture_output=True, text=True)


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _wait_for_sshd(process: subprocess.Popen[str], port: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr is not None else ""
            pytest.fail(f"test sshd exited before accepting connections: {stderr}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    pytest.fail("test sshd did not start within ten seconds")


def test_real_sshd_collects_twice_and_passes_preflight(tmp_path: Path) -> None:
    ssh = shutil.which("ssh")
    sshd = shutil.which("sshd")
    ssh_keygen = shutil.which("ssh-keygen")
    if not ssh or not sshd or not ssh_keygen:
        pytest.fail("ssh, sshd, and ssh-keygen must be installed for the SSH integration test")
    del ssh
    client_key = tmp_path / "client_ed25519"
    host_key = tmp_path / "host_ed25519"
    _run(ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(client_key))
    _run(ssh_keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(host_key))
    client_key.chmod(0o600)
    host_key.chmod(0o600)
    authorized_keys = tmp_path / "authorized_keys"
    authorized_keys.write_text(client_key.with_suffix(".pub").read_text(encoding="utf-8"))
    authorized_keys.chmod(0o600)
    port = _free_port()
    username = getpass.getuser()
    sshd_config = tmp_path / "sshd_config"
    sshd_config.write_text(
        "\n".join(
            [
                f"Port {port}",
                "ListenAddress 127.0.0.1",
                f"HostKey {host_key}",
                f"PidFile {tmp_path / 'sshd.pid'}",
                f"AuthorizedKeysFile {authorized_keys}",
                f"AllowUsers {username}",
                "PubkeyAuthentication yes",
                "PasswordAuthentication no",
                "KbdInteractiveAuthentication no",
                "UsePAM no",
                "StrictModes no",
                "UseDNS no",
                "PermitTTY no",
                "AllowTcpForwarding no",
                "X11Forwarding no",
                "LogLevel ERROR",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    process = subprocess.Popen(
        [sshd, "-D", "-e", "-f", str(sshd_config)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        _wait_for_sshd(process, port)
        state = tmp_path / "probe_runner.json"
        secret = tmp_path / "probe_runner.key"
        descriptor = initialize_probe_runner(
            robot_id="ssh-e2e",
            state_path=state,
            secret_path=secret,
        )
        host_public = host_key.with_suffix(".pub").read_text(encoding="utf-8").split()
        known_hosts = tmp_path / "known_hosts"
        known_hosts.write_text(
            f"[127.0.0.1]:{port} {host_public[0]} {host_public[1]}\n",
            encoding="utf-8",
        )
        robotctl = Path(sys.prefix) / "bin" / "robotctl"
        assert robotctl.is_file()
        deployment_path = tmp_path / "deployment.json"
        deployment = configure_deployment(
            robot_id="ssh-e2e",
            mode=EvidenceDeploymentMode.REMOTE,
            descriptor=descriptor,
            verification_secret_path=secret,
            output_path=deployment_path,
            ssh_target=f"{username}@127.0.0.1",
            known_hosts_path=known_hosts,
            ssh_port=port,
            ssh_identity_file=client_key,
            probe_runner_executable=str(robotctl),
            probe_runner_config=str(state),
        )
        first_request = new_request("ssh-e2e")
        first = collect_over_ssh(deployment, first_request, timeout_s=30)
        verify_evidence_bundle(first, deployment=deployment, request=first_request)
        second_request = new_request("ssh-e2e")
        second = collect_over_ssh(deployment, second_request, timeout_s=30)
        verify_evidence_bundle(second, deployment=deployment, request=second_request)

        preflight = CliRunner().invoke(
            app,
            [
                "target-evidence",
                "preflight",
                "--robot",
                "ssh-e2e",
                "--deployment-config",
                str(deployment_path),
                "--timeout",
                "30",
            ],
        )

        assert first.request_nonce != second.request_nonce
        assert first.source_id == second.source_id == descriptor.source_id
        assert preflight.exit_code == 0, preflight.output
        assert json.loads(preflight.output)["status"] == "READY"
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
