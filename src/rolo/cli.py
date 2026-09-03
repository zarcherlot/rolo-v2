"""Minimal robot-side/controller Probe CLI for Rolo v2."""

from __future__ import annotations

import typer

from rolo.commands.configuration import config_app
from rolo.commands.lifecycle import probe_stage_app, register_lifecycle_commands
from rolo.commands.runtime import runtime_app
from rolo.commands.target_evidence import target_evidence_app

app = typer.Typer(help="Rolo v2 Probe and target-evidence CLI.")
register_lifecycle_commands(app)
probe_stage_app.add_typer(target_evidence_app, name="target-evidence")
app.add_typer(config_app, name="config")
app.add_typer(runtime_app, name="runtime")


if __name__ == "__main__":
    app()
