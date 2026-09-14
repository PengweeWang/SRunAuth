#!/usr/bin/env python3
"""SRun campus network automatic authentication client (compatibility entry point)."""
from __future__ import annotations

from srun_auth import *  # noqa: F401, F403
from srun_auth.cli import cli_entry, main

if __name__ == "__main__":
    cli_entry()
