# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared fixtures for the CLI tests.

The recorded logs are the library's ground-truth corpus and stay in
``tests/fixtures``; these helpers point at them from here so the CLI tests
exercise the same real failures through the commands.
"""

from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def fixture_text(relative: str) -> str:
    """Read a recorded fixture, failing the test if it was never recorded."""
    path = FIXTURES / relative
    if not path.is_file():
        pytest.skip(f"fixture not recorded: {relative}")
    return path.read_text(encoding="utf-8")
