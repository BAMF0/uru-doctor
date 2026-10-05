# SPDX-License-Identifier: GPL-2.0-or-later
"""The uru-doctor command-line frontend.

Owns everything the :mod:`uru_doctor` library deliberately does not: the
Typer commands, Rich rendering, and the read-only Launchpad client
(:mod:`uru_doctor_cli.lp`). The layering rule is one-way -- the library never
imports this package, and a test enforces it.
"""

from __future__ import annotations
