# SPDX-License-Identifier: GPL-2.0-or-later
"""uru-doctor -- triage for Ubuntu Release Upgrader bugs.

Parses the logs that ``ubuntu-release-upgrader`` leaves in
``/var/log/dist-upgrade`` (and that apport attaches to Launchpad bugs) into a
compact, queryable record; diagnoses the root cause of the failure from the apt
resolver trace; clusters duplicates by root-cause structure rather than by
prose similarity; and proposes bug titles that name the actual culprit.

This package is the **library**. The command-line tool and the read-only
Launchpad client live in the separate ``uru_doctor_cli`` package, which depends
on this one -- never the other way around.

The names re-exported here are the supported surface; anything reachable only
through a submodule is internal and may move. A one-shot diagnosis needs no
database::

    from pathlib import Path

    from uru_doctor import Interner, MemoryBackend, diagnose, ingest_directory

    interner = Interner(MemoryBackend())
    result = ingest_directory(Path("/var/log/dist-upgrade"), interner)
    run = result.primary  # the most recent attempt, or None if no logs were found
    diagnosis = diagnose(run, interner)

For a corpus, use :class:`Store` as the interning backend instead -- its
persistence is what makes dedup's IDF weighting honest.
"""

from __future__ import annotations

from uru_doctor import models
from uru_doctor.config import Config, load_config
from uru_doctor.dedup import Cluster, Tier, build_signature, cluster_runs, score_pair
from uru_doctor.diagnose import DiagnosisResult, diagnose, rank_findings
from uru_doctor.ingest import (
    IngestResult,
    LogSet,
    ingest_attachments,
    ingest_directory,
    read_log_set,
)
from uru_doctor.intern import Interner
from uru_doctor.memory import MemoryBackend
from uru_doctor.store import Store
from uru_doctor.title import ProposedTitle, propose_title

__version__ = "0.2.0"

__all__ = [
    "Cluster",
    "Config",
    "DiagnosisResult",
    "IngestResult",
    "Interner",
    "LogSet",
    "MemoryBackend",
    "ProposedTitle",
    "Store",
    "Tier",
    "__version__",
    "build_signature",
    "cluster_runs",
    "diagnose",
    "ingest_attachments",
    "ingest_directory",
    "load_config",
    "models",
    "propose_title",
    "rank_findings",
    "read_log_set",
    "score_pair",
]
