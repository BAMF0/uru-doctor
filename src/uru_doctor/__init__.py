"""uru-doctor -- triage for Ubuntu Release Upgrader bugs.

Parses the logs that ``ubuntu-release-upgrader`` leaves in
``/var/log/dist-upgrade`` (and that apport attaches to Launchpad bugs) into a
compact, queryable record; diagnoses the root cause of the failure from the apt
resolver trace; clusters duplicates by root-cause structure rather than by
prose similarity; and proposes bug titles that name the actual culprit.
"""

from __future__ import annotations

__version__ = "0.1.0"
