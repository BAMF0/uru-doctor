"""Shared fixtures.

Two things live here: access to the recorded logs, and builders for synthetic
ones.

The recorded logs are real failures and are what stops this tool from being
correct only against the cases its author imagined. The builders exist for the
opposite reason -- to state one premise per test. A test about holdback
detection should contain a holdback and nothing else, so that when it fails the
failure is about holdbacks.

``NOW`` is pinned because release end-of-life is a function of the calendar, so
the calendar has to be an input rather than an ambient fact.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from uru_doctor.apt.graph import build_graph
from uru_doctor.apt.sections import SectionedLog, read_sections
from uru_doctor.intern import Interner
from uru_doctor.models import ConflictGraph
from uru_doctor.store import Store

if TYPE_CHECKING:
    from collections.abc import Iterator

#: Pinned clock. 26.04 LTS is released and 26.10 is in development as of this
#: date, which is the situation the tool is built for.
NOW = datetime(2026, 10, 1, tzinfo=UTC)

FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Recorded logs
# ---------------------------------------------------------------------------


def fixture_text(relative: str) -> str:
    """Read a recorded fixture, failing the test if it was never recorded."""
    path = FIXTURES / relative
    if not path.is_file():
        pytest.skip(f"fixture not recorded: {relative}")
    return path.read_text(encoding="utf-8")


#: Every recorded ``apt.log``, with the dialect it came from. Used by the
#: coverage tests, which must run over all of them rather than a chosen few --
#: the point of those tests is that nothing in any real log goes unrecognised.
APT_FIXTURES: tuple[tuple[str, str], ...] = (
    ("apt/lp2169028-apt.log", "apt2"),
    ("apt/lp2150319-apt.log", "apt2"),
    ("apt/lp2150245-apt.log", "apt2"),
    ("apt/local-apt3-success.log", "apt3"),
    ("apt/local-apt3-devcascade.log", "apt3"),
    ("apt/local-apt3-gnome.log", "apt3"),
)


@pytest.fixture
def store(tmp_path: Path) -> Iterator[Store]:
    """A throwaway store. Never the developer's real one."""
    with Store.open(tmp_path / "state") as opened:
        yield opened


@pytest.fixture
def interner(store: Store) -> Interner:
    return Interner(store)


# ---------------------------------------------------------------------------
# Synthetic log builders
# ---------------------------------------------------------------------------


def apt_log(*lines: str, timestamp: str = "2026-04-25 10:49:55.123456") -> str:
    """Wrap resolver lines in the framing a real section has.

    Saves every test from restating the ``Log time:`` header and the
    ``Starting``/``Done`` bracket, and means a change to the framing is made in
    one place.
    """
    body = "\n".join(lines)
    return (
        f"Log time: {timestamp}\n"
        f"Starting pkgProblemResolver with broken count: 1\n"
        f"{body}\n"
        f"Done\n"
    )


def broken(
    subject: str,
    dep: str,
    obj: str,
    state: str,
    constraint: str = "",
    *,
    indent: int = 0,
) -> str:
    """One ``Broken`` line.

    ``state`` describes the **object**, which is how apt writes it: in
    ``Broken lintian Depends on libfile-libmagic-perl < none | 1.23 @un uH >``
    the state is libfile-libmagic-perl's.
    """
    tail = f" ({constraint})" if constraint else ""
    return f"{' ' * indent}Broken {subject} {dep} on {obj} < {state} >{tail}"


def holdback_block(
    dependent: str = "lintian:amd64",
    blocker: str = "libfile-libmagic-perl:amd64",
    *,
    candidate: str = "1.23-2build2",
    dependent_from: str = "2.117.0ubuntu1.4",
    dependent_to: str = "2.129.0ubuntu2",
    score_blocker: int = 0,
    score_dependent: int = -1,
) -> str:
    """The holdback sequence, as it appears in LP#2150319.

    The blocker is not installed, a candidate exists, apt declines it, and the
    dependent is held back instead. Defaults reproduce the lintian case
    including its one-point score margin.
    """
    return apt_log(
        broken(dependent, "Depends", blocker, f"none | {candidate} @un uH"),
        f"  Considering {blocker} {score_blocker} as a solution to"
        f" {dependent} {score_dependent}",
        f"  MarkKeep {dependent} < {dependent_from} -> {dependent_to} @ii umU Ib > FU=0",
        f"  Holding Back {dependent} rather than change {blocker}",
    )


def pin_cascade(
    root: str = "python3:amd64",
    victims: tuple[str, ...] = ("python3-apt:amd64", "python3-yaml:amd64"),
    *,
    from_version: str = "3.12.3-0ubuntu2.1",
    to_version: str = "3.14.3-0ubuntu2",
    constraint: str = "< 3.13",
) -> str:
    """An exact-pin cascade: one upgrade breaking many tight dependents."""
    return apt_log(
        *(
            broken(victim, "Depends", root, f"{from_version} -> {to_version} @ii umU", constraint)
            for victim in victims
        )
    )


# ---------------------------------------------------------------------------
# Graph helpers
# ---------------------------------------------------------------------------


def sectioned(text: str) -> SectionedLog:
    return read_sections(text.splitlines())


def graph_of(text: str, interner: Interner) -> ConflictGraph:
    """Build the graph for the primary section of a synthetic log."""
    log = sectioned(text)
    primary = log.primary
    assert primary is not None, "synthetic log produced no section"
    return build_graph(primary, interner)


def node_names(graph: ConflictGraph, interner: Interner) -> dict[int, str]:
    """Vertex index to display name, for readable assertions."""
    return {index: interner.package_label(pkg) for index, pkg in enumerate(graph.nodes.ids)}


def named_root(roots: object, interner: Interner, name: str) -> object:
    """Find a root by package name, or None.

    Tests assert on names rather than vertex indices: an index depends on how
    many unrelated packages happened to be in the same transaction, which is
    not what any test is about.
    """
    for root in getattr(roots, "roots", roots):  # accepts RootReport or a list
        if interner.package_label(root.pkg_id) == name:
            return root
    return None
