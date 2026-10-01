"""Generating accurate bug titles from findings.

Titles are derived from the diagnosis, which is derived from the logs. Nothing
here reads the reporter's existing title, because the existing title is the
problem being solved: the thirteen duplicates of LP#2150245 are called things
like ``Ubgrade does not work`` and ``upgrade to 26.4``, and a title generator
that took them as input would launder noise into more noise.

Four constraints shape every template below.

**Name the package.** A title without a package name is unsearchable, and
unsearchable is how a bug acquires thirteen duplicates. ``Upgrade from 24.04 to
26.04 fails`` matches every bug in the queue.

**Name the mechanism, not the symptom.** ``broken packages`` is what the
reporter already said. ``held back`` or ``conflicts with`` tells a triager
which component owns it.

**Blame the right package.** For a cascade that is the root, not the
forty victims. For a livelock it is the package apt refused to install, not the
one it oscillated on. For a dpkg hook failure it is the package that shipped
the broken file, not the one whose maintainer script ran it.

**Never overstate.** When the evidence is truncated the title says so rather
than naming a cause the logs do not support.

The result is deliberately plain. It gets reviewed by a human before it goes
anywhere, and the optional language-model pass only ever rewords a title this
module has already decided -- it cannot change the package, the cause or the
counts.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from uru_doctor.models import Cause, Finding, Phase, UpgradeRun

if TYPE_CHECKING:
    from uru_doctor.diagnose import DiagnosisResult
    from uru_doctor.intern import Interner

__all__ = [
    "MAX_TITLE",
    "ProposedTitle",
    "propose_title",
    "render_detail",
]

#: Launchpad accepts longer, but a title that does not fit in a bug list is a
#: title nobody reads. Trimmed at a word boundary, never mid-package-name.
MAX_TITLE: Final[int] = 100

_ARROW: Final[str] = "\u2192"


@dataclass(frozen=True, slots=True)
class ProposedTitle:
    """A generated title and the reasoning behind it."""

    title: str
    detail: str
    """The part after the release prefix, before any trimming."""

    cause: Cause
    packages: tuple[str, ...]
    """Packages named in the title, for the report's cross-reference."""

    confident: bool = True
    """False when the evidence does not support naming a cause.

    The report shows such titles as suggestions needing confirmation rather
    than as proposals, because a confidently wrong title is worse than none.
    """

    truncated: bool = False

    @property
    def is_usable(self) -> bool:
        return bool(self.detail) and self.confident


def _count(n: int, noun: str = "package") -> str:
    return f"{n} {noun}{'s' if n != 1 else ''}"


def render_detail(finding: Finding, interner: Interner, *, run: UpgradeRun | None = None) -> str:
    """The cause-specific half of a title.

    One branch per cause rather than a generic template, because the useful
    phrasing differs: a livelock needs both halves of the cycle named, a
    cascade needs a count, and a third-party pin needs the origin stated.
    """
    names = [interner.package_label(p) for p in finding.root_pkgs if p]
    primary = names[0] if names else "an unknown package"
    victims = finding.cascade_size
    detail = finding.detail

    match finding.cause:
        case Cause.RESOLVER_LIVELOCK:
            stuck = detail.get("oscillating_package", "")
            # Both packages a triager needs go in the first forty characters.
            # A longer phrasing that also named the forcing package read
            # "apt cannot resolve lintian: libyaml-libyaml-perl needs a newer
            # version but..." and trimmed away ``libfile-libmagic-perl`` -- the
            # single package that resolves the bug, and the one upstream's
            # quirk installs. The forcing package belongs in the report body,
            # not the title.
            if stuck:
                return f"apt deadlocks on {stuck} needing {primary}"
            return f"apt cannot converge without installing {primary}"

        case Cause.THIRD_PARTY_PIN:
            shown = ", ".join(names[:2])
            more = f" and {len(names) - 2} others" if len(names) > 2 else ""
            tail = f", blocking {_count(victims)}" if victims else ""
            return f"third-party {shown}{more} cannot be upgraded{tail}"

        case Cause.HOLDBACK_BLOCKS_NEW_DEP:
            blocker = detail.get("dependency") or detail.get("blocked_by", "")
            because = f" because {blocker} is not installable" if blocker else ""
            tail = f", blocking {_count(victims)}" if victims else ""
            return f"{primary} held back{because}{tail}"

        case Cause.HELD_PACKAGE_BLOCKS_UPGRADE:
            return f"{primary} is held and blocks {_count(victims)}"

        case Cause.EXACT_PIN_BROKEN_BY_UPGRADE:
            constraint = detail.get("constraint", "")
            needs = (
                f" requires {constraint} which is unavailable"
                if constraint
                else (" has an unsatisfiable version requirement")
            )
            tail = f", breaking {_count(victims)}" if victims else ""
            return f"{primary}{needs}{tail}"

        case Cause.UNSATISFIABLE_VIRTUAL:
            tail = f", breaking {_count(victims)}" if victims else ""
            return f"nothing provides {primary}{tail}"

        case Cause.I386_ORPHAN:
            return f"i386 {primary} has no counterpart, breaking {_count(victims)}"

        case Cause.T64_TRANSITION:
            return f"{primary} is stuck in the 64-bit time_t transition"

        case Cause.REMOVAL_CASCADE:
            return f"removing {primary} would remove {_count(victims)}"

        case Cause.TRANSITIONAL_BREAKS:
            return f"{primary} conflicts with its own replacement"

        case Cause.DPKG_MAINTSCRIPT_FAILED:
            failing = detail.get("failing_package", "")
            if failing and failing != primary:
                return f"{failing} fails to configure because of a hook from {primary}"
            status = detail.get("exit_status", "")
            suffix = f" (exit {status})" if status else ""
            return f"{primary} maintainer script fails{suffix}"

        case Cause.DPKG_UNPACK_OVERWRITE:
            other = detail.get("conflicts_with", "")
            path = detail.get("path", "")
            if other and path:
                return f"{primary} overwrites {path} owned by {other}"
            return f"{primary} cannot be unpacked"

        case Cause.DPKG_UNMET_DEPS_UNCONFIGURED:
            return f"{_count(victims)} left unconfigured after {primary} failed"

        case Cause.DPKG_INTERRUPTED:
            return "a previous dpkg run was interrupted and must be repaired first"

        case Cause.NOT_ENOUGH_DISK_SPACE:
            required = detail.get("required", "")
            return f"not enough disk space{f': {required}' if required else ''}"

        case Cause.PACKAGE_AUTH_FAILED:
            return "packages could not be authenticated"

        case Cause.DOWNLOAD_FAILED:
            return "the upgrade could not be downloaded"

        case Cause.UPDATE_FAILED:
            return "refreshing the package lists failed"

        case Cause.CACHE_LOCK_FAILED:
            return "another package manager holds the apt lock"

        case Cause.FILESYSTEM_NOT_WRITABLE:
            path = detail.get("path", "")
            return f"cannot write to {path}" if path else "a required path is not writable"

        case Cause.SSH_UPGRADE_BLOCKED:
            return "the upgrade was refused over SSH"

        case Cause.ESP_UNUSABLE:
            return "the EFI system partition is not usable"

        case Cause.UNSUPPORTED_UPGRADE_PATH:
            return "this upgrade path is not supported"

        case Cause.UPGRADER_CRASH:
            exception = detail.get("exception", "")
            return f"the upgrader crashes: {exception}" if exception else ("the upgrader crashes")

        case Cause.POST_INSTALL_SCRIPT_ERROR:
            script = detail.get("script", "")
            return (
                f"post-install script {script} fails" if script else ("a post-install script fails")
            )

        case Cause.BROKEN_PACKAGES_AFTER_UPGRADE:
            return f"{_count(victims)} left broken after the upgrade"

        case Cause.NO_FAILURE_RECORDED:
            phase = finding.detail.get("terminal_phase", "")
            where = f" during {phase}" if phase else ""
            return f"logs end{where} with no failure recorded"

        case _:
            tail = f", affecting {_count(victims)}" if victims else ""
            return f"{primary} could not be resolved{tail}"


def _trim(text: str, limit: int) -> tuple[str, bool]:
    """Trim at a word boundary. Never splits a package name."""
    if len(text) <= limit:
        return (text, False)
    cut = text[: limit - 1]
    space = cut.rfind(" ")
    if space > limit // 2:
        cut = cut[:space]
    return (cut.rstrip(" ,:;") + "\u2026", True)


def propose_title(
    run: UpgradeRun,
    result: DiagnosisResult,
    interner: Interner,
    *,
    max_length: int = MAX_TITLE,
) -> ProposedTitle:
    """Build a title for one diagnosed run.

    The release pair always leads. These bugs are triaged in bulk and the first
    question about any of them is which upgrade it was, so putting it first
    makes a bug list sortable by the thing people filter on.
    """
    prefix = run.release_pair
    primary = result.primary

    if primary is None:
        detail = "no failure recorded in the attached logs"
        title, truncated = _trim(f"{prefix}: {detail}", max_length)
        return ProposedTitle(
            title=title,
            detail=detail,
            cause=Cause.NO_FAILURE_RECORDED,
            packages=(),
            confident=False,
            truncated=truncated,
        )

    detail = render_detail(primary, interner, run=run)
    packages = tuple(interner.package_label(p) for p in primary.root_pkgs if p)

    # A diagnosis drawn from truncated logs is offered, never asserted. The
    # caveat stays attached so the report can show why.
    confident = run.evidence_complete and primary.cause is not Cause.NO_FAILURE_RECORDED
    if not confident and primary.cause is not Cause.NO_FAILURE_RECORDED:
        detail = f"{detail} (unconfirmed: logs incomplete)"

    title, truncated = _trim(f"{prefix}: {detail}", max_length)
    return ProposedTitle(
        title=title,
        detail=detail,
        cause=primary.cause,
        packages=packages,
        confident=confident,
        truncated=truncated,
    )


def title_for_cluster(
    titles: Sequence[ProposedTitle],
) -> ProposedTitle | None:
    """Pick one title to represent a duplicate cluster.

    The most confident, then the most specific, then the shortest -- a short
    title that names a package beats a long one that hedges. Deterministic, so
    re-running over a corpus does not reshuffle the output.
    """
    usable = [t for t in titles if t.is_usable]
    if not usable:
        return titles[0] if titles else None
    return min(
        usable,
        key=lambda t: (not t.confident, -len(t.packages), len(t.title), t.title),
    )


def phase_note(run: UpgradeRun) -> str:
    """A short statement of how far the upgrade got.

    Reported beside the title because it answers the triager's second question
    -- is this machine broken, or did it simply refuse to start -- and the
    answer determines urgency.
    """
    if run.terminal_phase is Phase.UNKNOWN:
        return "stage unknown"
    if run.reached_dpkg:
        return f"packages were written (reached {run.terminal_phase.name})"
    return f"nothing was written (stopped at {run.terminal_phase.name})"
