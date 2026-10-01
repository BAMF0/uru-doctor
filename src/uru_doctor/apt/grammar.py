"""The ``apt.log`` line grammar.

The upgrader enables exactly three apt debug streams and no others
(``DistUpgradeCache._initAptLog`` sets ``Debug::pkgProblemResolver``,
``Debug::pkgDepCache::Marker`` and ``Debug::pkgDepCache::AutoInstall``; every
other ``Debug::`` call in the ``DistUpgrade`` tree is commented out). The set of
line shapes is therefore closed and enumerable, which is why this module is a
table rather than a heuristic.

Two decisions shape it.

**Matching happens on a skeleton, not the raw line.** Each line is first
stripped of its ``< ... @... >`` state expressions by
:mod:`uru_doctor.apt.state`, leaving a short fixed phrase and one or two package
references. Patterns then match that. This keeps verb recognition independent of
the state format, which matters because apt documents the state format as
unstable and it demonstrably differs between apt 2.8 and apt 3.2 -- a change
there should cost us mode decoding, not the ability to read the log at all.

**Unmatched lines are counted, not discarded.** The verb table was built from
six real logs, and it was still incomplete: scanning bug 2169028 turned up
``Re-Instated``, ``Upgrading X due to Breaks field in Y`` and two
``Upgrading``-with-state shapes that were not in it. Anything unmatched flows to
``uru-doctor templates --unclassified`` so the next gap is found the same way
rather than by being silently dropped.

A note on apt versions: the ``[apt].grammar`` setting exists because an
LTS-to-LTS upgrade runs the *source* release's apt, so these bugs carry apt 2.8
output. In the logs examined, the verbs are identical across apt 2.8.3 and
3.2.0 and only the state vocabulary differs. Rather than invent a second table
that has never been needed, there is one table here and
:func:`variant_for_version` records which dialect a log was, so that a future
genuine divergence has somewhere obvious to live.
"""

from __future__ import annotations

import re
from enum import StrEnum

from uru_doctor.models import AptStream, DepType

# ---------------------------------------------------------------------------
# Fragments
# ---------------------------------------------------------------------------

#: A package reference as apt prints it: ``name`` or ``name:arch``, where arch
#: may carry a ``:any`` multiarch qualifier.
REF = r"[a-z0-9][a-z0-9+.~-]*(?::[a-z0-9]+(?::any)?)?"

#: A Debian relationship name as it appears in resolver output.
DEP = r"(?:Pre-?Depends|Depends|Breaks|Conflicts|Recommends|Suggests|Replaces|Enhances)"

#: apt's resolver scores, which go negative.
SCORE = r"-?\d+"

#: Maps the spelling in the log to the enum. ``PreDepends`` appears both with
#: and without the hyphen depending on code path.
DEP_TYPES: dict[str, DepType] = {
    "depends": DepType.DEPENDS,
    "predepends": DepType.PRE_DEPENDS,
    "pre-depends": DepType.PRE_DEPENDS,
    "breaks": DepType.BREAKS,
    "conflicts": DepType.CONFLICTS,
    "recommends": DepType.RECOMMENDS,
    "suggests": DepType.SUGGESTS,
    "replaces": DepType.REPLACES,
    "enhances": DepType.UNKNOWN,
}


def dep_type(name: str | None) -> DepType:
    """Resolve a relationship name, tolerating case and the hyphen variant."""
    if not name:
        return DepType.UNKNOWN
    return DEP_TYPES.get(name.strip().lower(), DepType.UNKNOWN)


# ---------------------------------------------------------------------------
# Verbs
# ---------------------------------------------------------------------------


class Verb(StrEnum):
    """Every ``apt.log`` line shape this build recognises.

    Grouped by the debug stream that emits it. The resolver verbs carry the
    conflict record; the marker and autoinstall verbs carry context and the
    dependency recursion.
    """

    # -- section framing, written by the upgrader itself ---------------------
    LOG_TIME = "log_time"

    # -- Debug::pkgProblemResolver -----------------------------------------
    STARTING = "starting"
    """``Starting pkgProblemResolver with broken count: N``, and the
    ``Starting 2`` second pass of the same resolve."""

    INVESTIGATING = "investigating"
    """``Investigating (N) <pkg> <state>`` -- N is the resolver pass."""

    BROKEN = "broken"
    """``Broken A <DepType> on B <state> [(op ver)]``.

    The blame record. Everything :mod:`uru_doctor.apt.roots` does is built from
    these and nothing else.
    """

    CANT_BE_SATISFIED = "cant_be_satisfied"
    """``A <DepType> on B <state> (op ver) can't be satisfied!`` and its
    ``(dep)``-suffixed variant.

    A bare, indented line with no verb keyword, which is why it was missed on
    the first pass over the grammar. It is a *stronger* claim than ``Broken``:
    apt is saying the relationship cannot be satisfied at all, rather than that
    it currently is not. These lines name cascade roots directly -- the
    ``libselinux1-dev Depends on libselinux1 (= 3.8.1-1build1)`` statement that
    explains eleven downstream ``-dev`` breakages is one of them.
    """

    PACKAGE_DEP = "package_dep"
    """``Package A A <DepType> on B <state>``.

    apt prints the package name twice here, once as a header and once from its
    pretty-printer. Observed only around obsolete kernel metapackages marked for
    purge -- the ``obsolete package 'linux-headers-N' could not be removed``
    case.
    """

    CONSIDERING = "considering"
    """``Considering B <score> as a solution to A <score>``.

    The score pair explains which remedy apt preferred and by how much. A
    one-point margin is why the lintian holdback was irreproducible.
    """

    HOLDING_BACK = "holding_back"
    """``Holding Back A rather than change B`` -- the stalled-upgrade signature."""

    REMOVING_RATHER = "removing_rather"
    """``Removing B rather than change A``."""

    FIXING_VIA_REMOVE = "fixing_via_remove"
    FIXING_VIA_KEEP = "fixing_via_keep"
    ADDED_TO_REMOVE_LIST = "added_to_remove_list"
    KEEPING_PACKAGE = "keeping_package"
    DEPS_NOT_SATISFIED = "deps_not_satisfied"
    DELAYED_REMOVING = "delayed_removing"
    REMOVING_NOT_POSSIBLE = "removing_not_possible"
    """``Removing: A as upgrade is not possible``.

    The follow-through on a ``Delayed Removing:`` -- apt committing to the
    removal it had deferred. Carries only the victim, since the package that
    forced it was named on the earlier deferred line.
    """

    REINST_FAILED = "reinst_failed"
    """``Reinst Failed because of A`` -- a re-instatement attempt that did not
    take, naming what blocked it."""

    TRY_REINSTATE = "try_reinstate"
    REINSTATED = "reinstated"
    """``Re-Instated <pkg>`` -- the resolver undoing a removal. Appeared 174
    times in one real log and was absent from the first draft of this table."""

    TRY_INSTALLING_BEFORE = "try_installing_before"
    """``Try Installing B <state> before changing A``.

    apt weighing the alternative to a holdback: install the missing new
    dependency instead of pinning the dependent. When this is followed by
    ``Holding Back A rather than change B``, the log is showing the exact moment
    the upgrade was lost -- apt considered the fix and declined it.
    """

    IGNORE_MARK_KEEP_PROTECTED = "ignore_mark_keep_protected"
    """``Ignore MarkKeep of B <state> as its mode (Install) is protected``.

    The resolver trying to back out of an install it is not permitted to
    reverse. Useful context for why a holdback landed where it did.
    """

    OR_GROUP_KEEP = "or_group_keep"
    """``Or group keep for A`` -- an alternation left unsatisfied."""

    SETTING_NOT_AUTO = "setting_not_auto"
    """``Setting A NOT as auto-installed (direct Depends of B which is in
    APT::Never-MarkAuto-Sections)``.

    Bookkeeping from the autoinstall stream, not a conflict. High volume --
    over six hundred lines in one real log -- so it is recognised explicitly
    rather than left to inflate the unclassified report and drown the shapes
    that matter.
    """

    ENTERING_RESOLVE_BY_KEEP = "entering_resolve_by_keep"
    """``Entering ResolveByKeep`` -- apt giving up on a clean resolution.

    Also occurs with no preceding ``Starting``, so its presence is informative
    but its absence proves nothing.
    """

    DONE = "done"

    # -- Debug::pkgDepCache::Marker ----------------------------------------
    MARK_INSTALL = "mark_install"
    MARK_DELETE = "mark_delete"
    MARK_KEEP = "mark_keep"
    MARK_PURGE = "mark_purge"
    REMOVING = "removing"
    """A bare ``Removing <pkg>`` with no ``rather than change`` clause."""

    # -- Debug::pkgDepCache::AutoInstall -----------------------------------
    INSTALLING_AS = "installing_as"
    """``Installing B as Depends of A`` -- the dependency recursion edges."""

    UPGRADING_DUE_TO_FIELD = "upgrading_due_to_field"
    """``Upgrading A due to Breaks field in B``."""

    UPGRADING_DUE_TO_DEP = "upgrading_due_to_dep"
    """``Upgrading: A <state> due to B Depends on C <state> (= v)``.

    Note the colon. Carries two package references beyond the subject and two
    state expressions, which is why states are extracted before matching.
    """

    UPGRADING_DUE_TO = "upgrading_due_to"
    """``Upgrading A <state> due to B``. Indented to 28 columns in real logs."""

    IGNORE_OLD_UNSATISFIED = "ignore_old_unsatisfied"
    NEW_IMPORTANT_DEP = "new_important_dep"
    PREVIOUSLY_SATISFIED = "previously_satisfied"

    # -- fallback -----------------------------------------------------------
    UNKNOWN = "unknown"


#: Which stream each verb belongs to, for provenance in reports.
VERB_STREAM: dict[Verb, AptStream] = {
    Verb.LOG_TIME: AptStream.SECTION,
    Verb.STARTING: AptStream.RESOLVER,
    Verb.INVESTIGATING: AptStream.RESOLVER,
    Verb.BROKEN: AptStream.RESOLVER,
    Verb.CANT_BE_SATISFIED: AptStream.RESOLVER,
    Verb.PACKAGE_DEP: AptStream.RESOLVER,
    Verb.CONSIDERING: AptStream.RESOLVER,
    Verb.HOLDING_BACK: AptStream.RESOLVER,
    Verb.REMOVING_RATHER: AptStream.RESOLVER,
    Verb.FIXING_VIA_REMOVE: AptStream.RESOLVER,
    Verb.FIXING_VIA_KEEP: AptStream.RESOLVER,
    Verb.ADDED_TO_REMOVE_LIST: AptStream.RESOLVER,
    Verb.KEEPING_PACKAGE: AptStream.RESOLVER,
    Verb.DEPS_NOT_SATISFIED: AptStream.RESOLVER,
    Verb.DELAYED_REMOVING: AptStream.RESOLVER,
    Verb.REMOVING_NOT_POSSIBLE: AptStream.RESOLVER,
    Verb.REINST_FAILED: AptStream.RESOLVER,
    Verb.TRY_REINSTATE: AptStream.RESOLVER,
    Verb.REINSTATED: AptStream.RESOLVER,
    Verb.TRY_INSTALLING_BEFORE: AptStream.RESOLVER,
    Verb.IGNORE_MARK_KEEP_PROTECTED: AptStream.RESOLVER,
    Verb.OR_GROUP_KEEP: AptStream.RESOLVER,
    Verb.SETTING_NOT_AUTO: AptStream.AUTOINSTALL,
    Verb.ENTERING_RESOLVE_BY_KEEP: AptStream.RESOLVER,
    Verb.DONE: AptStream.RESOLVER,
    Verb.MARK_INSTALL: AptStream.MARKER,
    Verb.MARK_DELETE: AptStream.MARKER,
    Verb.MARK_KEEP: AptStream.MARKER,
    Verb.MARK_PURGE: AptStream.MARKER,
    Verb.REMOVING: AptStream.MARKER,
    Verb.INSTALLING_AS: AptStream.AUTOINSTALL,
    Verb.UPGRADING_DUE_TO_FIELD: AptStream.AUTOINSTALL,
    Verb.UPGRADING_DUE_TO_DEP: AptStream.AUTOINSTALL,
    Verb.UPGRADING_DUE_TO: AptStream.AUTOINSTALL,
    Verb.IGNORE_OLD_UNSATISFIED: AptStream.AUTOINSTALL,
    Verb.NEW_IMPORTANT_DEP: AptStream.AUTOINSTALL,
    Verb.PREVIOUSLY_SATISFIED: AptStream.AUTOINSTALL,
    Verb.UNKNOWN: AptStream.UNKNOWN,
}


# ---------------------------------------------------------------------------
# Pattern table
# ---------------------------------------------------------------------------

#: ``(verb, pattern)`` tried in order against the state-stripped skeleton.
#:
#: Order arbitrates genuine prefix ambiguity, and three cases depend on it:
#:
#: - ``Upgrading A due to Breaks field in B`` must precede
#:   ``Upgrading A due to B``, or the longer form matches the shorter pattern
#:   with ``object`` set to the word ``Breaks``.
#: - ``Upgrading: A due to B Depends on C`` (with the colon) must precede both.
#: - ``Removing B rather than change A`` must precede bare ``Removing B``.
#:
#: Patterns are anchored at both ends. An unanchored pattern would quietly
#: accept a truncated line, and a log cut off mid-write is a case that actually
#: occurs -- bug 2169028's ``apt.log`` ends inside a resolve.
PATTERNS: tuple[tuple[Verb, re.Pattern[str]], ...] = (
    # -- section framing ----------------------------------------------------
    (Verb.LOG_TIME, re.compile(r"^Log time:\s*(?P<timestamp>.+)$")),
    # -- resolver: framing --------------------------------------------------
    (
        Verb.STARTING,
        re.compile(
            r"^Starting(?:\s+(?P<pass>\d+))?\s+pkgProblemResolver"
            r"\s+with\s+broken\s+count:\s*(?P<broken>\d+)$"
        ),
    ),
    (Verb.ENTERING_RESOLVE_BY_KEEP, re.compile(r"^Entering\s+ResolveByKeep$")),
    (Verb.DONE, re.compile(r"^Done$")),
    # -- resolver: the blame record ----------------------------------------
    (
        Verb.BROKEN,
        re.compile(
            rf"^Broken\s+(?P<subject>{REF})\s+(?P<dep>{DEP})\s+on\s+(?P<object>{REF})"
            r"(?:\s+\((?P<constraint>[^)]*)\))?$"
        ),
    ),
    (Verb.INVESTIGATING, re.compile(rf"^Investigating\s+\((?P<pass>\d+)\)\s+(?P<subject>{REF})$")),
    (
        Verb.DEPS_NOT_SATISFIED,
        re.compile(rf"^Dependencies\s+are\s+not\s+satisfied\s+for\s+(?P<subject>{REF})$"),
    ),
    # -- resolver: decisions ------------------------------------------------
    (
        Verb.CONSIDERING,
        re.compile(
            rf"^Considering\s+(?P<subject>{REF})\s+(?P<score_src>{SCORE})"
            rf"\s+as\s+a\s+solution\s+to\s+(?P<object>{REF})\s+(?P<score_dst>{SCORE})$"
        ),
    ),
    (
        Verb.HOLDING_BACK,
        re.compile(
            rf"^Holding\s+Back\s+(?P<subject>{REF})\s+rather\s+than\s+change\s+(?P<object>{REF})$"
        ),
    ),
    (
        Verb.REMOVING_RATHER,
        re.compile(
            rf"^Removing\s+(?P<subject>{REF})\s+rather\s+than\s+change\s+(?P<object>{REF})$"
        ),
    ),
    (
        Verb.FIXING_VIA_REMOVE,
        re.compile(rf"^Fixing\s+(?P<subject>{REF})\s+via\s+remove\s+of\s+(?P<object>{REF})$"),
    ),
    (
        Verb.FIXING_VIA_KEEP,
        re.compile(rf"^Fixing\s+(?P<subject>{REF})\s+via\s+keep\s+of\s+(?P<object>{REF})$"),
    ),
    (
        Verb.ADDED_TO_REMOVE_LIST,
        re.compile(rf"^Added\s+(?P<subject>{REF})\s+to\s+the\s+remove\s+list$"),
    ),
    (
        # Both capitalisations occur, and the ``due to`` clause is optional:
        # ``Keeping Package X due to Depends`` and bare ``Keeping package X``
        # are emitted from different code paths in the same apt.
        Verb.KEEPING_PACKAGE,
        re.compile(
            rf"^Keeping\s+[Pp]ackage\s+(?P<subject>{REF})"
            rf"(?:\s+due\s+to\s+(?P<dep>\S+))?$"
        ),
    ),
    (
        Verb.PACKAGE_DEP,
        re.compile(
            rf"^Package\s+(?P<subject>{REF})\s+(?P<echo>{REF})"
            rf"\s+(?P<dep>{DEP})\s+on\s+(?P<object>{REF})$"
        ),
    ),
    (
        Verb.DELAYED_REMOVING,
        re.compile(
            rf"^Delayed\s+Removing:\s+(?P<subject>{REF})\s+as\s+upgrade\s+is\s+not\s+an\s+option"
            rf"\s+for\s+(?P<object>{REF})(?:\s+\((?P<constraint>[^)]*)\))?$"
        ),
    ),
    (
        Verb.REMOVING_NOT_POSSIBLE,
        re.compile(
            rf"^Removing:\s+(?P<subject>{REF})\s+as\s+upgrade\s+is\s+not\s+"
            rf"(?:possible|an\s+option\s+for\s+(?P<object>{REF})"
            r"(?:\s+\((?P<constraint>[^)]*)\))?)$"
        ),
    ),
    (
        Verb.SETTING_NOT_AUTO,
        re.compile(
            rf"^Setting\s+(?P<subject>{REF})\s+NOT\s+as\s+auto-installed"
            rf"\s+\(direct\s+(?P<dep>{DEP})\s+of\s+(?P<object>{REF})"
            r"\s+which\s+is\s+in\s+[\w:.-]+\)$"
        ),
    ),
    (
        Verb.REINST_FAILED,
        re.compile(rf"^Reinst\s+Failed\s+because\s+of\s+(?P<subject>{REF})$"),
    ),
    (
        Verb.TRY_REINSTATE,
        re.compile(rf"^Try\s+to\s+Re-?Instate\s+\((?P<pass>\d+)\)\s+(?P<subject>{REF})$"),
    ),
    (Verb.REINSTATED, re.compile(rf"^Re-?Instated\s+(?P<subject>{REF})$")),
    (
        Verb.TRY_INSTALLING_BEFORE,
        re.compile(
            rf"^Try\s+Installing\s+(?P<subject>{REF})\s+before\s+changing\s+(?P<object>{REF})$"
        ),
    ),
    (
        Verb.IGNORE_MARK_KEEP_PROTECTED,
        re.compile(
            rf"^Ignore\s+Mark(?:Keep|Install|Delete|Garbage)\s+of\s+(?P<subject>{REF})"
            r"\s+as\s+its\s+mode\s+\((?P<mode>\w+)\)\s+is\s+protected$"
        ),
    ),
    (
        Verb.OR_GROUP_KEEP,
        re.compile(rf"^Or\s+group\s+keep\s+for\s+(?P<subject>{REF})$"),
    ),
    # -- marker -------------------------------------------------------------
    (
        Verb.MARK_INSTALL,
        re.compile(rf"^MarkInstall\s+(?P<subject>{REF})(?:\s+FU=(?P<fu>[01]))?$"),
    ),
    (
        Verb.MARK_DELETE,
        re.compile(rf"^MarkDelete\s+(?P<subject>{REF})(?:\s+FU=(?P<fu>[01]))?$"),
    ),
    (Verb.MARK_KEEP, re.compile(rf"^MarkKeep\s+(?P<subject>{REF})(?:\s+FU=(?P<fu>[01]))?$")),
    (Verb.MARK_PURGE, re.compile(rf"^MarkPurge\s+(?P<subject>{REF})(?:\s+FU=(?P<fu>[01]))?$")),
    # -- autoinstall --------------------------------------------------------
    (
        Verb.INSTALLING_AS,
        re.compile(
            rf"^Installing\s+(?P<subject>{REF})\s+as\s+(?P<dep>{DEP})\s+of\s+(?P<object>{REF})$"
        ),
    ),
    # Longest first: the colon form, then the "field in" form, then the plain.
    (
        Verb.UPGRADING_DUE_TO_DEP,
        re.compile(
            rf"^Upgrading:\s+(?P<subject>{REF})\s+due\s+to\s+(?P<object>{REF})"
            rf"\s+(?P<dep>{DEP})\s+on\s+(?P<third>{REF})"
            r"(?:\s+\((?P<constraint>[^)]*)\))?$"
        ),
    ),
    (
        Verb.UPGRADING_DUE_TO_FIELD,
        re.compile(
            rf"^Upgrading:?\s+(?P<subject>{REF})\s+due\s+to\s+(?P<dep>{DEP})"
            rf"\s+field\s+in\s+(?P<object>{REF})$"
        ),
    ),
    (
        Verb.UPGRADING_DUE_TO,
        re.compile(rf"^Upgrading:?\s+(?P<subject>{REF})\s+due\s+to\s+(?P<object>{REF})$"),
    ),
    (
        Verb.IGNORE_OLD_UNSATISFIED,
        re.compile(
            r"^ignore\s+old\s+unsatisfied\s+(?:important\s+)?dependency"
            rf"\s+on\s+(?P<subject>{REF})$"
        ),
    ),
    (
        Verb.NEW_IMPORTANT_DEP,
        re.compile(rf"^new\s+important\s+dependency:\s*(?P<subject>{REF})$"),
    ),
    (
        Verb.PREVIOUSLY_SATISFIED,
        re.compile(
            r"^previously\s+satisfied\s+(?:important\s+)?dependency"
            rf"\s+on\s+(?P<subject>{REF})$"
        ),
    ),
    # Bare `Removing X`, after the `rather than change` form above.
    (Verb.REMOVING, re.compile(rf"^Removing\s+(?P<subject>{REF})$")),
    # Last: this one opens with a bare package reference rather than a keyword,
    # so it must not get the chance to shadow a keyword-anchored pattern. The
    # trailing `can't be satisfied!` makes it unambiguous in practice, but
    # ordering removes the question entirely.
    (
        Verb.CANT_BE_SATISFIED,
        re.compile(
            rf"^(?P<subject>{REF})\s+(?P<dep>{DEP})\s+on\s+(?P<object>{REF})"
            r"(?:\s+\((?P<constraint>[^)]*)\))?"
            r"\s+can't\s+be\s+satisfied!(?:\s+\(dep\))?$"
        ),
    ),
)


# ---------------------------------------------------------------------------
# Dialects
# ---------------------------------------------------------------------------


class Dialect(StrEnum):
    """Which apt produced a log.

    Recorded on every parse so that a report can say which dialect it read, and
    so a genuine future grammar divergence has an obvious place to branch. The
    verbs above are shared by every dialect observed so far; the differences are
    confined to the state vocabulary, which
    :mod:`uru_doctor.apt.state` handles without needing to know the version.
    """

    APT2 = "apt2"
    APT3 = "apt3"
    UNKNOWN = "unknown"


def variant_for_version(apt_version: str | None) -> Dialect:
    """Classify an ``apt version:`` string from ``main.log``.

    A 24.04-to-26.04 bug reports apt 2.8.x, because the upgrade runs the source
    release's apt. A 26.04-to-26.10 bug reports apt 3.x. Both occur in the same
    corpus.
    """
    if not apt_version:
        return Dialect.UNKNOWN
    major, _, _ = apt_version.strip().partition(".")
    if major == "2":
        return Dialect.APT2
    if major == "3":
        return Dialect.APT3
    return Dialect.UNKNOWN
