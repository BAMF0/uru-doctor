"""The domain model: enums, the conflict graph, and the per-run record.

Everything in this module is frozen and either a small scalar, an interned
``u32`` id, or a packed binary blob. Nothing holds a raw log line. That is the
point: a bug report arrives as several megabytes of text across up to six log
files, and leaves here as a record of a few kilobytes that the rest of the tool
can hold entirely in memory and compare byte-for-byte.

Three conventions run through the whole model.

**Interning.** Package names, version strings, file paths and repository
origins repeat endlessly across a corpus -- ``python3`` appears in forty
``Broken`` lines of a single log, and in most logs of every bug. They are
interned once, globally, in :mod:`uru_doctor.intern` and referenced here as
:data:`StrId` / :data:`PkgId`.

**Packed arrays.** Collections that are iterated far more often than they are
inspected individually -- graph edges, package sets -- are stored as
:mod:`array`-packed ``u32`` blobs rather than Python lists. This is not
premature optimisation: the conflict graph is traversed once per root-finding
pass and once per candidate duplicate pair, and the packed form is both
contiguous and directly storable as a SQLite BLOB with no serialisation step.

**Verbatim preservation of apt's debug tokens.** apt's own headers warn that
the ``pkgDepCache`` debug format is "subject to change without prior notice".
Observed vocabularies already differ between apt 2.8 and apt 3.2, including
shapes with no mode group at all (``@un H``) and four-character mode groups
(``@un pumN Ib``). So the flag blob is interned whole and only the parts that
have been empirically verified are decoded into :class:`NodeBits`. A future apt
that changes the format degrades this tool to "cannot decode mode", not to
"silently wrong diagnosis".
"""

from __future__ import annotations

from array import array
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Interned id aliases
# ---------------------------------------------------------------------------

#: An id into the global ``strings`` table. 0 is reserved for "absent", so that
#: a packed array of ids can represent optionality without a parallel mask.
StrId = int

#: An id into the global ``packages`` table. Keyed on the full ``name:arch``
#: because architecture is load-bearing: ``i965-va-driver:i386`` and its amd64
#: namesake are different nodes with different resolutions.
PkgId = int

#: An id into the global ``templates`` table.
TemplateId = int

#: Reserved id meaning "no value".
ABSENT: StrId = 0


# ---------------------------------------------------------------------------
# Base model
# ---------------------------------------------------------------------------


class Frozen(BaseModel):
    """Base for every model in this module.

    Immutable, because a record is a parsed fact and nothing downstream has any
    business editing one -- diagnosis returns a new record rather than mutating
    the old, which is what lets a rule change be replayed over the whole corpus.

    ``bytes`` round-trip as base64 rather than as UTF-8. This model is full of
    packed binary arrays, and the default byte handling tries to decode them as
    text and fails on the first graph that happens to contain a high byte.
    """

    model_config = ConfigDict(
        frozen=True,
        ser_json_bytes="base64",
        val_json_bytes="base64",
    )


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ProblemType(StrEnum):
    """apport's ``ProblemType``, which decides how a bug reached Launchpad.

    The three paths produce materially different evidence, so this is checked
    before anything else is attempted:

    - ``CRASH`` -- a Python traceback in the upgrader itself. Carries a
      ``Traceback`` field and an apport-computed ``DuplicateSignature``, which
      is authoritative and makes deduplication free.
    - ``PACKAGE`` -- ``apport_pkgfailure()`` fired on a dpkg error. Filed
      against the *failing package*, not against ubuntu-release-upgrader, and
      carries the dpkg error text as ``ErrorMessage``.
    - ``BUG`` -- filed by hand with ``ubuntu-bug``. The most common kind for
      resolver failures, because ``apport_pkgfailure`` deliberately suppresses
      auto-filing for dependency problems and for ENOSPC.
    """

    CRASH = "Crash"
    PACKAGE = "Package"
    BUG = "Bug"
    UNKNOWN = "Unknown"


class Arch(StrEnum):
    """Binary architecture. ``ALL`` is Debian's ``Architecture: all``."""

    AMD64 = "amd64"
    I386 = "i386"
    ARM64 = "arm64"
    ARMHF = "armhf"
    PPC64EL = "ppc64el"
    S390X = "s390x"
    RISCV64 = "riscv64"
    ALL = "all"
    ANY = "any"
    UNKNOWN = "unknown"


class Frontend(StrEnum):
    """Which ``DistUpgradeView`` drove the upgrade.

    Read from ``Using 'DistUpgradeViewX' view`` in ``main.log``. Worth keeping
    because the non-interactive and text frontends answer prompts differently
    from the GTK and KDE ones, which changes which failures are reachable.
    """

    GTK3 = "Gtk3"
    KDE = "KDE"
    TEXT = "Text"
    NON_INTERACTIVE = "NonInteractive"
    UNKNOWN = "unknown"


class Phase(IntEnum):
    """Where in the upgrade we are, derived from ``main.log`` markers.

    Ordered, and the order is meaningful: :attr:`UpgradeRun.terminal_phase` is
    the furthest phase observed, and a failure in a later phase is more likely
    to be the real one. The markers come from ``DistUpgradeController`` and
    ``DistUpgradeCache``; see :mod:`uru_doctor.phases` for the mapping.

    ``COMMIT`` is the boundary that matters most. Before it, nothing has been
    written to the system and the failure is a planning failure. After it, dpkg
    has run and packages are in an indeterminate state.
    """

    UNKNOWN = 0
    INIT = 10
    SCREEN_REEXEC = 15
    PRE_CACHE_OPEN = 20
    CACHE_OPEN = 25
    VIEW_DEPENDS = 30
    INITIAL_UPDATE = 35
    POST_INITIAL_UPDATE = 40
    SOURCES_REWRITE = 45
    SECOND_UPDATE = 50
    PRE_DIST_UPGRADE = 55
    CALCULATE = 60
    FETCH = 65
    COMMIT = 70
    POST_UPGRADE = 75
    REMOVE_OBSOLETE = 80
    POST_CLEANUP = 85
    POST_INSTALL_SCRIPTS = 90
    DONE = 100

    @property
    def is_pre_commit(self) -> bool:
        """True when no package has been unpacked yet.

        A cheap and strong signal: when a bug ships no ``apt-term.log`` and no
        ``history.log``, dpkg never ran, so the failure is necessarily here.
        """
        return self < Phase.COMMIT


class PhaseOutcome(StrEnum):
    """How a phase ended."""

    OK = "ok"
    FAILED = "failed"
    #: The log stops inside this phase. Not a failure -- an absence of evidence.
    TRUNCATED = "truncated"
    UNKNOWN = "unknown"


class LogSource(StrEnum):
    """Which file an event came from, for provenance in reports.

    ``SCREENLOG`` is deliberately last: it is raw terminal capture with ANSI
    escapes and carriage-return progress spam, so findings derived only from it
    carry a confidence penalty.
    """

    MAIN = "main.log"
    APT = "apt.log"
    APT_TERM = "apt-term.log"
    HISTORY = "history.log"
    TERM = "term.log"
    XORG_FIXUP = "xorg_fixup.log"
    SCREENLOG = "screenlog.0"
    APPORT = "apport"
    SCREENLOG_DERIVED = "screenlog.0 (derived)"


class Level(StrEnum):
    """Severity of a log event, as recorded by the producing log.

    A :class:`StrEnum`, so the member values compare as *strings*. Do not
    order them with ``<`` or ``>``: ``Level.INFO >= Level.ERROR`` is true
    because ``"INFO" >= "ERROR"`` alphabetically. Use :attr:`is_problem` or
    compare against members explicitly.
    """

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"

    @property
    def is_problem(self) -> bool:
        """Whether the producing log considered this a warning or worse.

        ``UNKNOWN`` is excluded. It means the level could not be parsed, which
        is a parser problem rather than evidence about the upgrade.
        """
        return self in (Level.WARNING, Level.ERROR)

    @property
    def is_error(self) -> bool:
        return self is Level.ERROR


class AptStream(StrEnum):
    """Which apt debug stream produced an ``apt.log`` line.

    The upgrader enables exactly three (``DistUpgradeCache._initAptLog``), so
    this is a closed set, not a guess:

    - ``RESOLVER`` -- ``Debug::pkgProblemResolver``. The conflict record. About
      20% of lines and effectively all of the signal.
    - ``MARKER`` -- ``Debug::pkgDepCache::Marker``. ``MarkInstall`` and friends.
    - ``AUTOINSTALL`` -- ``Debug::pkgDepCache::AutoInstall``. The dependency
      recursion tree, plus a lot of ``ignore old unsatisfied`` noise.

    ``SECTION`` covers the ``Log time:`` headers the upgrader writes itself.
    """

    RESOLVER = "resolver"
    MARKER = "marker"
    AUTOINSTALL = "autoinstall"
    SECTION = "section"
    UNKNOWN = "unknown"


class DepType(IntEnum):
    """Debian relationship type on a ``Broken`` line.

    Severity ordering is intentional and is used to rank roots: an unsatisfiable
    ``Depends`` or ``PreDepends`` is a genuine archive problem, whereas a
    ``Breaks`` against an old version is ordinary transitional churn that apt
    resolves by removing the old package.
    """

    UNKNOWN = 0
    RECOMMENDS = 1
    SUGGESTS = 2
    REPLACES = 3
    BREAKS = 4
    CONFLICTS = 5
    DEPENDS = 6
    PRE_DEPENDS = 7

    @property
    def is_hard(self) -> bool:
        """True for relationships that must be satisfied for a working system."""
        return self in (DepType.DEPENDS, DepType.PRE_DEPENDS, DepType.CONFLICTS)


class Mode(IntEnum):
    """The action apt has settled on for a package.

    Decoded from the final character of the mode group in apt's state blob
    (``@ii umU Ib`` -> ``U``). The letter-to-action mapping was confirmed
    empirically rather than assumed: the ``|`` version form
    (``cur | cand``, meaning a candidate exists but was *not* selected) occurs
    only alongside ``R`` and ``H`` modes, while ``->`` (candidate selected)
    occurs with ``U`` and ``N``, which pins the meanings.
    """

    UNKNOWN = 0
    #: Keep the installed version.
    KEEP = 1
    #: Install a newer version.
    UPGRADE = 2
    #: Install a package that is not currently installed.
    NEW_INSTALL = 3
    #: Remove.
    REMOVE = 4
    #: Remove including configuration.
    PURGE = 5
    #: Not installed and the resolver has settled on not installing it, or
    #: installed and pinned. The state that blocks most LTS-to-LTS upgrades.
    HOLD = 6

    @property
    def removes(self) -> bool:
        return self in (Mode.REMOVE, Mode.PURGE)


class EdgeKind(IntEnum):
    """What kind of claim an edge in the conflict graph makes.

    Each corresponds to a distinct line shape in ``apt.log``, and the direction
    of blame differs between them, which is why they are not collapsed into one
    relation.
    """

    UNKNOWN = 0
    #: ``Broken A <DepType> on B (constraint)``. B causes A to be broken, so
    #: blame flows B -> A and roots are found by in-degree on these edges alone.
    BREAKS = 1
    #: ``Installing B as Depends of A``. A pulled B in. Context, not blame.
    AUTOINSTALL = 2
    #: ``Fixing A via remove of B`` / ``Removing B rather than change A`` /
    #: ``Holding Back A rather than change B``. apt's chosen remedy, carrying
    #: the score pair from the preceding ``Considering`` line.
    DECISION = 3
    #: ``Delayed Removing: B as upgrade is not an option for A (v)``.
    DELAYED_REMOVE = 4
    #: ``Upgrading A ... due to B`` / ``Upgrading A due to Breaks field in B``.
    #: B forced A's upgrade -- blame flows opposite to :attr:`BREAKS`.
    UPGRADE_PROP = 5
    #: ``A <DepType> on B (op ver) can't be satisfied!``. A stronger claim than
    #: :attr:`BREAKS`: apt is asserting the relationship cannot be satisfied at
    #: all, not merely that it currently is not. Participates in root finding
    #: alongside ``BREAKS`` and outranks it when both describe the same pair.
    UNSATISFIABLE = 6


#: Edge kinds from which blame flows, and which therefore define the DAG that
#: root finding walks. Deliberately narrow: an autoinstall edge records that one
#: package pulled another in, which is context, not fault, and including it
#: would make every metapackage the root of everything.
BLAME_EDGES: frozenset[int] = frozenset({EdgeKind.BREAKS, EdgeKind.UNSATISFIABLE})


class Decision(IntEnum):
    """Which remedy apt picked, on a :attr:`EdgeKind.DECISION` edge."""

    UNKNOWN = 0
    #: ``Fixing A via remove of B``
    FIX_VIA_REMOVE = 1
    #: ``Fixing A via keep of B``
    FIX_VIA_KEEP = 2
    #: ``Removing B rather than change A``
    REMOVE_RATHER_THAN_CHANGE = 3
    #: ``Holding Back A rather than change B`` -- the signature of a stalled
    #: LTS-to-LTS upgrade.
    HOLD_BACK_RATHER_THAN_CHANGE = 4
    #: ``Keeping Package A due to <DepType>``
    KEEP_DUE_TO = 5
    #: ``Added B to the remove list``
    ADDED_TO_REMOVE_LIST = 6


class Cause(StrEnum):
    """Root-cause classes.

    Every member here was observed in a real failing log before it was added;
    none are speculative. The resolver-derived classes come first because they
    account for the great majority of 24.04-to-26.04 failures.
    """

    # -- resolver (apt.log) --------------------------------------------------
    #: A package must be newly installed to satisfy a dependency, a candidate
    #: exists, but it sits in ``@un ...H`` (not installed, resolver settled on
    #: not installing) -- so apt holds back the dependent instead and the
    #: resolve fails. apt names this itself in its give-up string: "this may be
    #: caused by held packages".
    HOLDBACK_BLOCKS_NEW_DEP = "holdback_blocks_new_dep"
    #: An *installed* package has an available candidate that would satisfy a
    #: dependent's requirement, and apt declined to take it, so the dependent
    #: broke. The same refusal as
    #: :attr:`HOLDBACK_BLOCKS_NEW_DEP` but with a different remedy: the package
    #: needs to be allowed to upgrade rather than to be installed.
    HELD_PACKAGE_BLOCKS_UPGRADE = "held_package_blocks_upgrade"
    #: An exact or upper-bounded pin broken by an ordinary upgrade, e.g. forty
    #: ``python3-*`` packages pinning ``python3 (<< 3.13)`` while python3 moves
    #: 3.12 -> 3.14.
    EXACT_PIN_BROKEN_BY_UPGRADE = "exact_pin_broken_by_upgrade"
    #: A package marked for removal drags its reverse-dependencies down with it.
    REMOVAL_CASCADE = "removal_cascade"
    #: The 64-bit-time_t rename, where ``libfoo1t64`` and ``libfoo1`` conflict
    #: in both directions.
    T64_TRANSITION = "t64_transition"
    #: A dependency on a virtual or ABI package with no provider at all, e.g.
    #: ``libva-driver-abi-1.20 < none @un H >``.
    UNSATISFIABLE_VIRTUAL = "unsatisfiable_virtual"
    #: A stranded i386 multiarch package with no amd64 counterpart.
    I386_ORPHAN = "i386_orphan"
    #: The root comes from a PPA or other non-Ubuntu origin. Routed to its own
    #: report section as a candidate-Invalid, grouped by origin.
    THIRD_PARTY_PIN = "third_party_pin"
    #: Ordinary transitional ``Breaks`` that apt resolves by removal. Low
    #: severity; present so that it is explicitly classified rather than
    #: falling through to UNKNOWN and demanding human attention.
    TRANSITIONAL_BREAKS = "transitional_breaks"

    # -- environment and process -------------------------------------------
    NOT_ENOUGH_DISK_SPACE = "not_enough_disk_space"
    DPKG_INTERRUPTED = "dpkg_interrupted"
    CACHE_LOCK_FAILED = "cache_lock_failed"
    FILESYSTEM_NOT_WRITABLE = "filesystem_not_writable"
    SSH_UPGRADE_BLOCKED = "ssh_upgrade_blocked"
    ESP_UNUSABLE = "esp_unusable"
    VIEW_DEPENDS_MISSING = "view_depends_missing"
    PYTHON_SYMLINK_BROKEN = "python_symlink_broken"

    # -- sources and network -----------------------------------------------
    UNSUPPORTED_UPGRADE_PATH = "unsupported_upgrade_path"
    MIRROR_UNKNOWN = "mirror_unknown"
    PACKAGE_AUTH_FAILED = "package_auth_failed"
    DOWNLOAD_FAILED = "download_failed"
    UPDATE_FAILED = "update_failed"

    # -- dpkg (apt-term.log) -----------------------------------------------
    DPKG_UNPACK_OVERWRITE = "dpkg_unpack_overwrite"
    DPKG_MAINTSCRIPT_FAILED = "dpkg_maintscript_failed"
    DPKG_UNMET_DEPS_UNCONFIGURED = "dpkg_unmet_deps_unconfigured"
    DPKG_TRIGGER_CYCLE = "dpkg_trigger_cycle"
    #: Essential package marked for removal -- the upgrader refuses outright.
    ESSENTIAL_REMOVAL = "essential_removal"
    BROKEN_PACKAGES_AFTER_UPGRADE = "broken_packages_after_upgrade"

    # -- upgrader itself ----------------------------------------------------
    UPGRADER_CRASH = "upgrader_crash"
    POST_INSTALL_SCRIPT_ERROR = "post_install_script_error"

    # -- terminal states ----------------------------------------------------
    #: No rule fired. Surfaced loudly for human review, never silently bucketed.
    UNKNOWN = "unknown"
    #: The log ends without recording an outcome. Distinct from UNKNOWN: there
    #: is no failure to explain, only missing evidence.
    NO_FAILURE_RECORDED = "no_failure_recorded"

    @property
    def is_resolver(self) -> bool:
        """True for causes derived from the apt resolver trace."""
        return self in _RESOLVER_CAUSES

    @property
    def needs_human(self) -> bool:
        """True for causes that mean "I could not explain this"."""
        return self in (Cause.UNKNOWN, Cause.NO_FAILURE_RECORDED)


_RESOLVER_CAUSES: frozenset[Cause] = frozenset(
    {
        Cause.HOLDBACK_BLOCKS_NEW_DEP,
        Cause.HELD_PACKAGE_BLOCKS_UPGRADE,
        Cause.EXACT_PIN_BROKEN_BY_UPGRADE,
        Cause.REMOVAL_CASCADE,
        Cause.T64_TRANSITION,
        Cause.UNSATISFIABLE_VIRTUAL,
        Cause.I386_ORPHAN,
        Cause.THIRD_PARTY_PIN,
        Cause.TRANSITIONAL_BREAKS,
    }
)

#: Causes whose severity does not depend on how many packages they broke.
#:
#: A holdback stops the upgrade dead whether it breaks one dependent or forty,
#: and an unsupported third-party archive needs closing either way. Everything
#: else is judged partly on blast radius, because a single package that pinned
#: itself too tightly is a footnote while forty of them is the headline.
BLAST_RADIUS_INDEPENDENT: frozenset[Cause] = frozenset(
    {
        Cause.HOLDBACK_BLOCKS_NEW_DEP,
        Cause.HELD_PACKAGE_BLOCKS_UPGRADE,
        Cause.THIRD_PARTY_PIN,
    }
)


class Severity(IntEnum):
    """How much a finding should pull a triager's attention."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3


class Confidence(IntEnum):
    """How much the evidence supports a finding.

    ``WEAK`` is reserved for findings derived from ``screenlog.0`` alone or
    from a truncated log, so that the report can separate "this is what broke"
    from "this is the best guess available from what survived".
    """

    WEAK = 0
    MODERATE = 1
    STRONG = 2
    CERTAIN = 3


# ---------------------------------------------------------------------------
# Node state bits
# ---------------------------------------------------------------------------


class NodeBits(IntEnum):
    """Bit positions in the packed per-node flag byte of a conflict graph.

    Only the four broken markers are decoded from apt's state blob, because
    only those four were verifiable from the logs themselves: ``Broken`` lines
    correlate with ``Ib``/``Nb`` presence, which pins their meaning. The mode
    group is decoded separately into :class:`Mode`; everything else in the blob
    is preserved verbatim via :attr:`GraphNodes.raw_flags` and never guessed at.
    """

    #: ``Ib`` -- broken once the planned changes are applied.
    INST_BROKEN = 0
    #: ``Nb`` -- broken right now, before any change.
    NOW_BROKEN = 1
    #: ``IPb`` -- policy-broken after the planned changes.
    INST_POLICY_BROKEN = 2
    #: ``NPb`` -- policy-broken now.
    NOW_POLICY_BROKEN = 3
    #: ``FU=1`` on the governing ``Mark*`` line: the change was user-requested
    #: rather than inferred, which makes it a more credible root.
    FROM_USER = 4
    #: Automatically installed (``g`` in the mode group). Auto-installed
    #: packages make poor roots -- something else asked for them.
    AUTO_INSTALLED = 5
    #: Origin is a PPA or other non-Ubuntu archive, cross-checked against
    #: ``main.log``'s ``Foreign (before rewriting sources)`` list.
    THIRD_PARTY = 6
    #: Subject of a ``Re-Instated`` line: the resolver undid a removal.
    REINSTATED = 7


class VerSelect(IntEnum):
    """Whether apt selected the candidate version.

    The distinction is carried by the version expression inside the state blob
    and is the single most informative bit on a node:

    - ``cur -> cand`` -- candidate selected; the package is moving.
    - ``cur | cand`` -- a candidate exists and was *not* taken. Combined with
      :attr:`Mode.HOLD` this is the holdback that stalls LTS-to-LTS upgrades.
    - ``cur`` alone -- no candidate.
    """

    NONE = 0
    #: ``->``
    SELECTED = 1
    #: ``|``
    AVAILABLE_NOT_SELECTED = 2


# ---------------------------------------------------------------------------
# Packed-array helpers
# ---------------------------------------------------------------------------

#: Typecode for unsigned 32-bit ids. Checked at import because ``array``
#: typecode widths are platform-dependent in principle, and every blob written
#: to the store assumes four bytes.
_U32 = "I"
_I32 = "i"
_U8 = "B"

if array(_U32).itemsize != 4:  # pragma: no cover - not seen on any supported platform
    raise RuntimeError(f"array('{_U32}') is {array(_U32).itemsize} bytes, expected 4")
if array(_I32).itemsize != 4:  # pragma: no cover
    raise RuntimeError(f"array('{_I32}') is {array(_I32).itemsize} bytes, expected 4")


def pack_u32(values: list[int] | tuple[int, ...]) -> bytes:
    """Pack unsigned 32-bit ids into bytes for storage."""
    return array(_U32, values).tobytes()


def unpack_u32(blob: bytes) -> tuple[int, ...]:
    """Unpack what :func:`pack_u32` produced."""
    out = array(_U32)
    out.frombytes(blob)
    return tuple(out)


def pack_i32(values: list[int] | tuple[int, ...]) -> bytes:
    """Pack signed 32-bit values (apt's resolver scores go negative)."""
    return array(_I32, values).tobytes()


def unpack_i32(blob: bytes) -> tuple[int, ...]:
    """Unpack what :func:`pack_i32` produced."""
    out = array(_I32)
    out.frombytes(blob)
    return tuple(out)


def pack_u8(values: list[int] | tuple[int, ...]) -> bytes:
    """Pack small enum values into one byte each."""
    return array(_U8, values).tobytes()


def unpack_u8(blob: bytes) -> tuple[int, ...]:
    """Unpack what :func:`pack_u8` produced."""
    out = array(_U8)
    out.frombytes(blob)
    return tuple(out)


# ---------------------------------------------------------------------------
# Conflict graph
# ---------------------------------------------------------------------------


class GraphNodes(Frozen):
    """The vertex set of a conflict graph, as parallel packed arrays.

    Parallel arrays rather than a list of node objects because every consumer
    either walks all nodes in order (root finding, canonicalisation) or indexes
    one field across many nodes (``which nodes are inst-broken?``). Both are
    served better by six contiguous blobs than by N small objects.

    ``pkg_ids`` is sorted ascending, which is what makes the canonical form of
    the whole graph free: sort the vertices by interned id, renumber the edges
    to vertex *indices*, and two structurally identical graphs serialise to
    identical bytes.
    """

    pkg_ids: bytes
    """Packed ``u32`` :data:`PkgId`, sorted ascending. Defines node indices."""

    cur_ver: bytes
    """Packed ``u32`` :data:`StrId` of the installed version, :data:`ABSENT` if none."""

    cand_ver: bytes
    """Packed ``u32`` :data:`StrId` of the candidate version, :data:`ABSENT` if none."""

    selected: bytes
    """Packed ``u8`` :class:`VerSelect`."""

    mode: bytes
    """Packed ``u8`` :class:`Mode`."""

    bits: bytes
    """Packed ``u8`` bitfields over :class:`NodeBits`."""

    raw_flags: bytes
    """Packed ``u32`` :data:`StrId` of the verbatim state blob, e.g. ``"@ii umU Ib"``.

    Kept because apt documents this format as unstable and the observed
    vocabulary already differs between apt 2.8 and 3.2. When a future apt emits
    something this tool cannot decode, the exact token is still recorded, still
    comparable, and still usable for deduplication.
    """

    def __len__(self) -> int:
        return len(self.pkg_ids) // 4

    @property
    def ids(self) -> tuple[PkgId, ...]:
        return unpack_u32(self.pkg_ids)

    @property
    def modes(self) -> tuple[int, ...]:
        return unpack_u8(self.mode)

    @property
    def selections(self) -> tuple[int, ...]:
        return unpack_u8(self.selected)

    @property
    def bitfields(self) -> tuple[int, ...]:
        return unpack_u8(self.bits)

    @property
    def current_versions(self) -> tuple[StrId, ...]:
        return unpack_u32(self.cur_ver)

    @property
    def candidate_versions(self) -> tuple[StrId, ...]:
        return unpack_u32(self.cand_ver)

    @property
    def raw_flag_ids(self) -> tuple[StrId, ...]:
        return unpack_u32(self.raw_flags)

    def index_of(self, pkg_id: PkgId) -> int | None:
        """Return the node index for ``pkg_id``, or None.

        Binary search, since :attr:`pkg_ids` is sorted.
        """
        ids = self.ids
        lo, hi = 0, len(ids)
        while lo < hi:
            mid = (lo + hi) // 2
            if ids[mid] < pkg_id:
                lo = mid + 1
            else:
                hi = mid
        if lo < len(ids) and ids[lo] == pkg_id:
            return lo
        return None

    def has(self, index: int, bit: NodeBits) -> bool:
        """True when ``bit`` is set on the node at ``index``."""
        return bool(self.bitfields[index] & (1 << bit))


class GraphEdges(Frozen):
    """The edge set of a conflict graph in compressed sparse row form.

    ``offsets`` has ``len(nodes) + 1`` entries; the out-edges of node ``i`` are
    the slice ``targets[offsets[i]:offsets[i + 1]]``. The remaining arrays are
    parallel to ``targets``.

    Targets are node *indices*, not :data:`PkgId`. That halves the working set
    for a graph of a few hundred nodes and, more importantly, makes the encoding
    independent of the global interning tables, so a canonicalised graph hashes
    the same across runs and across machines.
    """

    offsets: bytes
    """Packed ``u32``, length ``n_nodes + 1``."""

    targets: bytes
    """Packed ``u32`` node indices."""

    edge_kind: bytes
    """Packed ``u8`` :class:`EdgeKind`."""

    dep_type: bytes
    """Packed ``u8`` :class:`DepType`."""

    constraint: bytes
    """Packed ``u32`` :data:`StrId` of the unsatisfied version constraint.

    The parenthesised tail of a ``Broken`` line, e.g. ``"(= 2.86.3-4)"`` or
    ``"(< 3.13)"``. :data:`ABSENT` for unversioned relationships. The *operator*
    survives version normalisation during deduplication while the version does
    not, because ``(< 46.0.1~)`` and ``(< 46.0.7~)`` are the same bug.
    """

    decision: bytes
    """Packed ``u8`` :class:`Decision`, meaningful on DECISION edges."""

    score_src: bytes
    """Packed ``i32``: apt's ``Considering`` score for the edge source."""

    score_dst: bytes
    """Packed ``i32``: apt's ``Considering`` score for the edge target.

    The pair explains *why* apt chose a remedy, and the margin between them
    predicts fragility. For the lintian holdback the margin was one point
    (``libfile-libmagic-perl 0`` against ``lintian -1``), which is why that bug
    was environment-dependent and could not be reproduced on a clean install.
    """

    score_set: bytes = b""
    """Packed ``u8``: whether scores were actually recorded for each edge.

    An explicit presence flag rather than treating ``(0, 0)`` as absent,
    because apt emits genuine zero pairs -- ``Considering libavcodec62 0 as a
    solution to calibre-bin 0`` occurs in a real log. A zero margin is the
    *most* fragile outcome apt can report, so conflating it with "no data"
    silently suppresses the strongest fragility signal there is.

    Empty for graphs written before this field existed; readers treat a short
    array as "unknown" and fall back to the old heuristic.
    """

    depth: bytes
    """Packed ``u8`` recursion depth at which the line was emitted.

    Indentation in ``apt.log`` encodes the resolver's recursion, reaching 28
    spaces (about fourteen levels) in real logs. Depth distinguishes a
    top-level conflict from a consequence discovered deep inside dependency
    expansion.
    """

    def __len__(self) -> int:
        return len(self.targets) // 4

    @property
    def offset_list(self) -> tuple[int, ...]:
        return unpack_u32(self.offsets)

    @property
    def target_list(self) -> tuple[int, ...]:
        return unpack_u32(self.targets)

    @property
    def kinds(self) -> tuple[int, ...]:
        return unpack_u8(self.edge_kind)

    @property
    def dep_types(self) -> tuple[int, ...]:
        return unpack_u8(self.dep_type)

    @property
    def constraints(self) -> tuple[StrId, ...]:
        return unpack_u32(self.constraint)

    @property
    def decisions(self) -> tuple[int, ...]:
        return unpack_u8(self.decision)

    @property
    def scores_src(self) -> tuple[int, ...]:
        return unpack_i32(self.score_src)

    @property
    def scores_dst(self) -> tuple[int, ...]:
        return unpack_i32(self.score_dst)

    @property
    def score_flags(self) -> tuple[int, ...]:
        """Per-edge score-presence flags, padded when the field is absent."""
        flags = unpack_u8(self.score_set)
        missing = len(self) - len(flags)
        return flags + (0,) * missing if missing > 0 else flags

    @property
    def depths(self) -> tuple[int, ...]:
        return unpack_u8(self.depth)


class ConflictGraph(Frozen):
    """One resolver section of ``apt.log``, as a graph.

    A section is one bracketed resolver run: a ``Log time:`` header, then
    optionally ``Starting pkgProblemResolver with broken count: N``, the
    ``Broken``/``Considering``/``Fixing`` traffic, and ``Done``. The upgrader
    logs each resolve twice (``Starting`` and ``Starting 2``) and runs the whole
    calculation twice, so identical sections are collapsed upstream in
    :mod:`uru_doctor.apt.sections` -- without that, a single real problem is
    counted four times.
    """

    nodes: GraphNodes
    edges: GraphEdges

    broken_count: int | None = None
    """apt's own ``broken count: N``, when the section reported one.

    A free top-level health metric: zero means the resolve was clean.
    """

    resolve_by_keep: bool = False
    """Whether ``Entering ResolveByKeep`` appeared.

    apt falling back to keep-based resolution means it gave up on a clean
    answer, which correlates with partial upgrades. Note this line also occurs
    with no preceding ``Starting``, so its absence proves nothing on its own.
    """

    completed: bool = False
    """Whether the section reached ``Done``.

    False means the log was truncated mid-resolve, which is evidence about the
    capture, not about the upgrade.
    """

    section_index: int = 0
    """Position of this section in the file, for provenance."""

    first_line: int = 0
    """1-based line number where the section starts, for provenance."""


# ---------------------------------------------------------------------------
# Events, phases, packages
# ---------------------------------------------------------------------------


class Event(Frozen):
    """One interesting log line, reduced to a template id and its arguments.

    Volatile tokens -- versions, paths, hex addresses, pids, byte counts -- are
    masked out when the template is mined, so that the thousand distinct
    renderings of "dpkg: error processing archive <path>" collapse to one
    template id whose document frequency is tracked globally. That frequency is
    what makes similarity scoring meaningful: ``Setting up X`` occurs in every
    report and weighs nothing, while a rare unpack-conflict template dominates.
    """

    template_id: TemplateId
    args: tuple[StrId, ...] = ()
    """The masked-out tokens, interned, in order of appearance."""

    level: Level = Level.UNKNOWN
    source: LogSource = LogSource.MAIN
    t_ms: int = 0
    """Milliseconds since the run started. ``u32`` so that "always dies 40s
    into COMMIT" is a cheap indexed query rather than datetime arithmetic."""

    line_no: int = 0
    phase: Phase = Phase.UNKNOWN


class PhaseSpan(Frozen):
    """One phase of the upgrade and how it went."""

    phase: Phase
    t_start_ms: int = 0
    t_end_ms: int = 0
    outcome: PhaseOutcome = PhaseOutcome.UNKNOWN

    @property
    def duration_ms(self) -> int:
        return max(0, self.t_end_ms - self.t_start_ms)


class PackageDelta(Frozen):
    """The planned package changes, as packed sorted :data:`PkgId` arrays.

    Sorted so that set operations between two reports are a linear merge, and
    packed because a full desktop upgrade touches a couple of thousand packages
    and the text form of that is tens of kilobytes per report.
    """

    upgraded: bytes = b""
    installed: bytes = b""
    removed: bytes = b""
    held_back: bytes = b""
    broken: bytes = b""
    failed: bytes = b""
    """Packages dpkg actually failed on, from ``apt-term.log``."""

    unauthenticated: bytes = b""
    obsolete: bytes = b""

    def ids(self, field: str) -> tuple[PkgId, ...]:
        """Unpack one field by name."""
        return unpack_u32(getattr(self, field))


class PackageCounts(Frozen):
    """Cardinalities of :class:`PackageDelta`, stored separately.

    Duplicated on purpose: the overwhelmingly common query is "how many
    packages were held back", and answering it should not require unpacking a
    two-thousand-element array.
    """

    upgraded: int = 0
    installed: int = 0
    removed: int = 0
    held_back: int = 0
    broken: int = 0
    failed: int = 0
    unauthenticated: int = 0
    obsolete: int = 0


class OriginRef(Frozen):
    """A repository origin seen in the upgrade, and whether it is Ubuntu's.

    Third-party origins are cross-checked against ``main.log``'s
    ``Foreign (before rewriting sources)`` list, which is the upgrader's own
    verdict on which installed packages come from outside Ubuntu.
    """

    origin: StrId
    is_third_party: bool = False
    pkg_count: int = 0
    label: StrId = ABSENT
    """A human-facing name such as ``"ppa:linux-surface/release"`` when known."""


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------


class Finding(Frozen):
    """One diagnosed root cause, with the evidence that produced it.

    Findings are the only thing the report, the title generator and the
    deduplicator read. They must therefore carry enough provenance to be
    checked by hand: ``evidence`` indexes into
    :attr:`UpgradeRun.events`, and ``root_pkgs`` / ``victim_pkgs`` are interned
    ids that render back to real package names.
    """

    cause: Cause
    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MODERATE
    rule: str = ""
    """Name of the rule that fired, so ``uru-doctor rules`` can explain it."""

    summary: str = ""
    """One line of plain English, already rendered. No markup."""

    root_pkgs: tuple[PkgId, ...] = ()
    """The packages blamed. Usually one; a cascade has one root by definition."""

    victim_pkgs: tuple[PkgId, ...] = ()
    """Packages broken as a consequence, in cascade order."""

    cascade_size: int = 0
    """Number of packages reachable from the root in the blame graph.

    The headline number for ranking: in bug 2169028, eighty-six ``Broken``
    lines reduced to eleven roots, one of which owned forty of them.
    """

    evidence: tuple[int, ...] = ()
    """Indices into :attr:`UpgradeRun.events`."""

    graph_index: int | None = None
    """Which :attr:`UpgradeRun.graphs` entry this came from, if any."""

    remedy: Decision = Decision.UNKNOWN
    """What apt did about it."""

    score_margin: int | None = None
    """Absolute difference of apt's ``Considering`` scores for the remedy."""

    fragile: bool = False
    """True when :attr:`score_margin` is small enough that the outcome depends
    on incidental system state.

    Such bugs are irreproducible on clean installs and attract many
    inconsistent duplicates, so the report flags them explicitly rather than
    leaving a triager to rediscover it.
    """

    detail: dict[str, str] = Field(default_factory=dict)
    """Rule-specific extras for the report, e.g. the unsatisfied constraint."""

    phase: Phase = Phase.UNKNOWN


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------


class Signature(Frozen):
    """What deduplication compares.

    Three independent keys, tried cheapest first, so that the great majority of
    duplicates are found by hash lookup and only a genuinely ambiguous minority
    reaches scoring -- let alone a language model.
    """

    apport_dupe: bytes | None = None
    """Hash of apport's own ``DuplicateSignature``.

    Present only for ``ProblemType: Crash``. Authoritative: apport computed it
    from the traceback with the temporary directory scrubbed.
    """

    root_graph: bytes | None = None
    """Hash of the canonical root-cause subgraph.

    Roots, their immediate victims, the relationship types and the constraint
    *operators*, with versions normalised to upstream. This is what makes the
    thirteen duplicates of bug 2150245 collapse without any text comparison:
    they share a root, regardless of what their titles say.
    """

    cause_tuple: bytes | None = None
    """Hash of ``(cause, normalised root names, terminal phase)``.

    A coarser key than :attr:`root_graph`, used for bucketing before pairwise
    scoring and as the fallback for causes that have no graph at all -- disk
    space, dpkg failures, upgrader crashes.
    """

    evidence_set: bytes = b""
    """Packed sorted ``u32`` template ids.

    The input to IDF-weighted Jaccard similarity, used for non-resolver causes
    and as a tiebreak. Sorted so the comparison is a linear merge.
    """


# ---------------------------------------------------------------------------
# The record
# ---------------------------------------------------------------------------


class UpgradeRun(Frozen):
    """One attempted upgrade, fully reduced.

    A bug report may contain several of these: ``/var/log/dist-upgrade`` holds
    the most recent attempt at the top level and archives earlier ones into
    ``YYYYMMDD-HHMM/`` subdirectories. All are kept, because repeated attempts
    are themselves triage signal, but exactly one is marked
    :attr:`is_primary` and that is the one diagnosed.
    """

    # -- identity -----------------------------------------------------------
    bug_id: int | None = None
    attempt: int = 0
    """0 for the top-level logs, 1.. for archived ``YYYYMMDD-HHMM`` directories."""

    is_primary: bool = True
    source_dir: str = ""

    # -- environment --------------------------------------------------------
    from_series: str = ""
    """Source series codename, e.g. ``"noble"``. Resolved against
    ``/usr/share/distro-info/ubuntu.csv`` rather than hardcoded."""

    to_series: str = ""
    """Target series codename, e.g. ``"resolute"``."""

    arch: Arch = Arch.UNKNOWN
    problem_type: ProblemType = ProblemType.UNKNOWN

    apt_version: str = ""
    """Selects the ``apt.log`` grammar variant.

    Load-bearing, not decorative. An LTS-to-LTS upgrade runs the *source*
    release's apt, so a 24.04 to 26.04 bug carries noble's apt 2.8.x output,
    whose debug vocabulary differs from apt 3.x in ways that break naive
    parsing: ``@un H`` has no mode group, ``@un pumN Ib`` has a four-character
    one.
    """

    upgrader_version: str = ""
    python_version: str = ""
    kernel: str = ""
    locale: str = ""
    frontend: Frontend = Frontend.UNKNOWN
    server_mode: bool = False

    # -- timeline -----------------------------------------------------------
    started_at: datetime | None = None
    phases: tuple[PhaseSpan, ...] = ()
    terminal_phase: Phase = Phase.UNKNOWN

    evidence_complete: bool = True
    """False when a log ends mid-run.

    Bug 2169028's ``main.log`` stops at ``running Quirks.PreDistUpgradeCache``
    with no error and no abort, and its ``apt.log`` ends at ``Done``. The honest
    output there is "no failure recorded, last phase PRE_DIST_UPGRADE", with the
    resolver roots offered as findings that have no confirmed terminal cause.
    Inventing a cause from a truncated log would be the worst thing this tool
    could do.
    """

    logs_present: tuple[LogSource, ...] = ()
    """Which logs were found.

    Absence carries information. apport attaches ``apt-term.log`` and
    ``history.log`` only when non-empty, so when neither is present dpkg never
    ran and the failure is necessarily before :attr:`Phase.COMMIT`.
    """

    # -- evidence -----------------------------------------------------------
    events: tuple[Event, ...] = ()
    pkgs: PackageDelta = PackageDelta()
    counts: PackageCounts = PackageCounts()
    origins: tuple[OriginRef, ...] = ()
    graphs: tuple[ConflictGraph, ...] = ()

    apt_error_entries: tuple[StrId, ...] = ()
    """The ``E:`` entries split out of ``ERROR Dist-upgrade failed: '...'``.

    apt's error stack arrives comma-joined and mixes warnings with errors. The
    ``W:`` entries are dropped here on purpose: in bug 2150319 a Chrome i386
    warning sat next to the real resolver error and sent the reporter and three
    commenters chasing Google Chrome for weeks. Cause is never attributed to a
    warning.
    """

    apt_warning_entries: tuple[StrId, ...] = ()
    """The ``W:`` entries, kept for display but never used to attribute cause."""

    # -- derived ------------------------------------------------------------
    findings: tuple[Finding, ...] = ()
    signature: Signature = Signature()

    # -- bug metadata -------------------------------------------------------
    current_title: str = ""
    tags: tuple[str, ...] = ()
    reported_at: datetime | None = None
    duplicate_of: int | None = None
    """Launchpad's own verdict, when known. Free ground truth for tests."""

    @property
    def key(self) -> tuple[int | None, int]:
        """Primary key: a bug plus an attempt index."""
        return (self.bug_id, self.attempt)

    @property
    def top_finding(self) -> Finding | None:
        """The highest-ranked finding, which drives the title."""
        return self.findings[0] if self.findings else None

    @property
    def reached_dpkg(self) -> bool:
        """Whether any package was unpacked."""
        return LogSource.APT_TERM in self.logs_present or LogSource.HISTORY in self.logs_present

    @property
    def release_pair(self) -> str:
        """``"noble→resolute"``, the prefix used by every generated title."""
        if self.from_series and self.to_series:
            return f"{self.from_series}\u2192{self.to_series}"
        return "unknown\u2192unknown"

    def with_findings(self, findings: tuple[Finding, ...], signature: Signature) -> Self:
        """Return a copy carrying diagnosis results.

        Diagnosis is a pure function of an ingested record, so it produces a new
        record rather than mutating one. That is what lets a rule change be
        re-run across the whole corpus in seconds without touching raw logs.
        """
        return self.model_copy(update={"findings": findings, "signature": signature})
