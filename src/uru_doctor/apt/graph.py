"""Building the conflict graph, and canonicalising it for deduplication.

The output is compressed sparse row: a sorted vertex array plus an offsets
array indexing into a flat edge array. Three reasons, in order of how much they
matter.

**Canonical form comes free.** Vertices are sorted by interned package id and
edges are renumbered to vertex *indices*, so two structurally identical graphs
serialise to identical bytes. A digest over that is the duplicate fingerprint --
no graph-isomorphism heuristic, no separate canonicalisation pass. Because edge
targets are indices rather than global ids, the encoding is also independent of
the interning tables, so the same conflict hashes the same across stores and
machines.

**The graph is walked far more often than it is inspected.** Root finding
traverses it once per section; deduplication traverses it once per candidate
pair. A few hundred vertices in six contiguous blobs beats a few hundred small
objects, and it goes into SQLite without a serialisation step.

**Blame has a direction, and it is not obvious.** ``Broken A Depends on B``
means B is the cause and A the victim, so the edge runs B to A. But
``Upgrading A due to B`` means B forced A, which is the same direction, while
``Installing B as Depends of A`` means A pulled B in, which is the opposite.
Getting these backwards inverts every diagnosis, so each is derived from the
verb explicitly in :data:`_EDGE_RULES` rather than inferred from argument
position.

One subtlety worth stating: on a ``Broken`` line the state expression belongs to
the **object**, not the subject. ``Broken lintian Depends on
libfile-libmagic-perl < none | 1.23-2build2 @un uH >`` is describing
libfile-libmagic-perl's state, and reading it as lintian's would make the
holdback detector look at the wrong package entirely.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import blake2b
from typing import TYPE_CHECKING

from uru_doctor.apt.grammar import Verb
from uru_doctor.apt.state import InstallStatus, PackageState
from uru_doctor.models import (
    ABSENT,
    BLAME_EDGES,
    ConflictGraph,
    Decision,
    DepType,
    EdgeKind,
    GraphEdges,
    GraphNodes,
    Mode,
    NodeBits,
    PkgId,
    VerSelect,
    pack_i32,
    pack_u8,
    pack_u32,
)

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence

    from uru_doctor.apt.lexer import Token
    from uru_doctor.apt.sections import Section
    from uru_doctor.intern import Interner


# ---------------------------------------------------------------------------
# Edge derivation rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EdgeRule:
    """How one verb becomes an edge.

    ``cause_is_object`` resolves the direction question once, per verb, in a
    place where it can be read and checked against the log, instead of being
    re-derived at each call site.
    """

    kind: EdgeKind
    cause_is_object: bool
    """True when the verb's ``object`` is the cause and ``subject`` the affected
    party, as in ``Broken <subject> Depends on <object>``. False for the
    verbs that name the cause first, as in ``Removing <subject> rather than
    change <object>``."""

    decision: Decision = Decision.UNKNOWN
    state_belongs_to_object: bool = False
    """Whether the line's state expression describes the object rather than the
    subject. True for the ``Broken`` family, where the state is the dependency's
    and not the dependent's."""


#: Verb to edge derivation. Verbs absent from this table contribute node
#: annotations only -- ``MarkInstall``, ``Re-Instated``, ``Investigating`` and
#: friends tell us about a package's state without relating two packages.
_EDGE_RULES: dict[Verb, EdgeRule] = {
    # The blame record. State is the dependency's.
    Verb.BROKEN: EdgeRule(EdgeKind.BREAKS, True, state_belongs_to_object=True),
    Verb.CANT_BE_SATISFIED: EdgeRule(EdgeKind.UNSATISFIABLE, True, state_belongs_to_object=True),
    Verb.PACKAGE_DEP: EdgeRule(EdgeKind.BREAKS, True, state_belongs_to_object=True),
    # Remedies apt chose. Direction is "the package apt refused to change" to
    # "the package that paid for it".
    Verb.HOLDING_BACK: EdgeRule(EdgeKind.DECISION, True, Decision.HOLD_BACK_RATHER_THAN_CHANGE),
    Verb.REMOVING_RATHER: EdgeRule(EdgeKind.DECISION, False, Decision.REMOVE_RATHER_THAN_CHANGE),
    Verb.FIXING_VIA_REMOVE: EdgeRule(EdgeKind.DECISION, False, Decision.FIX_VIA_REMOVE),
    Verb.FIXING_VIA_KEEP: EdgeRule(EdgeKind.DECISION, False, Decision.FIX_VIA_KEEP),
    Verb.DELAYED_REMOVING: EdgeRule(EdgeKind.DELAYED_REMOVE, False),
    Verb.TRY_INSTALLING_BEFORE: EdgeRule(EdgeKind.DECISION, False, Decision.FIX_VIA_KEEP),
    # Upgrade propagation: B forced A.
    Verb.UPGRADING_DUE_TO: EdgeRule(EdgeKind.UPGRADE_PROP, True),
    Verb.UPGRADING_DUE_TO_FIELD: EdgeRule(EdgeKind.UPGRADE_PROP, True),
    Verb.UPGRADING_DUE_TO_DEP: EdgeRule(EdgeKind.UPGRADE_PROP, True),
    # Dependency recursion: A pulled B in. Note the direction is the reverse of
    # the blame verbs -- the subject is the thing being installed.
    Verb.INSTALLING_AS: EdgeRule(EdgeKind.AUTOINSTALL, True),
}

#: Verbs whose state expression annotates the subject's node.
_NODE_STATE_VERBS: frozenset[Verb] = frozenset(
    {
        Verb.INVESTIGATING,
        Verb.DEPS_NOT_SATISFIED,
        Verb.MARK_INSTALL,
        Verb.MARK_DELETE,
        Verb.MARK_KEEP,
        Verb.MARK_PURGE,
        Verb.IGNORE_MARK_KEEP_PROTECTED,
    }
)


# ---------------------------------------------------------------------------
# Mutable build-time structures
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Node:
    """A vertex under construction."""

    pkg_id: PkgId
    cur_ver: str | None = None
    cand_ver: str | None = None
    selection: VerSelect = VerSelect.NONE
    mode: Mode = Mode.UNKNOWN
    status: InstallStatus = InstallStatus.UNKNOWN
    bits: int = 0
    raw_flags: str = ""
    authoritative: bool = False
    """Whether the recorded state came from a blame line.

    apt revises its decisions as it resolves, so one package legitimately
    appears with several different modes in one section -- ``libpeas-1.0-1``
    shows up both as ``@un uH`` and as ``@un umN`` in bug 2169028. The mode that
    explains a conflict is the one apt reported *on the line asserting the
    conflict*, so those sightings take precedence over ``MarkInstall`` and
    ``Investigating`` traffic. Without this distinction a held package whose
    mode was later revised reads as an ordinary new install, and the holdback
    diagnosis -- the single most common root cause on this upgrade path --
    silently stops firing.
    """

    def absorb(self, state: PackageState, *, authoritative: bool = False) -> None:
        """Merge another sighting of this package's state.

        Broken bits are unioned rather than overwritten: a package observed
        broken once is broken, whatever a later line says. Everything else
        follows precedence.

        Among authoritative sightings there can still be disagreement, because
        apt revises a decision and then asserts a new conflict against the
        revised state. ``libwacom9`` appears in one real log as both
        ``@un umH`` with a declined candidate and ``@un pumN`` as a fresh
        install. The informative one is always the declined candidate: a
        package apt refused to take is why something broke, whereas one it
        agreed to install is not. So a declined candidate outranks a selected
        one even when both sightings are authoritative.
        """
        self.bits |= state.bits

        declined = state.selection is VerSelect.AVAILABLE_NOT_SELECTED
        overwrite = authoritative and (
            not self.authoritative
            or (declined and self.selection is not VerSelect.AVAILABLE_NOT_SELECTED)
        )
        if authoritative:
            self.authoritative = True

        if state.mode is not Mode.UNKNOWN and (overwrite or self.mode is Mode.UNKNOWN):
            self.mode = state.mode
        if state.status is not InstallStatus.UNKNOWN and (
            overwrite or self.status is InstallStatus.UNKNOWN
        ):
            self.status = state.status
        if state.raw and (overwrite or not self.raw_flags):
            self.raw_flags = state.raw

        # A sighting carrying a candidate beats one that does not, because the
        # candidate is what distinguishes "nothing available" from "available
        # and declined" -- the whole holdback diagnosis turns on it.
        incoming_rank = (state.cand_version is not None, state.cur_version is not None)
        current_rank = (self.cand_ver is not None, self.cur_ver is not None)
        if overwrite or incoming_rank > current_rank:
            self.cur_ver = state.cur_version
            self.cand_ver = state.cand_version
            self.selection = state.selection
        elif self.selection is VerSelect.NONE and state.selection is not VerSelect.NONE:
            self.selection = state.selection


@dataclass(slots=True)
class _Edge:
    """An edge under construction, holding package ids until renumbering."""

    src: PkgId
    dst: PkgId
    kind: EdgeKind
    dep: DepType = DepType.UNKNOWN
    constraint: str = ""
    decision: Decision = Decision.UNKNOWN
    score_src: int = 0
    score_dst: int = 0
    has_scores: bool = False
    depth: int = 0

    def key(self) -> tuple[PkgId, PkgId, int, int, str]:
        """Identity for collapsing repeats.

        The same ``Broken`` line is emitted once per resolver pass, so an
        unkeyed builder produces every edge twice even after section collapsing.
        """
        return (self.src, self.dst, int(self.kind), int(self.dep), self.constraint)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class GraphBuilder:
    """Accumulates tokens into one :class:`ConflictGraph`.

    Used once per resolver section. Package references are interned on the way
    in, so the builder holds no strings beyond the version and constraint text
    it is about to intern as well.
    """

    def __init__(self, interner: Interner, *, keep_autoinstall: bool = True) -> None:
        self._interner = interner
        self._keep_autoinstall = keep_autoinstall
        self._nodes: dict[PkgId, _Node] = {}
        self._edges: dict[tuple[PkgId, PkgId, int, int, str], _Edge] = {}
        self._pending_scores: tuple[PkgId, int, PkgId, int] | None = None

    # -- accumulation -------------------------------------------------------

    def _node(self, pkg_id: PkgId) -> _Node:
        node = self._nodes.get(pkg_id)
        if node is None:
            node = _Node(pkg_id=pkg_id)
            self._nodes[pkg_id] = node
        return node

    def _add_edge(self, edge: _Edge) -> None:
        if edge.src == ABSENT or edge.dst == ABSENT or edge.src == edge.dst:
            # Self-edges arise from ``Package A A Depends on B`` style lines and
            # carry no information; a missing endpoint means the line named a
            # package the interner rejected.
            return
        existing = self._edges.get(edge.key())
        if existing is None:
            self._edges[edge.key()] = edge
            return
        # Keep the shallowest sighting: a conflict reported at depth 0 is a
        # top-level problem, the same conflict rediscovered at depth 12 is a
        # consequence of walking into a subtree.
        if edge.depth < existing.depth:
            existing.depth = edge.depth
        if not existing.has_scores and edge.has_scores:
            existing.score_src = edge.score_src
            existing.score_dst = edge.score_dst
            existing.has_scores = True

    def feed(self, token: Token) -> None:
        """Absorb one token."""
        # ``Considering B <score> as a solution to A <score>`` precedes the
        # decision it explains, so the scores are buffered and attached to the
        # next decision edge rather than becoming an edge of their own.
        if token.verb is Verb.CONSIDERING:
            subject = self._interner.package(token.subject)
            obj = self._interner.package(token.object)
            self._pending_scores = (
                subject,
                token.score_src or 0,
                obj,
                token.score_dst or 0,
            )
            self._node(subject)
            self._node(obj)
            return

        if token.verb is Verb.REINSTATED:
            pkg = self._interner.package(token.subject)
            self._node(pkg).bits |= 1 << NodeBits.REINSTATED
            return

        if token.verb in (Verb.ADDED_TO_REMOVE_LIST, Verb.REMOVING_NOT_POSSIBLE):
            pkg = self._interner.package(token.subject)
            node = self._node(pkg)
            if node.mode is Mode.UNKNOWN:
                node.mode = Mode.REMOVE
            return

        # Node-only verbs: record the state against the subject.
        if token.verb in _NODE_STATE_VERBS:
            pkg = self._interner.package(token.subject)
            node = self._node(pkg)
            if token.state is not None:
                node.absorb(token.state)
            if token.from_user:
                node.bits |= 1 << NodeBits.FROM_USER
            return

        rule = _EDGE_RULES.get(token.verb)
        if rule is None:
            return
        if rule.kind is EdgeKind.AUTOINSTALL and not self._keep_autoinstall:
            return

        subject = self._interner.package(token.subject)
        obj = self._interner.package(token.object)
        if subject == ABSENT or obj == ABSENT:
            return

        subject_node = self._node(subject)
        object_node = self._node(obj)

        # Attribute the state to whichever package the verb describes. States
        # seen on a blame line are authoritative: they are apt's account of why
        # the conflict exists, and they outrank later revisions.
        blame = rule.kind in (EdgeKind.BREAKS, EdgeKind.UNSATISFIABLE)
        if token.state is not None:
            target = object_node if rule.state_belongs_to_object else subject_node
            target.absorb(token.state, authoritative=blame)

        # ``Upgrading: A due to B Depends on C`` carries a second state, which
        # belongs to C.
        if token.third and len(token.states) > 1:
            third = self._interner.package(token.third)
            if third != ABSENT:
                self._node(third).absorb(token.states[1])

        cause, affected = (obj, subject) if rule.cause_is_object else (subject, obj)

        score_src = score_dst = 0
        has_scores = False
        if rule.kind is EdgeKind.DECISION and self._pending_scores is not None:
            pending_a, score_a, pending_b, score_b = self._pending_scores
            # The Considering line names the same two packages as the decision,
            # in either order; match them up rather than assuming.
            if {pending_a, pending_b} == {cause, affected}:
                score_src = score_a if pending_a == cause else score_b
                score_dst = score_b if pending_a == cause else score_a
                has_scores = True
            self._pending_scores = None

        self._add_edge(
            _Edge(
                src=cause,
                dst=affected,
                kind=rule.kind,
                dep=token.dep,
                constraint=token.constraint,
                decision=rule.decision,
                score_src=score_src,
                score_dst=score_dst,
                has_scores=has_scores,
                depth=token.depth,
            )
        )

        # A subject that is broken-after-install is worth recording even when
        # the state was attributed to the object.
        if blame:
            subject_node.bits |= 1 << NodeBits.INST_BROKEN

    def feed_all(self, tokens: Iterable[Token]) -> None:
        for token in tokens:
            self.feed(token)

    # -- finishing ----------------------------------------------------------

    def build(
        self,
        *,
        broken_count: int | None = None,
        resolve_by_keep: bool = False,
        completed: bool = False,
        section_index: int = 0,
        first_line: int = 0,
        third_party: Sequence[PkgId] = (),
    ) -> ConflictGraph:
        """Freeze into CSR form.

        Vertices are sorted by interned id, which is what makes the result
        canonical, and edges are renumbered to vertex indices and sorted so the
        offsets array is monotonic.
        """
        third_party_ids = set(third_party)
        order = sorted(self._nodes)
        index_of = {pkg_id: position for position, pkg_id in enumerate(order)}

        cur_ver: list[int] = []
        cand_ver: list[int] = []
        selected: list[int] = []
        modes: list[int] = []
        bits: list[int] = []
        raw_flags: list[int] = []

        for pkg_id in order:
            node = self._nodes[pkg_id]
            node_bits = node.bits
            if pkg_id in third_party_ids:
                node_bits |= 1 << NodeBits.THIRD_PARTY
            cur_ver.append(self._interner.string(node.cur_ver))
            cand_ver.append(self._interner.string(node.cand_ver))
            selected.append(int(node.selection))
            modes.append(int(node.mode))
            bits.append(node_bits & 0xFF)
            raw_flags.append(self._interner.string(node.raw_flags))

        # Group edges by source index so the CSR offsets can be filled in one
        # pass. Sorting by (src, dst, kind) also makes the packed bytes a
        # deterministic function of the graph's content.
        renumbered = sorted(
            (
                (index_of[edge.src], index_of[edge.dst], edge)
                for edge in self._edges.values()
                if edge.src in index_of and edge.dst in index_of
            ),
            key=lambda item: (item[0], item[1], int(item[2].kind), int(item[2].dep)),
        )

        offsets: list[int] = [0] * (len(order) + 1)
        targets: list[int] = []
        kinds: list[int] = []
        deps: list[int] = []
        constraints: list[int] = []
        decisions: list[int] = []
        scores_src: list[int] = []
        scores_dst: list[int] = []
        score_flags: list[int] = []
        depths: list[int] = []

        for src_index, dst_index, edge in renumbered:
            offsets[src_index + 1] += 1
            targets.append(dst_index)
            kinds.append(int(edge.kind))
            deps.append(int(edge.dep))
            constraints.append(self._interner.string(edge.constraint))
            decisions.append(int(edge.decision))
            scores_src.append(edge.score_src)
            scores_dst.append(edge.score_dst)
            score_flags.append(int(edge.has_scores))
            depths.append(min(edge.depth, 255))

        for position in range(1, len(offsets)):
            offsets[position] += offsets[position - 1]

        return ConflictGraph(
            nodes=GraphNodes(
                pkg_ids=pack_u32(order),
                cur_ver=pack_u32(cur_ver),
                cand_ver=pack_u32(cand_ver),
                selected=pack_u8(selected),
                mode=pack_u8(modes),
                bits=pack_u8(bits),
                raw_flags=pack_u32(raw_flags),
            ),
            edges=GraphEdges(
                offsets=pack_u32(offsets),
                targets=pack_u32(targets),
                edge_kind=pack_u8(kinds),
                dep_type=pack_u8(deps),
                constraint=pack_u32(constraints),
                decision=pack_u8(decisions),
                score_src=pack_i32(scores_src),
                score_dst=pack_i32(scores_dst),
                score_set=pack_u8(score_flags),
                depth=pack_u8(depths),
            ),
            broken_count=broken_count,
            resolve_by_keep=resolve_by_keep,
            completed=completed,
            section_index=section_index,
            first_line=first_line,
        )


def build_graph(
    section: Section,
    interner: Interner,
    *,
    keep_autoinstall: bool = True,
    third_party: Sequence[PkgId] = (),
) -> ConflictGraph:
    """Build the graph for one resolver section."""
    builder = GraphBuilder(interner, keep_autoinstall=keep_autoinstall)
    builder.feed_all(section.tokens)
    return builder.build(
        broken_count=section.broken_count,
        resolve_by_keep=section.resolve_by_keep,
        completed=section.completed,
        section_index=section.index,
        first_line=section.first_line,
        third_party=third_party,
    )


# ---------------------------------------------------------------------------
# Traversal helpers
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EdgeView:
    """One decoded edge, for code that reads rather than packs."""

    src: int
    dst: int
    kind: EdgeKind
    dep: DepType
    constraint: int
    decision: Decision
    score_src: int
    score_dst: int
    has_scores: bool
    depth: int

    @property
    def is_blame(self) -> bool:
        return int(self.kind) in BLAME_EDGES

    @property
    def score_margin(self) -> int | None:
        """How narrowly apt preferred its remedy, or None if unrecorded.

        A small margin means the outcome turned on incidental system state,
        which is why such bugs resist reproduction and arrive as a stream of
        inconsistent duplicates. Zero is a legitimate and maximally fragile
        value, so presence is tracked explicitly rather than inferred.
        """
        if not self.has_scores:
            return None
        return abs(self.score_src - self.score_dst)


def iter_edges(graph: ConflictGraph) -> list[EdgeView]:
    """Decode every edge once.

    Returns a list rather than a generator: callers walk it several times
    (forward adjacency, reverse adjacency, blame filtering) and decoding the
    packed arrays repeatedly would be the only expensive thing here.
    """
    offsets = graph.edges.offset_list
    targets = graph.edges.target_list
    kinds = graph.edges.kinds
    deps = graph.edges.dep_types
    constraints = graph.edges.constraints
    decisions = graph.edges.decisions
    src_scores = graph.edges.scores_src
    dst_scores = graph.edges.scores_dst
    score_flags = graph.edges.score_flags
    depths = graph.edges.depths

    out: list[EdgeView] = []
    for src in range(len(graph.nodes)):
        for position in range(offsets[src], offsets[src + 1]):
            out.append(
                EdgeView(
                    src=src,
                    dst=targets[position],
                    kind=EdgeKind(kinds[position]),
                    dep=DepType(deps[position]),
                    constraint=constraints[position],
                    decision=Decision(decisions[position]),
                    score_src=src_scores[position],
                    score_dst=dst_scores[position],
                    has_scores=bool(score_flags[position]),
                    depth=depths[position],
                )
            )
    return out


def out_edges(graph: ConflictGraph, node: int) -> list[EdgeView]:
    """Edges leaving one vertex, by index."""
    return [edge for edge in iter_edges(graph) if edge.src == node]


# ---------------------------------------------------------------------------
# Canonicalisation
# ---------------------------------------------------------------------------


def canonical_digest(
    graph: ConflictGraph,
    interner: Interner,
    nodes: Sequence[int],
    *,
    granularity: str = "operator",
) -> bytes:
    """Digest the subgraph induced by ``nodes``, canonically.

    This is the duplicate fingerprint. Three things are deliberately *excluded*:

    - **Node indices and ordering.** Package names are emitted instead, sorted,
      so the digest does not depend on how many unrelated packages happened to
      be in the same transaction.
    - **Constraint versions**, to the degree ``granularity`` allows. The
      default drops them entirely and keeps only the operator, which is what
      makes ``python3-cryptography (< 46.0.1~)`` and ``(< 46.0.7~)`` the same
      bug -- both appear in real logs for one underlying problem.
    - **Scores, depths and line numbers.** Incidental to the structure.

    What is included: the participating package names, and for each edge the
    relationship type and the constraint *operator*. The operator matters --
    ``(= v)`` and ``(< v)`` are different failures -- while the version it is
    applied to usually does not.
    """
    wanted = set(nodes)
    ids = graph.nodes.ids
    digest = blake2b(digest_size=16)

    # Sort the *names*, not the node indices. Sorting indices emits the names
    # in whatever order the packages happened to be interned, which makes the
    # digest depend on the interner instance that produced it: the same two
    # logs hashed to equal digests when ingested through one interner and
    # unequal digests through two. Persisted signatures would then never match
    # across sessions, which is the whole point of storing them.
    names = sorted(interner.package_key(ids[node]) for node in wanted if node < len(ids))
    for name in names:
        digest.update(name.encode())
        digest.update(b"\x00")
    digest.update(b"\x02")

    rows: list[tuple[str, str, int, str]] = []
    for edge in iter_edges(graph):
        if edge.src not in wanted or edge.dst not in wanted:
            continue
        if not edge.is_blame:
            continue
        constraint = interner.text(edge.constraint)
        rows.append(
            (
                interner.package_key(ids[edge.src]),
                interner.package_key(ids[edge.dst]),
                int(edge.dep),
                normalise_constraint(constraint, granularity),
            )
        )

    for src_name, dst_name, dep, constraint in sorted(rows):
        digest.update(f"{src_name}>{dst_name}:{dep}:{constraint}".encode())
        digest.update(b"\x01")

    return digest.digest()


def normalise_constraint(constraint: str, granularity: str = "operator") -> str:
    """Reduce a constraint to the part that identifies the failure.

    The operator is always kept, because ``(= v)`` and ``(<< v)`` describe
    genuinely different failures. How much of the version survives is a policy
    choice, and the default is none of it:

    - ``exact`` -- the constraint verbatim.
    - ``upstream`` -- operator plus the upstream version, dropping epoch,
      Debian revision and any ``~`` pre-release suffix.
    - ``major`` -- operator plus the first version component.
    - ``operator`` -- the operator alone. The default.

    Operator-only is the default because the exact boundary version reflects
    when a log was captured rather than what went wrong. Real duplicates differ
    there routinely: one underlying ``python3-cryptography-vectors`` conflict
    appears in the corpus as both ``(< 46.0.1~)`` and ``(< 46.0.7~)``, and any
    setting that keeps version detail files those as two separate bugs.
    """
    text = constraint.strip()
    if not text:
        return ""
    if granularity == "exact":
        return text
    parts = text.split(None, 1)
    operator = parts[0]
    if len(parts) == 1 or granularity == "operator":
        return operator
    version = normalise_version(parts[1])
    if granularity == "major":
        version = version.split(".", 1)[0]
    return f"{operator} {version}"


def normalise_version(version: str) -> str:
    """Strip epoch, Debian revision and pre-release suffix.

    ``"4:26.2.5.2-0ubuntu0.26.04.1"`` becomes ``"26.2.5.2"``. The epoch goes
    because it is an archive bookkeeping artefact; the revision goes because a
    rebuild is not a different bug.
    """
    text = version.strip()
    if ":" in text:
        text = text.split(":", 1)[1]
    if "-" in text:
        text = text.rsplit("-", 1)[0]
    return text.split("~", 1)[0]
