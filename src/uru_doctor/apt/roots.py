"""Finding root causes in the conflict graph.

A failing LTS-to-LTS resolve reports a lot of broken packages and very few
actual problems. Bug 2169028's ``apt.log`` carries 86 distinct ``Broken`` lines;
they reduce to eleven roots, one of which owns 37 of them. A tool that reports
the 86 is useless. The job of this module is to report the eleven, ranked, each
with the cascade it caused and the mechanism that caused it.

**The algorithm.** Blame edges -- ``Broken`` and ``can't be satisfied!`` -- form
a directed graph from cause to victim. A root is a node with blame out-edges and
no blame in-edges: something it depends on is not at fault, so it is where the
trouble starts. A cascade is everything reachable from a root. Overlapping
cascades are expected and not merged; two independent roots can break the same
``-dev`` package and both facts are true.

**Cycles happen.** ``libxmlsec1-openssl1`` conflicts with
``libxmlsec1t64-openssl`` and vice versa, so neither has in-degree zero. When a
component has no entry point, the node with the greatest excess of victims over
blamers is promoted and the fact is recorded in the finding's detail, so a
reader can see that the choice was arbitrated rather than derived.

**Classification is ordered, specific first.** The eight mechanisms are not
disjoint in principle -- a third-party package can also be an exact-version pin
-- so the order in :func:`classify` decides which one is reported, and it is
chosen so the reported mechanism is the one a triager can act on. Third-party
origin wins over mechanism because the action is "close Invalid, unsupported
archive" regardless of how the breakage technically happened; the mechanism is
still recorded in the detail map.
"""

from __future__ import annotations

from collections import Counter, deque
from collections.abc import Collection
from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING

from uru_doctor.apt.graph import EdgeView, iter_edges
from uru_doctor.models import (
    BLAST_RADIUS_INDEPENDENT,
    Cause,
    Confidence,
    ConflictGraph,
    Decision,
    DepType,
    EdgeKind,
    Mode,
    NodeBits,
    PkgId,
    Severity,
    VerSelect,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

    from uru_doctor.intern import Interner

#: Name shapes that denote a virtual or ABI-marker package rather than a real
#: one. These never have a candidate because nothing builds them; they exist so
#: that a soname or ABI bump breaks dependents loudly. Seen in the wild as
#: ``libva-driver-abi-1.20`` and ``python3-numpy-abi9``.
_VIRTUAL_HINTS: tuple[str, ...] = ("-abi-", "-abi", "abi-")

def _is_foreign(graph: ConflictGraph, node: int, overlay: frozenset[int]) -> bool:
    """Whether ``node`` is a third-party package.

    Two sources, because they become available at different times. The graph's
    :attr:`~uru_doctor.models.NodeBits.THIRD_PARTY` bit is set when origin data
    was known at build time; the overlay carries ids resolved afterwards from
    ``main.log``'s ``Foreign`` list, which cannot be matched to apt's
    architecture-qualified names until the apt log has been interned.
    """
    return graph.nodes.has(node, NodeBits.THIRD_PARTY) or (
        bool(overlay) and graph.nodes.ids[node] in overlay
    )


#: Relationships where the log's direction carries no judgement about fault.
#: "A conflicts with B" is a statement about the pair, not about A.
_SYMMETRIC_DEPS: frozenset[DepType] = frozenset({DepType.CONFLICTS, DepType.BREAKS})

#: Constraint operators that pin a dependent to one specific version, or to
#: anything below a boundary. These are what an ordinary upgrade breaks: forty
#: ``python3-*`` packages pinning ``python3 (<< 3.13)`` all break the moment
#: python3 moves to 3.14.
_PIN_OPERATORS: frozenset[str] = frozenset({"=", "<", "<<", "<="})


@dataclass(frozen=True, slots=True)
class Root:
    """One diagnosed root cause within a single conflict graph."""

    node: int
    """Vertex index into the graph."""

    pkg_id: PkgId
    cause: Cause
    cascade: tuple[int, ...]
    """Victim vertex indices, in breadth-first order from the root.

    Breadth-first so that the immediate victims come first; a report that elides
    a long cascade then shows the packages closest to the cause rather than an
    arbitrary slice.
    """

    severity: Severity = Severity.MEDIUM
    confidence: Confidence = Confidence.MODERATE
    mode: Mode = Mode.UNKNOWN
    dep: DepType = DepType.UNKNOWN
    constraint: str = ""
    """Representative unsatisfied constraint, as written, e.g. ``"< 3.13"``."""

    remedy: Decision = Decision.UNKNOWN
    score_margin: int | None = None
    fragile: bool = False
    depth: int = 0
    """Shallowest recursion depth at which this root's blame was reported."""

    cycle_broken: bool = False
    """True when this root was promoted out of a cycle rather than derived."""

    detail: dict[str, str] = field(default_factory=dict)

    @property
    def cascade_size(self) -> int:
        return len(self.cascade)

    def rank(self) -> tuple[int, int, int, int]:
        """Sort key, descending. Severity first, then blast radius."""
        return (
            int(self.severity),
            self.cascade_size,
            1 if self.remedy is not Decision.UNKNOWN else 0,
            -self.depth,
        )


@dataclass(slots=True)
class RootReport:
    """Everything :mod:`uru_doctor.rules` needs from one graph."""

    roots: list[Root] = field(default_factory=list)
    blame_edges: int = 0
    victims: int = 0
    """Distinct nodes blamed by at least one edge -- the number a naive tool
    would report as "broken packages"."""

    cycles_broken: int = 0
    reoriented: int = 0
    """Symmetric edges turned around because one side was third-party."""

    @property
    def compression(self) -> str:
        """``"86 broken -> 11 roots"``, for the report header."""
        return f"{self.victims} broken \u2192 {len(self.roots)} roots"

    @property
    def top(self) -> Root | None:
        return self.roots[0] if self.roots else None


# ---------------------------------------------------------------------------
# Graph views
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class _Blame:
    """Adjacency over blame edges only, plus the decisions alongside them."""

    forward: dict[int, list[EdgeView]]
    reverse: dict[int, list[EdgeView]]
    decisions: dict[int, list[EdgeView]]
    """Decision edges indexed by the node they concern, either end.

    Indexed both ways because ``Holding Back A rather than change B`` is
    recorded cause-to-affected, but a report about B wants to know it was the
    reason A was held just as much as a report about A does.
    """

    all_edges: list[EdgeView]
    third_party: frozenset[int] = frozenset()
    """Third-party package ids resolved after the graph was built.

    Held here so that :func:`classify` sees the same origin evidence that
    reorientation used. Without it a reoriented root is correctly identified
    but then mislabelled -- LP#2150245's PPA conflict came out as
    ``transitional_breaks`` instead of ``third_party_pin``.
    """

    reoriented: int = 0
    """How many symmetric edges were turned around. See :meth:`of`."""

    @classmethod
    def of(cls, graph: ConflictGraph, third_party: frozenset[int] = frozenset()) -> _Blame:
        """Build blame adjacency, reorienting symmetric relationships.

        ``Depends`` is asymmetric: ``Broken A Depends on B`` genuinely means B
        is at fault. ``Conflicts`` and ``Breaks`` are not. "A conflicts with B"
        says the two cannot coexist and says nothing about which should give
        way -- apt writes it in whichever direction it happened to evaluate.

        That matters when one side comes from outside Ubuntu. In LP#2150245,
        ``libwacom9-surface`` from an unsupported PPA conflicts with the
        archive's ``libwacom9``, which stops ``libwacom9`` being installed and
        strands ``libinput10`` along with fifty other packages. apt logs it as
        ``Broken libwacom9-surface Conflicts on libwacom9``, so taken at face
        value the blame lands on the Ubuntu package and the PPA -- the only
        thing anyone can actually act on -- is recorded as a victim.

        So for a symmetric edge with exactly one third-party endpoint, blame is
        reoriented to flow from the third-party side. Asymmetric edges are
        never touched, and an edge with zero or two third-party endpoints has
        no basis for reorientation and is left alone.
        """
        forward: dict[int, list[EdgeView]] = {}
        reverse: dict[int, list[EdgeView]] = {}
        decisions: dict[int, list[EdgeView]] = {}
        edges = iter_edges(graph)
        reoriented = 0

        for edge in edges:
            if edge.is_blame:
                oriented = edge
                if edge.dep in _SYMMETRIC_DEPS:
                    src_foreign = _is_foreign(graph, edge.src, third_party)
                    dst_foreign = _is_foreign(graph, edge.dst, third_party)
                    if dst_foreign and not src_foreign:
                        oriented = replace(edge, src=edge.dst, dst=edge.src)
                        reoriented += 1
                forward.setdefault(oriented.src, []).append(oriented)
                reverse.setdefault(oriented.dst, []).append(oriented)
            elif edge.kind in (EdgeKind.DECISION, EdgeKind.DELAYED_REMOVE):
                decisions.setdefault(edge.src, []).append(edge)
                decisions.setdefault(edge.dst, []).append(edge)

        return cls(
            forward=forward,
            reverse=reverse,
            decisions=decisions,
            all_edges=edges,
            third_party=third_party,
            reoriented=reoriented,
        )

    def out_degree(self, node: int) -> int:
        return len(self.forward.get(node, ()))

    def in_degree(self, node: int) -> int:
        return len(self.reverse.get(node, ()))


def _reachable(blame: _Blame, start: int) -> tuple[int, ...]:
    """Breadth-first victims of ``start``, excluding itself.

    Iterative rather than recursive: real cascades run eleven or twelve deep,
    but a pathological log should not be able to exhaust the stack.
    """
    seen: set[int] = {start}
    order: list[int] = []
    queue: deque[int] = deque([start])
    while queue:
        node = queue.popleft()
        for edge in blame.forward.get(node, ()):
            if edge.dst in seen:
                continue
            seen.add(edge.dst)
            order.append(edge.dst)
            queue.append(edge.dst)
    return tuple(order)


def _find_roots(blame: _Blame) -> tuple[list[int], int]:
    """Nodes where blame originates, and how many cycles had to be broken.

    The ordinary case is in-degree zero. When a set of mutually-blaming nodes
    has no such entry -- the ``t64`` transitions do this, since the old and new
    packages declare conflicts against each other -- the member with the
    greatest excess of victims over blamers is promoted so that the component is
    still reported rather than silently dropped.
    """
    sources = {node for node in blame.forward if blame.out_degree(node) > 0}
    roots = [node for node in sorted(sources) if blame.in_degree(node) == 0]

    covered: set[int] = set()
    for root in roots:
        covered.add(root)
        covered.update(_reachable(blame, root))

    cycles = 0
    stranded = sorted(sources - covered)
    while stranded:
        promoted = max(
            stranded,
            key=lambda n: (blame.out_degree(n) - blame.in_degree(n), blame.out_degree(n), -n),
        )
        roots.append(promoted)
        cycles += 1
        covered.add(promoted)
        covered.update(_reachable(blame, promoted))
        stranded = [node for node in stranded if node not in covered]

    return (roots, cycles)


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


def _is_virtual_name(name: str) -> bool:
    bare = name.split(":", 1)[0]
    return any(hint in bare for hint in _VIRTUAL_HINTS)


def _t64_partner(name: str) -> str | None:
    """The other half of a 64-bit-time_t rename, if ``name`` is one half.

    ``libfoo1t64`` pairs with ``libfoo1``. Used to recognise the transition
    where both halves declare conflicts against each other and neither is
    really at fault -- the archive is mid-rename.
    """
    bare, _, arch = name.partition(":")
    suffix = f":{arch}" if arch else ""
    if bare.endswith("t64"):
        return f"{bare[:-3]}{suffix}"
    return f"{bare}t64{suffix}"


def _constraint_operator(constraint: str) -> str:
    text = constraint.strip()
    if not text:
        return ""
    return text.split(None, 1)[0]


def classify(
    graph: ConflictGraph,
    interner: Interner,
    blame: _Blame,
    node: int,
    cascade: Sequence[int],
) -> tuple[Cause, Severity, dict[str, str]]:
    """Decide which mechanism explains a root.

    Ordered most specific first. The order is the policy, so it is written out
    rather than buried in nested conditionals.
    """
    nodes = graph.nodes
    ids = nodes.ids
    name = interner.package_key(ids[node])
    mode = Mode(nodes.modes[node])
    selection = VerSelect(nodes.selections[node])
    has_cur = bool(nodes.current_versions[node])
    has_cand = bool(nodes.candidate_versions[node])
    out = blame.forward.get(node, [])
    detail: dict[str, str] = {}

    operators = Counter(_constraint_operator(interner.text(edge.constraint)) for edge in out)
    dominant_operator = operators.most_common(1)[0][0] if operators else ""
    if dominant_operator:
        detail["operator"] = dominant_operator

    # 1. Third-party origin. Decided first because the action does not depend on
    #    the mechanism: an unsupported archive is closed Invalid either way. The
    #    mechanism is still recorded so the report can explain itself.
    if _is_foreign(graph, node, blame.third_party):
        detail["mechanism"] = _mechanism_label(mode, selection, has_cur, has_cand)
        return (Cause.THIRD_PARTY_PIN, Severity.HIGH, detail)

    # 2. A dependency on something with no provider at all. Distinguished from a
    #    holdback by having no candidate: nothing in the archive satisfies it.
    if not has_cur and not has_cand and (mode is Mode.HOLD or _is_virtual_name(name)):
        detail["kind"] = "virtual" if _is_virtual_name(name) else "no-candidate"
        return (Cause.UNSATISFIABLE_VIRTUAL, Severity.HIGH, detail)

    # 3. apt declined an available candidate and broke a dependent as a result.
    #    Two forms, split because the remedy differs: a package that is not
    #    installed needs marking for install, while one that is installed needs
    #    permission to upgrade. The first is the lintian /
    #    libfile-libmagic-perl case that stalls LTS-to-LTS upgrades outright.
    if mode is Mode.HOLD and has_cand:
        detail["candidate"] = interner.text(nodes.candidate_versions[node])
        label = interner.package_label(ids[node])
        if not has_cur:
            detail["kind"] = "new-dependency"
            detail["fix"] = f"mark {label} for install"
            return (Cause.HOLDBACK_BLOCKS_NEW_DEP, Severity.HIGH, detail)
        detail["kind"] = "held-upgrade"
        detail["installed"] = interner.text(nodes.current_versions[node])
        detail["fix"] = f"allow {label} to upgrade to {detail['candidate']}"
        return (Cause.HELD_PACKAGE_BLOCKS_UPGRADE, Severity.HIGH, detail)

    # 4. The time_t rename, where both halves conflict with each other.
    partner = _t64_partner(name)
    if partner is not None:
        present = {interner.package_key(ids[index]) for index in (node, *cascade)}
        if partner in present and any(
            edge.dep in (DepType.CONFLICTS, DepType.BREAKS) for edge in out
        ):
            detail["partner"] = partner
            return (Cause.T64_TRANSITION, Severity.MEDIUM, detail)

    # 5. A stranded i386 package. Low severity because the remedy is to remove
    #    it and the user can do that unaided.
    if name.endswith(":i386"):
        bare = name.split(":", 1)[0]
        present = {interner.package_key(pkg) for pkg in ids}
        if f"{bare}:amd64" not in present:
            detail["arch"] = "i386"
            return (Cause.I386_ORPHAN, Severity.LOW, detail)

    # 6. A pin broken by an ordinary upgrade. This is the python3 case: the root
    #    is doing nothing wrong, its dependents pinned too tightly.
    if mode is Mode.UPGRADE and dominant_operator in _PIN_OPERATORS:
        detail["from"] = interner.text(nodes.current_versions[node])
        detail["to"] = interner.text(nodes.candidate_versions[node])
        return (Cause.EXACT_PIN_BROKEN_BY_UPGRADE, Severity.HIGH, detail)

    # 7. A removal dragging its reverse-dependencies down.
    if mode.removes:
        detail["removed"] = interner.text(nodes.current_versions[node])
        return (Cause.REMOVAL_CASCADE, Severity.MEDIUM, detail)

    # 8. Ordinary transitional churn: the archive is replacing a package and the
    #    old one is on its way out. Covers both Breaks and Conflicts, because a
    #    conflict apt settles by removing the loser is the same situation --
    #    classified explicitly so normal churn does not land in the
    #    needs-human pile.
    if mode is Mode.KEEP and any(edge.dep in (DepType.BREAKS, DepType.CONFLICTS) for edge in out):
        detail["relationship"] = (
            "conflicts" if any(edge.dep is DepType.CONFLICTS for edge in out) else "breaks"
        )
        return (Cause.TRANSITIONAL_BREAKS, Severity.LOW, detail)

    detail["mechanism"] = _mechanism_label(mode, selection, has_cur, has_cand)
    return (Cause.UNKNOWN, Severity.MEDIUM, detail)


def _mechanism_label(mode: Mode, selection: VerSelect, has_cur: bool, has_cand: bool) -> str:
    """A short description of a node's state, for when no rule claims it."""
    parts = [mode.name.lower()]
    if selection is VerSelect.AVAILABLE_NOT_SELECTED:
        parts.append("candidate-declined")
    elif selection is VerSelect.SELECTED:
        parts.append("candidate-selected")
    if not has_cur:
        parts.append("not-installed")
    if not has_cand:
        parts.append("no-candidate")
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Remedies
# ---------------------------------------------------------------------------


def _remedy_for(
    blame: _Blame, node: int, *, fragile_margin: int
) -> tuple[Decision, int | None, bool]:
    """What apt did about this root, and how narrowly it decided.

    The score pair on a decision edge is apt's own account of the trade-off. A
    narrow margin means the outcome turned on incidental system state, which is
    why such bugs cannot be reproduced on a clean install and arrive as a stream
    of inconsistent duplicates. The lintian holdback turned on one point.
    """
    candidates = blame.decisions.get(node, [])
    if not candidates:
        return (Decision.UNKNOWN, None, False)

    # Prefer a decision that carries scores, since that is the informative one.
    scored = [edge for edge in candidates if edge.score_margin is not None]
    chosen = scored[0] if scored else candidates[0]
    margin = chosen.score_margin
    fragile = margin is not None and margin <= fragile_margin
    return (chosen.decision, margin, fragile)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def analyse(
    graph: ConflictGraph,
    interner: Interner,
    *,
    fragile_margin: int = 2,
    min_cascade_for_high: int = 5,
    evidence_complete: bool = True,
    third_party: Collection[PkgId] = (),
) -> RootReport:
    """Extract and rank the roots of one conflict graph.

    ``third_party`` names packages known to come from outside Ubuntu, normally
    :func:`~uru_doctor.parsers.mainlog.resolve_third_party` applied to
    ``main.log``'s ``Foreign`` list. It only reorients symmetric
    ``Conflicts``/``Breaks`` blame; it never invents or suppresses a root.
    """
    blame = _Blame.of(graph, frozenset(third_party))
    if not blame.forward:
        return RootReport()

    root_nodes, cycles = _find_roots(blame)
    victims = set(blame.reverse)
    ids = graph.nodes.ids

    roots: list[Root] = []
    for node in root_nodes:
        cascade = _reachable(blame, node)
        cause, severity, detail = classify(graph, interner, blame, node, cascade)
        out = blame.forward.get(node, [])
        remedy, margin, fragile = _remedy_for(blame, node, fragile_margin=fragile_margin)

        # Blast radius modulates severity in both directions, except for the
        # causes that stop an upgrade regardless of how many packages they take
        # with them. Without the demotion, a corpus reports a dozen HIGH roots
        # of which eleven have a single victim, and the one that broke forty
        # packages is buried among them.
        if cause not in BLAST_RADIUS_INDEPENDENT:
            if severity is not Severity.HIGH and len(cascade) >= min_cascade_for_high:
                severity = Severity.HIGH
                detail["promoted"] = f"cascade of {len(cascade)}"
            elif severity is Severity.HIGH and len(cascade) <= 1:
                severity = Severity.MEDIUM
                detail["demoted"] = "single victim"

        constraints = Counter(interner.text(edge.constraint) for edge in out if edge.constraint)
        deps = Counter(int(edge.dep) for edge in out)

        confidence = Confidence.STRONG
        if not evidence_complete:
            # The graph is real, but we cannot claim it is the terminal cause of
            # a run whose log stopped early.
            confidence = Confidence.MODERATE
        if cause is Cause.UNKNOWN:
            confidence = Confidence.WEAK

        roots.append(
            Root(
                node=node,
                pkg_id=ids[node],
                cause=cause,
                cascade=cascade,
                severity=severity,
                confidence=confidence,
                mode=Mode(graph.nodes.modes[node]),
                dep=DepType(deps.most_common(1)[0][0]) if deps else DepType.UNKNOWN,
                constraint=constraints.most_common(1)[0][0] if constraints else "",
                remedy=remedy,
                score_margin=margin,
                fragile=fragile,
                depth=min((edge.depth for edge in out), default=0),
                cycle_broken=blame.in_degree(node) > 0,
                detail=detail,
            )
        )

    roots.sort(key=lambda r: (r.rank(), interner.package_key(r.pkg_id)), reverse=True)
    return RootReport(
        roots=roots,
        blame_edges=sum(1 for edge in blame.all_edges if edge.is_blame),
        victims=len(victims),
        cycles_broken=cycles,
        reoriented=blame.reoriented,
    )


def cascade_tree(
    graph: ConflictGraph, interner: Interner, root: Root, *, max_width: int = 12
) -> list[str]:
    """Render a root's cascade as indented lines for ``uru-doctor show``.

    Depth-first so the output reads as a tree, with each level's victims capped
    so that a forty-package cascade reports a count instead of forty lines.
    """
    blame = _Blame.of(graph)
    ids = graph.nodes.ids
    lines: list[str] = []
    seen: set[int] = {root.node}

    def walk(node: int, prefix: str) -> None:
        children = [edge for edge in blame.forward.get(node, []) if edge.dst not in seen]
        shown = children[:max_width]
        hidden = len(children) - len(shown)
        for position, edge in enumerate(shown):
            last = position == len(shown) - 1 and hidden == 0
            branch = "\u2514\u2500 " if last else "\u251c\u2500 "
            constraint = interner.text(edge.constraint)
            suffix = f" ({constraint})" if constraint else ""
            lines.append(
                f"{prefix}{branch}{interner.package_label(ids[edge.dst])}"
                f" [{DepType(edge.dep).name.lower()}]{suffix}"
            )
            seen.add(edge.dst)
            walk(edge.dst, prefix + ("   " if last else "\u2502  "))
        if hidden:
            lines.append(f"{prefix}\u2514\u2500 ... and {hidden} more")

    lines.append(f"{interner.package_label(ids[root.node])}  [{root.cause.value}]")
    walk(root.node, "")
    return lines
