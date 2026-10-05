# SPDX-License-Identifier: GPL-2.0-or-later
"""Configuration: a TOML file loaded into a frozen Pydantic tree.

Defaults live in the code, not in the file, so a missing ``uru-doctor.toml``
behaves identically to a complete one.

This module holds the sections the **library** reads: ``ingest``, ``apt``,
``rules``, ``dedup``, ``title`` and ``report``. The CLI frontend adds its own
sections (``paths``, ``launchpad``, ``queue``) in
:mod:`uru_doctor_cli.config`, which subclasses :class:`Config`.

The checked-in ``uru-doctor.toml`` writes out every default **that something
actually reads**, with a comment explaining it. Options defined here but not
yet consulted are listed in that file as unimplemented rather than presented as
settings, because a documented option that silently does nothing is worse than
an undocumented one: it invites someone to change it and conclude the tool is
broken. ``cli/tests/test_config.py`` enforces both directions across the whole
tree -- no documented option may be inert, and no field may be absent from both
lists -- so adding a field forces a decision instead of quietly becoming a
third kind of thing.

That guard exists because the alternative happened. A ``wanted_attachments``
list lived in the CLI's ``LaunchpadConfig``, was read by nothing, and three of
its entries named attachments that
:func:`~uru_doctor.parsers.apportmeta.is_irrelevant_attachment` classifies as
worthless. Two tables of attachment names disagreed for as long as neither was
used.

API keys are never stored here. The config names the *environment variable* to
read, and a validator rejects anything that looks like a key pasted into the
file, so that a config can be committed without thinking about it.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any, Literal, Self, overload

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

#: Searched for by walking up from the working directory.
DEFAULT_CONFIG_FILENAMES: tuple[str, ...] = ("uru-doctor.toml", ".uru-doctor.toml")

#: Anything longer than this in a single log file is truncated during ingest.
#: ``screenlog.0`` reaches multiple megabytes of terminal capture and the useful
#: content is always near the end, so the tail is what gets kept.
DEFAULT_MAX_LOG_BYTES = 16 * 1024 * 1024


class IngestConfig(BaseModel):
    """How logs are read and reduced."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_log_bytes: int = Field(DEFAULT_MAX_LOG_BYTES, ge=64 * 1024)
    """Per-file cap. Oversized files are read from the tail."""

    redact: bool = True
    """Scrub hostnames, usernames, IP addresses and home paths.

    On by default because these are other people's machines. Turning it off is
    occasionally useful when a path *is* the bug, but committed fixtures are
    always redacted.
    """

    keep_archived_attempts: bool = True
    """Ingest ``YYYYMMDD-HHMM/`` subdirectories as additional attempts.

    Worth keeping: a user who retried four times before filing tells you the
    failure is deterministic, and the earliest attempt often has the fullest
    logs before a later one truncated them.
    """

    screenlog_fallback: bool = True
    """Parse ``screenlog.0`` when the structured logs are missing or truncated.

    Low-quality input -- raw terminal with ANSI escapes -- so findings derived
    from it are confidence-penalised rather than trusted.
    """


class AptConfig(BaseModel):
    """How ``apt.log`` is parsed."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    grammar: Literal["auto", "apt2", "apt3"] = "auto"
    """Which debug grammar to assume.

    ``auto`` selects from the ``apt version`` line in ``main.log``, which is the
    right answer: an LTS-to-LTS upgrade runs the *source* release's apt, so a
    24.04 bug carries apt 2.8 output whose state vocabulary differs from apt 3's
    in ways that break fixed-field parsing.
    """

    dedupe_sections: bool = True
    """Collapse byte-identical resolver sections.

    The upgrader logs each resolve twice (``Starting`` then ``Starting 2``) and
    runs the whole calculation twice, so one real problem appears four times.
    Leaving this off inflates every count fourfold.
    """

    max_graph_nodes: int = Field(5000, ge=100)
    """Guard against a pathological log producing an unbounded graph."""

    keep_autoinstall_edges: bool = True
    """Record ``Installing B as Depends of A`` edges.

    Context rather than blame -- they do not participate in root finding -- but
    they are what lets a report explain why a package was in the transaction
    at all.
    """


class RulesConfig(BaseModel):
    """Which diagnostic rules run, and their thresholds."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: tuple[str, ...] = ()
    """Rule names to run. Empty means all registered rules."""

    disabled: tuple[str, ...] = ()
    """Rule names to skip, applied after :attr:`enabled`."""

    fragile_score_margin: int = Field(2, ge=0)
    """apt ``Considering`` score margin at or below which a finding is fragile.

    The lintian holdback turned on a one-point margin
    (``libfile-libmagic-perl 0`` against ``lintian -1``), which is why it could
    not be reproduced on a clean install and attracted inconsistent duplicates.
    Flagging that explicitly saves the next person the same week of work.
    """

    min_cascade_for_high: int = Field(5, ge=1)
    """Cascade size at which a pin or removal cascade is promoted to high severity."""

    third_party_origins: tuple[str, ...] = (
        "ppa.launchpad.net",
        "ppa.launchpadcontent.net",
    )
    """Origin substrings that mark a package as not from Ubuntu.

    The upgrader's own ``Foreign (before rewriting sources)`` list is the
    primary signal; this catches origins that appear in apt metadata but not
    in that list.
    """


class DedupConfig(BaseModel):
    """How duplicates are found."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version_granularity: Literal["exact", "upstream", "major", "operator"] = "operator"
    """How much of a dependency constraint survives into a fingerprint.

    The relationship operator is always kept, because ``(= v)`` and ``(<< v)``
    are different failures. The version is policy, and the default keeps none
    of it: the exact boundary reflects when a log was captured, not what broke.
    One real ``python3-cryptography-vectors`` conflict appears in the corpus as
    both ``(< 46.0.1~)`` and ``(< 46.0.7~)``, so anything finer files that as
    two bugs.
    """

    ambiguous_low: float = Field(0.55, ge=0.0, le=1.0)
    """Below this score a pair is not a duplicate and no model is consulted."""

    ambiguous_high: float = Field(0.80, ge=0.0, le=1.0)
    """At or above this score a pair is a duplicate on structure alone."""

    min_shared_roots: int = Field(1, ge=1)
    """Shared root packages required before a pair is even scored."""

    max_cluster_size: int = Field(500, ge=2)
    """Sanity bound; a cluster larger than this indicates a fingerprint bug."""

    @model_validator(mode="after")
    def _check_band(self) -> Self:
        if self.ambiguous_low > self.ambiguous_high:
            raise ValueError(
                f"[dedup].ambiguous_low ({self.ambiguous_low}) must not exceed "
                f"ambiguous_high ({self.ambiguous_high})"
            )
        return self


class TitleConfig(BaseModel):
    """How proposed titles are built."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_length: int = Field(120, ge=40, le=255)
    """Launchpad accepts more, but a title that fits a bug list is read."""

    include_cascade_size: bool = True
    """Mention how many packages a root broke.

    "breaks 40 python3-* pinned to (<< 3.13)" conveys scale in a way that
    "breaks python3-apt" does not.
    """

    include_fragile_marker: bool = True
    """Append a fragility note when apt's score margin was small."""


class ReportConfig(BaseModel):
    """What the Markdown digest contains."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    max_clusters: int = Field(50, ge=1)
    max_members_shown: int = Field(20, ge=1)
    max_cascade_shown: int = Field(12, ge=1)
    """Victims listed per root before eliding. A forty-victim cascade needs a
    count, not forty lines."""

    top_packages: int = Field(20, ge=1)
    separate_third_party: bool = True
    """Route third-party-origin findings to their own candidate-Invalid section,
    grouped by origin.

    One PPA can account for a dozen bugs -- the linux-surface packages did
    exactly that -- and they are all closed for the same reason, so they should
    be dispatched together rather than rediagnosed one at a time.
    """

    show_fragile_section: bool = True
    show_needs_human: bool = True


class Config(BaseModel):
    """The library's configuration tree.

    The CLI frontend subclasses this to add the sections only it reads
    (``paths``, ``launchpad``, ``queue``); see :mod:`uru_doctor_cli.config`.
    ``extra="forbid"`` here is deliberate, which means a config file carrying
    CLI sections can only be loaded through the CLI's model.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ingest: IngestConfig = IngestConfig()
    apt: AptConfig = AptConfig()
    rules: RulesConfig = RulesConfig()
    dedup: DedupConfig = DedupConfig()
    title: TitleConfig = TitleConfig()
    report: ReportConfig = ReportConfig()

    source_path: Path | None = None
    """Where this was loaded from, for a frontend to report."""


def find_config(start: Path | None = None) -> Path | None:
    """Locate a config file by walking up from ``start`` (default: cwd)."""
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        for name in DEFAULT_CONFIG_FILENAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


@overload
def load_config(path: Path | None = None, *, search: bool = True) -> Config: ...


@overload
def load_config[C: Config](
    path: Path | None = None, *, search: bool = True, model: type[C]
) -> C: ...


def load_config(
    path: Path | None = None, *, search: bool = True, model: type[Config] | None = None
) -> Config:
    """Load configuration, falling back to all-defaults.

    An explicit ``path`` is required to exist. Without one, the tree is searched
    upward unless ``search`` is False, and a total absence of config is a
    perfectly valid configuration.

    ``model`` is the tree to validate against: the library's :class:`Config`
    by default, or a frontend's subclass carrying extra sections. Because every
    model in the tree is ``extra="forbid"``, loading through the library's
    model rejects a file that contains CLI-only sections -- load through the
    frontend's model instead.

    Validation errors are re-raised without the offending *values*. Pydantic's
    default message embeds ``input_value=``, and a frontend prints the whole
    message to stderr -- so a config holding a credential in a section this
    tool does not recognise would have that credential echoed into a terminal,
    a CI log or a bug report. The field path and the reason are what a person
    needs to fix it; the value is theirs already.
    """
    cls = Config if model is None else model
    resolved = path or (find_config() if search else None)
    if resolved is None:
        return cls()
    with resolved.open("rb") as handle:
        raw: dict[str, Any] = tomllib.load(handle)
    # Not settable from the file; it describes where the file was.
    raw.pop("source_path", None)
    try:
        return cls(**raw, source_path=resolved)
    except ValidationError as exc:
        raise ValueError(_redacted_validation_error(exc, resolved)) from None


def _redacted_validation_error(exc: ValidationError, source: Path) -> str:
    """Render a validation failure as locations and reasons, never values.

    ``from None`` at the call site matters as much as this function: chaining
    the original would put pydantic's full message, values included, back into
    the traceback that a crash report would carry.
    """
    lines = [f"{source} is not valid:"]
    for error in exc.errors():
        where = ".".join(str(part) for part in error["loc"]) or "(root)"
        lines.append(f"  {where}: {error['msg']}")
    return "\n".join(lines)
