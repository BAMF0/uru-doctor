# SPDX-License-Identifier: GPL-2.0-or-later
"""The CLI's configuration: the library tree plus frontend-only sections.

``paths``, ``launchpad`` and ``queue`` describe where the CLI keeps state,
how it talks to Launchpad and how much of the worklist it prints -- none of
which the library consults. They live here so that the library's
:class:`uru_doctor.config.Config`, which is ``extra="forbid"`` like every
model in the tree, stays an honest description of what the library reads.
"""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from uru_doctor.config import Config, load_config


class PathsConfig(BaseModel):
    """Where state and output live."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    state_dir: Path = Path(".uru-doctor")
    """The record store and the downloaded attachment cache."""

    out_dir: Path = Path("out")
    """Generated reports, exports and retitle proposals."""


class LaunchpadConfig(BaseModel):
    """The optional read-only fetch path."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    api_base: str = "https://api.launchpad.net/devel"
    user_agent: str = (
        "uru-doctor/0.1 (+https://launchpad.net/ubuntu/+source/ubuntu-release-upgrader)"
    )
    """Identifies the client. Launchpad is a shared service; be nameable."""

    max_retries: int = Field(5, ge=0)
    backoff_base_s: float = Field(2.0, gt=0)
    """Exponential backoff base. Observed 429s need tens of seconds, not milliseconds."""

    min_interval_s: float = Field(3.0, ge=0.0)
    """Minimum gap between requests.

    Measured, not guessed: below roughly two seconds the API starts answering
    429, and recovering from one costs about a minute. Spacing requests is
    cheaper than retrying them, which is also why there is no concurrency
    setting -- parallel requests against this API are slower than serial ones
    once the 429s start.
    """

    max_attachment_bytes: int = Field(32 * 1024 * 1024, ge=1024)
    """Cap on a single attachment.

    ``VarLogDistupgradeAptclonesystemstate.tar.gz`` can be tens of megabytes
    and answers nothing the resolver trace does not answer better.
    """

    sweep_page_size: int = Field(50, ge=1, le=300)
    """Tasks per ``searchTasks`` page.

    Larger pages mean fewer requests for the listing, which is the cheap part
    of a sweep -- the logs are what cost. 50 is what the API returns
    comfortably.
    """

    sweep_max_bugs: int = Field(50, ge=1)
    """How many new bugs one ``sweep`` will fetch logs for.

    A stop, not a target. At roughly six requests and three seconds each, a
    hundred bugs is half an hour; an unbounded sweep against a quiet week is
    fine and against a flood is an afternoon. The watermark only advances over
    bugs actually handled, so the remainder is picked up by the next run rather
    than skipped.
    """

    max_deep_bugs: int = Field(50, ge=1)
    """How many bugs one ``refresh --deep`` will ask about individually.

    A cheap refresh learns every bug's status in one request per fifty bugs,
    because ``searchTasks`` returns status in the task entry. Learning *which*
    bug a duplicate duplicates is one request each, since only the bug resource
    carries that link -- so at three seconds apiece a corpus of thousands is
    hours, and this is the stop that keeps the command usable.

    It is safe to cap because the batch is chosen least-recently-checked first,
    which makes repeated runs walk the corpus round-robin rather than
    re-reading the same head of it.
    """

    # There is deliberately no ``wanted_attachments`` list. One lived here and
    # disagreed with the code: its last three entries -- ``Dependencies``,
    # ``ProcCpuinfoMinimal`` and ``VarLogDistupgradeLspcitxt`` -- are all
    # classified irrelevant by ``apportmeta.is_irrelevant_attachment``, which
    # is what the fetcher actually consults. Two tables of attachment names
    # that disagree is worse than one, so the mapping lives only in
    # :mod:`uru_doctor.parsers.apportmeta`, next to the code that reads the
    # files it names.


class QueueConfig(BaseModel):
    """The worklist: what still needs a decision."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    stale_after_days: int = Field(7, ge=1)
    """When to stop trusting the recorded Launchpad state.

    The worklist exists so that a triager does not have to re-check Launchpad
    for every row, which only works if the tool is honest about how old its
    copy is. Past this many days it says so rather than presenting a stale
    verdict as current.
    """

    max_rows: int = Field(20, ge=1)
    """Rows listed per bucket before eliding.

    Counts are always exact and always shown; this caps only what is printed.
    A worklist of three hundred actionable bugs is paged through, not read, and
    a command that prints all of them has buried its own first row.
    """


class CliConfig(Config):
    """The whole configuration tree: the library's sections plus the CLI's."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    paths: PathsConfig = PathsConfig()
    launchpad: LaunchpadConfig = LaunchpadConfig()
    queue: QueueConfig = QueueConfig()


def load_cli_config(path: Path | None = None, *, search: bool = True) -> CliConfig:
    """Load the CLI configuration, falling back to all-defaults.

    Thin binding of :func:`uru_doctor.config.load_config` to
    :class:`CliConfig`; see that function for the search semantics and the
    reason validation errors are re-raised without values.
    """
    return load_config(path, search=search, model=CliConfig)
