"""Parsing apport metadata and recognising which log an attachment holds.

Two jobs, both of which are about tolerating names and formats we do not
control.

**Attachment naming.** The apport hook in
``/usr/share/apport/package-hooks/source_ubuntu-release-upgrader.py`` attaches
each dist-upgrade log under a CamelCase key derived from its path, and apport
then appends ``.txt`` when it uploads text. So ``/var/log/dist-upgrade/apt.log``
arrives as ``VarLogDistupgradeAptlog.txt``. Three wrinkles make a literal table
insufficient:

* ``CurrentDmesg.txt`` already ends in ``.txt``, so it uploads as
  ``CurrentDmesg.txt.txt``. Two of our three sample bugs show the doubled
  suffix and one does not.
* The key for ``history.log`` is ``VarLogDistupgradeAptHistorylog`` -- note the
  interposed ``Apt``, which does not appear in the filename. Guessing the key
  from the filename gets this one wrong.
* Reporters attach logs by hand under any name they like. One of our fixtures
  carries a plain ``main.log`` plus an attachment titled ``Holding Back lintian
  rather than change libfile-libmagic-perl`` -- a title that is itself the
  diagnosis. Names alone are therefore a hint, and
  :func:`sniff_source` exists to check the content.

**Metadata format.** The structured fields live in the bug *description*, below
whatever the reporter typed. Fields are ``Key: value`` with continuation lines
indented by one space, so a value can span many lines (``ProcEnviron``,
``CrashReports``). The preamble above the first field is the reporter's own
words and is kept separately: it is often the only statement of intent, and it
is also unreliable, so it must never be mistaken for a parsed field.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final

from uru_doctor.models import LogSource, ProblemType

__all__ = [
    "ATTACHMENT_KEYS",
    "DPKG_PROGRESS_VERBS",
    "ApportMeta",
    "attachment_source",
    "normalise_attachment_name",
    "parse_apport_fields",
    "parse_apport_meta",
    "sniff_source",
]

#: Canonical apport keys, taken verbatim from the package hook.
#:
#: Keys, not filenames. ``history.log`` is attached as
#: ``VarLogDistupgradeAptHistorylog``, which no filename-based rule produces.
ATTACHMENT_KEYS: Final[dict[str, LogSource]] = {
    "varlogdistupgradeaptlog": LogSource.APT,
    "varlogdistupgradeapttermlog": LogSource.APT_TERM,
    "varlogdistupgradeapthistorylog": LogSource.HISTORY,
    "varlogdistupgrademainlog": LogSource.MAIN,
    "varlogdistupgradetermlog": LogSource.TERM,
    "varlogdistupgradexorgfixuplog": LogSource.XORG_FIXUP,
    "varlogdistupgradescreenlog": LogSource.SCREENLOG,
    # Spellings the current hook does not emit but which appear on older bugs
    # and in hand-made attachments. Accepting them costs nothing; rejecting
    # them loses the log entirely.
    "varlogdistupgradehistorylog": LogSource.HISTORY,
    "varlogdistupgradeapthistory": LogSource.HISTORY,
    "varlogdistupgradexorgfixup": LogSource.XORG_FIXUP,
    "varlogdistupgradescreenlog0": LogSource.SCREENLOG,
}

#: Plain filenames, as attached by hand.
_PLAIN_NAMES: Final[dict[str, LogSource]] = {
    "apt.log": LogSource.APT,
    "apt-term.log": LogSource.APT_TERM,
    "history.log": LogSource.HISTORY,
    "main.log": LogSource.MAIN,
    "term.log": LogSource.TERM,
    "xorg_fixup.log": LogSource.XORG_FIXUP,
    "screenlog.0": LogSource.SCREENLOG,
}

#: apport's generic attachments, which never contain upgrade evidence.
#:
#: Listed so the fetcher can skip them without downloading. That matters: the
#: Launchpad API answers with HTTP 429 under load and needs a minute of backoff
#: to recover, so every avoided request is real time saved across a corpus of
#: hundreds of bugs. These are recognised after
#: :func:`normalise_attachment_name`, which is why ``currentdmesg`` has no
#: suffix -- it arrives as both ``CurrentDmesg.txt`` and ``CurrentDmesg.txt.txt``.
IRRELEVANT_ATTACHMENTS: Final[frozenset[str]] = frozenset(
    {
        "currentdmesg",
        "dependencies",
        "journalerrors",
        "proccpuinfominimal",
        "proccpuinfo",
        "procenviron",
        "procmodules",
        "procinterrupts",
        "lsusb",
        "lspci",
        "lspcivnvn",
        "varlogdistupgradelspcitxt",
        "varlogdistupgradeaptclonesystemstate",
        "crashreports",
        "gsettingschanges",
        "xorglog",
        "xorglogold",
        "udevdb",
        "acpitables",
        "rfkill",
        "cpuinfo",
    }
)

#: dpkg progress verbs, from apport's own ``pkg_mngr_msgs`` in
#: ``/usr/share/apport/general-hooks/ubuntu.py``.
#:
#: Reused rather than reinvented: apport uses this exact set to decide where a
#: dpkg failure signature begins, so matching it keeps our reading of
#: ``apt-term.log`` aligned with the signatures Launchpad already has.
DPKG_PROGRESS_VERBS: Final[tuple[str, ...]] = (
    "Authenticating",
    "De-configuring",
    "Examining",
    "Installing",
    "Preparing",
    "Processing triggers",
    "Purging",
    "Removing",
    "Replaced",
    "Replacing",
    "Setting up",
    "Unpacking",
    "Would remove",
)

#: ``Key: value``, where the key is a bare CamelCase identifier.
_FIELD_RE: Final = re.compile(r"^(?P<key>[A-Za-z][A-Za-z0-9_.-]*):(?: (?P<value>.*)|)$")

#: ``Package: ubuntu-release-upgrader-core 1:24.04.28``
_PACKAGE_RE: Final = re.compile(r"^(?P<name>\S+)(?:\s+(?P<version>\S+))?")

#: ``DistroRelease: Ubuntu 24.04``
_DISTRO_RE: Final = re.compile(r"^(?P<distro>\w+)\s+(?P<version>[\d.]+)")

#: ``InstallationMedia: Ubuntu 24.04.4 LTS "Noble Numbat" - Release amd64 (...)``
_MEDIA_RE: Final = re.compile(r"(?:Ubuntu|Kubuntu|Xubuntu|Lubuntu)[\w ]*?\s(?P<version>\d\d\.\d\d)")

#: ``Uname: Linux 6.18.7-surface-1 x86_64``
_UNAME_RE: Final = re.compile(r"^Linux\s+(?P<release>\S+)\s+(?P<machine>\S+)")

#: Ubuntu kernel flavours. Anything else in ``Uname`` is a third-party kernel,
#: which is independent evidence of an unsupported configuration -- the surface
#: PPA bug reports ``6.18.7-surface-1``.
_UBUNTU_KERNEL_RE: Final = re.compile(
    r"^\d+\.\d+\.\d+-\d+"
    r"(?:-(?:generic|lowlatency|kvm|aws|azure|gcp|oracle|oem|raspi|riscv|"
    r"intel-iotg|nvidia|realtime|ibm|gke|laptop|hwe|crashdump|64k|allwinner))*$"
)


def normalise_attachment_name(title: str) -> str:
    """Reduce an attachment title to a comparable key.

    Lower-cases, drops directory parts, and strips upload suffixes repeatedly
    so that ``CurrentDmesg.txt.txt`` and ``CurrentDmesg.txt`` agree. Only
    suffixes with their dot are stripped, which leaves
    ``VarLogDistupgradeLspcitxt`` -- where ``txt`` is part of the key -- intact.
    """
    name = title.strip().rsplit("/", 1)[-1].lower()
    for _ in range(4):
        for suffix in (".txt", ".gz", ".tar", ".log.txt"):
            if name.endswith(suffix) and len(name) > len(suffix):
                name = name[: -len(suffix)]
                break
        else:
            break
    return name.replace("-", "").replace("_", "").replace(" ", "")


def attachment_source(title: str) -> LogSource | None:
    """Identify an attachment from its title alone, or ``None``.

    ``None`` means "unknown", not "irrelevant" -- ask
    :func:`is_irrelevant_attachment` to tell those apart, and
    :func:`sniff_source` to settle the unknown case. Roughly a third of the
    useful attachments on real bugs are hand-uploaded under names no table can
    predict.
    """
    plain = title.strip().rsplit("/", 1)[-1].lower()
    if plain in _PLAIN_NAMES:
        return _PLAIN_NAMES[plain]
    # A hand-attached file may still carry apport's .txt suffix.
    if plain.endswith(".txt") and plain[:-4] in _PLAIN_NAMES:
        return _PLAIN_NAMES[plain[:-4]]

    return ATTACHMENT_KEYS.get(normalise_attachment_name(title))


def is_irrelevant_attachment(title: str) -> bool:
    """Whether an attachment is known to hold no upgrade evidence.

    Used to avoid downloading it at all. Distinct from an unrecognised name,
    which must be fetched and sniffed.
    """
    key = normalise_attachment_name(title)
    if key in IRRELEVANT_ATTACHMENTS:
        return True
    # Images: reporters attach screenshots of the failure dialogue. The text is
    # in the logs; we are not doing OCR.
    return (
        title.strip()
        .lower()
        .endswith((".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".mp4", ".svg"))
    )


#: Content fingerprints, tried in order. First match wins, so the most
#: distinctive patterns come first.
_SNIFF: Final[tuple[tuple[LogSource, re.Pattern[str]], ...]] = (
    # apt's resolver trace: the section banner, or any depth-indented verb.
    (LogSource.APT, re.compile(r"^Log time: \w{3} \w{3}", re.MULTILINE)),
    (
        LogSource.APT,
        re.compile(r"^(?:  )*(?:Investigating|Broken|Considering) \S+ ", re.MULTILINE),
    ),
    # history.log is RFC822 stanzas with a Start-Date.
    (LogSource.HISTORY, re.compile(r"^Start-Date: \d{4}-\d{2}-\d{2}", re.MULTILINE)),
    # main.log: timestamp, level, message.
    (
        LogSource.MAIN,
        re.compile(
            r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} "
            r"(?:DEBUG|INFO|WARNING|ERROR|CRITICAL) ",
            re.MULTILINE,
        ),
    ),
    # apt-term.log: dpkg's own progress chatter.
    (
        LogSource.APT_TERM,
        re.compile(
            r"^(?:" + "|".join(re.escape(v) for v in DPKG_PROGRESS_VERBS) + r") .*\.\.\.",
            re.MULTILINE,
        ),
    ),
    (LogSource.APT_TERM, re.compile(r"^dpkg: (?:error|warning)", re.MULTILINE)),
)


def sniff_source(text: str, *, limit: int = 64_000) -> LogSource | None:
    """Identify a log from its content.

    Needed because attachment titles are unreliable, and because an attachment
    whose title *is* a sentence may still be a complete apt log. Only the head
    of the file is examined; every fingerprint here appears within the first
    few lines of a genuine log.
    """
    head = text[:limit]
    for source, pattern in _SNIFF:
        if pattern.search(head):
            return source
    return None


def parse_apport_fields(text: str) -> tuple[str, dict[str, str]]:
    """Split an apport report body into ``(preamble, fields)``.

    The preamble is everything above the first ``Key: value`` line -- the
    reporter's own description. Continuation lines, indented by one space, are
    folded into the preceding field with the indent removed.

    A blank line does not terminate a field block: apport emits them inside
    reports, and treating one as a terminator truncates the metadata.
    """
    preamble: list[str] = []
    fields: dict[str, str] = {}
    key: str | None = None
    buffer: list[str] = []

    def flush() -> None:
        if key is not None:
            fields[key] = "\n".join(buffer).strip("\n")

    for line in text.splitlines():
        if line.startswith((" ", "\t")) and key is not None:
            buffer.append(line[1:] if line.startswith(" ") else line.lstrip("\t"))
            continue

        match = _FIELD_RE.match(line)
        if match is None:
            if key is None:
                preamble.append(line)
            # A non-field, non-continuation line after a field block. Apport
            # does not produce these; ignore rather than guess.
            continue

        flush()
        key = match["key"]
        value = match["value"] or ""
        buffer = [value] if value else []

    flush()
    return ("\n".join(preamble).strip(), fields)


@dataclass(frozen=True, slots=True)
class ApportMeta:
    """The apport fields that bear on diagnosing an upgrade failure."""

    problem_type: ProblemType = ProblemType.UNKNOWN
    package: str = ""
    """Source of the report, e.g. ``ubuntu-release-upgrader-core``."""

    package_version: str = ""
    source_package: str = ""
    distro_release: str = ""
    """``"24.04"`` from ``DistroRelease: Ubuntu 24.04``."""

    architecture: str = ""
    kernel_release: str = ""
    """``6.18.7-surface-1`` from ``Uname``."""

    version_signature: str = ""
    """``ProcVersionSignature``, e.g. ``Ubuntu 6.8.0-107.107-generic 6.8.12``.

    Empty when the field was absent. The apport hook attaches
    ``/proc/version_signature`` only ``if_exists``, and that file is created by
    Ubuntu's kernel packaging -- so an absent field is itself evidence of a
    kernel Ubuntu did not build. See :attr:`has_third_party_kernel`."""

    has_version_signature: bool = False
    """Whether the field was present at all, as opposed to present and empty.

    Needed because absence is the signal, and an empty string cannot tell the
    two apart."""

    upgrade_status: str = ""
    installation_media: str = ""
    casper_md5: str = ""
    """``CasperMD5CheckResult``. ``"skip"`` or a failure means the install
    media itself is suspect, which outranks most other explanations."""

    current_desktop: str = ""
    apport_version: str = ""
    traceback: str = ""
    duplicate_signature: str = ""
    """apport's own signature. Embeds ``package:name:version``, so it varies
    between reporters of the same fault -- which is why these bugs do not
    self-deduplicate on Launchpad."""

    error_message: str = ""
    preamble: str = ""
    """The reporter's own words, above the structured fields."""

    tags: tuple[str, ...] = ()
    fields: dict[str, str] = field(default_factory=dict)
    """Every parsed field, for the report and for rules we have not written."""

    @property
    def has_third_party_kernel(self) -> bool:
        """Whether the running kernel is one Ubuntu did not build.

        Two independent checks, because each alone has a blind spot.

        ``ProcVersionSignature`` is the stronger one: the apport hook attaches
        ``/proc/version_signature`` only if it exists, and Ubuntu's kernel
        packaging is what creates it. The surface-PPA bug has no such field
        while both generic-kernel bugs do. But a reporter who edits the
        description -- as happens when a bug is groomed for an SRU -- can
        remove it, so absence alone is not conclusive.

        The ``Uname`` flavour check is the backstop. It is deliberately a
        whitelist of Ubuntu flavours rather than a blacklist of known PPAs,
        because the set of third-party kernels is unbounded.

        This is independent of ``main.log``'s ``Foreign`` list and survives the
        common case of a bug with no apt log attached at all.
        """
        if self.has_version_signature:
            return not self.version_signature.strip().startswith("Ubuntu")
        if not self.kernel_release:
            return False
        return _UBUNTU_KERNEL_RE.match(self.kernel_release) is None

    @property
    def installation_release(self) -> str:
        """The release this system was originally installed as.

        From ``InstallationMedia``. One fixture reports 22.04 media on a 24.04
        system attempting 26.04, which is two chained upgrades' worth of
        accumulated local state.
        """
        if match := _MEDIA_RE.search(self.installation_media):
            return match["version"]
        return ""

    @property
    def is_chained_upgrade(self) -> bool:
        """Whether this system has been upgraded before, rather than installed.

        Reported rather than acted on: it is weak evidence that cuts both ways,
        and treating it as a cause would be exactly the kind of plausible
        guess this tool is built to avoid.
        """
        origin = self.installation_release
        return bool(origin) and bool(self.distro_release) and origin != self.distro_release

    @property
    def declared_attachments(self) -> tuple[str, ...]:
        """Attachment keys that appear as fields in the description.

        apport decides per value: one that is at most 1000 bytes *and* at most
        five lines is inlined into the description, anything larger becomes a
        separate attachment (``problem_report.write_mime``, ``attach_treshold``).
        So a key present here is a file that existed and was small -- and an
        empty one is a file that existed and was empty.

        Useful as a cross-check. A key declared here but absent from the
        attachment list was not lost; it was empty.
        """
        return tuple(
            key for key in self.fields if normalise_attachment_name(key) in ATTACHMENT_KEYS
        )

    @property
    def empty_logs(self) -> tuple[LogSource, ...]:
        """Logs that existed on the reporter's disk but had no content.

        The inference that matters is ``apt-term.log``: empty means dpkg
        produced no output, so nothing was written to the system, so the
        failure is before :attr:`~uru_doctor.models.Phase.COMMIT`. It is
        available from the description alone, which is the common case --
        LP#2150319 declares both ``VarLogDistupgradeApttermlog`` and
        ``VarLogDistupgradeAptHistorylog`` as empty keys and attaches neither,
        independently confirming the pre-commit failure its ``main.log`` shows.
        """
        out: list[LogSource] = []
        for key in self.declared_attachments:
            if not self.fields.get(key, "").strip():
                source = ATTACHMENT_KEYS.get(normalise_attachment_name(key))
                if source is not None and source not in out:
                    out.append(source)
        return tuple(out)

    @property
    def dpkg_produced_no_output(self) -> bool:
        """Whether ``apt-term.log`` is known to have been empty.

        A positive answer is strong evidence that no package was written.
        ``False`` means "not known", not "dpkg ran" -- the description may
        simply not mention the file.
        """
        return LogSource.APT_TERM in self.empty_logs

    @property
    def media_check_failed(self) -> bool:
        """Whether the install media failed its checksum.

        ``skip`` is not a failure -- it is what a normal installed system
        reports -- but anything else non-empty outranks most other
        explanations, because corrupt media invalidates the whole run.
        """
        return self.casper_md5 not in ("", "pass", "skip")

    @property
    def is_crash(self) -> bool:
        return self.problem_type is ProblemType.CRASH


def _first(fields: dict[str, str], *keys: str) -> str:
    for key in keys:
        if value := fields.get(key, "").strip():
            return value
    return ""


def parse_apport_meta(text: str, *, tags: Sequence[str] = ()) -> ApportMeta:
    """Parse a bug description into :class:`ApportMeta`."""
    preamble, fields = parse_apport_fields(text)

    package = version = ""
    if (raw := _first(fields, "Package")) and (match := _PACKAGE_RE.match(raw)):
        package = match["name"] or ""
        version = match["version"] or ""

    distro = ""
    if raw := _first(fields, "DistroRelease"):
        match = _DISTRO_RE.match(raw)
        distro = match["version"] if match else raw

    kernel = ""
    if (raw := _first(fields, "Uname")) and (match := _UNAME_RE.match(raw)):
        kernel = match["release"]

    return ApportMeta(
        problem_type=ProblemType.parse(_first(fields, "ProblemType")),
        package=package,
        package_version=version,
        source_package=_first(fields, "SourcePackage"),
        distro_release=distro,
        architecture=_first(fields, "Architecture", "PackageArchitecture"),
        kernel_release=kernel,
        version_signature=_first(fields, "ProcVersionSignature"),
        has_version_signature="ProcVersionSignature" in fields,
        upgrade_status=_first(fields, "UpgradeStatus"),
        installation_media=_first(fields, "InstallationMedia"),
        casper_md5=_first(fields, "CasperMD5CheckResult").lower(),
        current_desktop=_first(fields, "CurrentDesktop"),
        apport_version=_first(fields, "ApportVersion"),
        traceback=_first(fields, "Traceback"),
        duplicate_signature=_first(fields, "DuplicateSignature"),
        error_message=_first(fields, "ErrorMessage", "Title"),
        preamble=preamble,
        tags=tuple(tags),
        fields=fields,
    )
