"""Cleaning log text: terminal escapes, progress spam, and personal data.

Two separate jobs that both have to happen before a log is useful.

**Sanitising.** ``screenlog.0`` is a raw terminal capture. It contains ANSI
colour and cursor-movement escapes, and dpkg's progress output uses carriage
returns to overwrite a line in place, so a single logical line arrives as
``(Reading database ... 5%\\r(Reading database ... 10%\\r...`` repeated twenty
times. Left alone, that one line masks to twenty different templates and
inflates every count that touches it.

**Redaction.** These are other people's machines. A ``main.log`` contains the
hostname in its ``uname`` line, ``history.log`` names the invoking user, and
paths under ``/home`` carry account names. Fixtures committed to this repository
are real logs from real bug reports, so redaction is on by default and the
committed fixtures are generated through it.

Redaction is deliberately conservative about package data. Hostnames and
usernames are replaced; version strings, package names and file paths under
system directories are not, because those *are* the evidence. The one exception
is ``/home/<user>/...``, where the account name is replaced but the rest of the
path is kept.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Terminal sanitising
# ---------------------------------------------------------------------------

#: CSI and OSC escape sequences, plus the handful of single-character escapes
#: that appear in practice. Written out rather than using a library because the
#: alternative is a dependency for thirty characters of pattern.
_ANSI = re.compile(
    r"""
    \x1B
    (?:
        \[ [0-?]* [ -/]* [@-~]          # CSI ... final byte
      | \] .*? (?: \x07 | \x1B\\ )      # OSC ... BEL or ST
      | [@-Z\\-_]                       # single-character escape
    )
    """,
    re.VERBOSE,
)

#: Other control characters worth dropping. Backspace is included because
#: ``screenlog`` sometimes contains overstrike sequences from man-page output.
_CONTROL = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

#: ``\r``-separated segments. dpkg redraws a line in place rather than emitting
#: a new one, so only the last segment is the finished text.
_CR_SPLIT = re.compile(r"\r+")

#: Repeated ``(Reading database ... N%`` fragments, which survive CR collapsing
#: when the writer emitted them without a trailing carriage return.
_READING_DB = re.compile(r"\(Reading database \.\.\.(?:\s*\d+%)?")


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences and stray control characters."""
    return _CONTROL.sub("", _ANSI.sub("", text))


def collapse_carriage_returns(line: str) -> str:
    """Keep only the final segment of a carriage-return-overwritten line.

    ``"a\\rb\\rc"`` becomes ``"c"``, which is what a terminal would have
    displayed. Segments are not concatenated: that would produce text no user
    ever saw and no template ever matches.
    """
    if "\r" not in line:
        return line
    segments = [segment for segment in _CR_SPLIT.split(line) if segment]
    return segments[-1] if segments else ""


def collapse_progress(line: str) -> str:
    """Reduce repeated ``(Reading database ...`` fragments to one.

    Real logs contain twenty of these on a single line. One is enough to
    recognise the line; twenty is noise that forks the template.
    """
    matches = list(_READING_DB.finditer(line))
    if len(matches) <= 1:
        return line
    tail = line[matches[-1].end() :]
    return f"(Reading database ...{tail}"


def sanitize_line(line: str) -> str:
    """Apply every sanitising step to one line, in the required order.

    Escapes go first: a cursor-movement sequence can contain a byte that would
    otherwise be mistaken for a carriage return boundary.
    """
    return collapse_progress(collapse_carriage_returns(strip_ansi(line))).rstrip()


def sanitize(text: str) -> str:
    """Sanitise a whole log, dropping lines that were nothing but escapes."""
    out: list[str] = []
    for raw in text.splitlines():
        cleaned = sanitize_line(raw)
        if cleaned.strip() or not raw.strip():
            out.append(cleaned)
    return "\n".join(out)


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

#: ``uname -a`` output in ``main.log``: the second field is the hostname.
_UNAME = re.compile(r"(uname information:\s*'Linux\s+)(\S+)")

#: ``Requested-By: user (1000)`` in ``history.log``.
_REQUESTED_BY = re.compile(r"(Requested-By:\s*)(\S+)(\s*\(\d+\))")

#: Home directories. The account name is replaced; the rest of the path stays,
#: because a path under a home directory is occasionally the bug.
_HOME = re.compile(r"/home/([A-Za-z0-9_.-]+)")
_ROOT_HOME = re.compile(r"/root/")

#: IPv4 addresses, but only where the surrounding text makes them addresses.
#:
#: A bare dotted-quad pattern is unusable here: ``libva2 2.20.0.1`` and
#: ``192.168.1.47`` are the same shape, and four-part Debian versions are
#: common (``6.14.0.37``, ``2.20.0.1``). Redacting those destroys exactly the
#: package evidence this tool exists to read, so an address is only recognised
#: when it appears in a URL, after a word that introduces a host, or with a
#: port attached. Dotted quads in these logs are otherwise versions.
_IPV4_IN_URL = re.compile(r"(//)(?:\d{1,3}\.){3}\d{1,3}")
_IPV4_LABELLED = re.compile(
    r"""
    (?P<lead>
        \b(?: from | to | at | via | client | clients | host | server | peer
            | addr | address | ip | ipv4 | gateway | src | dst | source
            | destination | connected | listening | bind | nameserver )
        \b [\s:=]+
    )
    (?P<addr> (?:\d{1,3}\.){3}\d{1,3} )
    """,
    re.VERBOSE | re.IGNORECASE,
)
_IPV4_WITH_PORT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?=:\d{1,5}\b)")

#: Bare MAC addresses. Unambiguous -- nothing in a Debian version looks like
#: six colon-separated hex pairs.
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")

#: Email addresses, which turn up in ``Maintainer`` fields and signatures.
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

#: ``user@host:~$`` style prompts captured in ``screenlog.0``.
_PROMPT = re.compile(r"\b([A-Za-z0-9_.-]+)@([A-Za-z0-9_.-]+):([~/][^\s$#]*)[$#]")

#: Launchpad and PPA URLs keep their owner, because an unsupported PPA's
#: identity is the whole point of the third-party finding. Only credentials
#: embedded in a URL are removed.
_URL_CREDENTIALS = re.compile(r"://[^/\s:@]+:[^/\s@]+@")


#: Placeholder forms. Stable, so a redacted fixture is reproducible and a diff
#: between two runs of the redactor is empty.
HOST = "redacted-host"
USER = "redacted-user"
IP = "0.0.0.0"
MAC = "00:00:00:00:00:00"
EMAIL = "redacted@example.invalid"


def redact(text: str) -> str:
    """Remove personally identifying content, keeping the package evidence.

    Idempotent: running it twice produces the same output, which is what makes
    a committed fixture reviewable by regenerating it and diffing.
    """
    text = _URL_CREDENTIALS.sub("://", text)
    text = _UNAME.sub(lambda m: f"{m.group(1)}{HOST}", text)
    text = _REQUESTED_BY.sub(lambda m: f"{m.group(1)}{USER}{m.group(3)}", text)
    text = _PROMPT.sub(lambda m: f"{USER}@{HOST}:{m.group(3)}$", text)
    text = _HOME.sub(f"/home/{USER}", text)
    text = _ROOT_HOME.sub("/root/", text)
    text = _EMAIL.sub(EMAIL, text)
    text = _MAC.sub(MAC, text)
    text = _IPV4_IN_URL.sub(lambda m: f"{m.group(1)}{IP}", text)
    text = _IPV4_LABELLED.sub(lambda m: f"{m.group('lead')}{IP}", text)
    return _IPV4_WITH_PORT.sub(IP, text)


def clean(text: str, *, redacted: bool = True) -> str:
    """Sanitise, and redact unless asked not to.

    The order matters: redaction patterns expect text that has already had its
    escape sequences removed, or a coloured prompt will not match.
    """
    sanitized = sanitize(text)
    return redact(sanitized) if redacted else sanitized


def read_log(data: bytes, *, redacted: bool = True, max_bytes: int | None = None) -> str:
    """Decode and clean a log file's bytes.

    Decoded with ``errors="replace"``: these files contain whatever a failing
    maintainer script wrote to the terminal, including invalid UTF-8, and
    refusing to read a log because one byte is malformed would be the wrong
    trade.

    When ``max_bytes`` is given the **tail** is kept, because a truncated
    upgrade log is interesting at the end -- that is where it stopped.
    """
    if max_bytes is not None and len(data) > max_bytes:
        data = data[-max_bytes:]
        # The cut probably landed mid-line; drop the partial first line so the
        # parser is never handed a fragment.
        newline = data.find(b"\n")
        if newline != -1:
            data = data[newline + 1 :]
    return clean(data.decode("utf-8", errors="replace"), redacted=redacted)
