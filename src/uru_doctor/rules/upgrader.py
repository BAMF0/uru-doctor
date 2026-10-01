"""Rules for failures the apt resolver has nothing to say about.

Every pattern here is an upstream string from
``/usr/lib/python3/dist-packages/DistUpgrade/``, reproduced literally so the
table can be audited against the source. ``upstream()`` turns the ``%s``
placeholders into captures, which keeps the literal recognisable.

Priority runs lowest-number-first and encodes one judgement: **the environment
outranks the packages.** A run that failed because the disk filled has broken
packages too, and a run that failed because the archive was unreachable looks
like a dependency problem. Reporting the dependency problem in either case
sends a triager to the wrong place, so the physical and configuration failures
are given the lower numbers and win.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

from uru_doctor.models import (
    Cause,
    Confidence,
    Finding,
    LogSource,
    Phase,
    Severity,
)
from uru_doctor.parsers.aptterm import FailureKind
from uru_doctor.rules.context import RuleContext
from uru_doctor.rules.registry import ErrorPattern, rule, upstream

__all__ = [
    "DISK_PATTERNS",
    "dpkg_failures",
    "dpkg_interrupted",
    "truncated_evidence",
    "upgrader_crash",
]

#: ``(cause, patterns, summary template)``, tried in listed order.
#:
#: The summary templates take the first capture, which is why the capture names
#: matter: a rule that reports "a problem occurred" is not worth firing.
DISK_PATTERNS: Final[tuple[ErrorPattern, ...]] = (
    upstream(
        "Not enough free space: %s",
        "DistUpgradeController._checkFreeSpace",
        "required",
    ),
)

_ENVIRONMENT_RULES: Final[
    tuple[tuple[str, Cause, tuple[ErrorPattern, ...], str, Severity, int], ...]
] = (
    (
        "env.disk-space",
        Cause.NOT_ENOUGH_DISK_SPACE,
        DISK_PATTERNS,
        "not enough free disk space: {required}",
        Severity.HIGH,
        10,
    ),
    (
        "env.not-root",
        Cause.FILESYSTEM_NOT_WRITABLE,
        (upstream("Not running as root!", "DistUpgradeController.run"),),
        "the upgrader was not run as root",
        Severity.HIGH,
        11,
    ),
    (
        "env.not-writable",
        Cause.FILESYSTEM_NOT_WRITABLE,
        (
            upstream("%s not writable", "DistUpgradeController._checkDirectory", "path"),
            upstream(
                "Can not write to '%s'",
                "DistUpgradeController.doPostInitialUpdate",
                "path",
            ),
            upstream(
                "error '%s' when trying to write to the conffile",
                "DistUpgradeViewText.confirmConffilePrompt",
                "error",
            ),
        ),
        "a required path is not writable: {path}",
        Severity.HIGH,
        12,
    ),
    (
        "env.cache-locked",
        Cause.CACHE_LOCK_FAILED,
        (
            upstream(
                "Cache can not be locked (%s)",
                "DistUpgradeController.openCache",
                "error",
            ),
        ),
        "another package manager holds the apt lock: {error}",
        Severity.HIGH,
        13,
    ),
    (
        "env.ssh-blocked",
        Cause.SSH_UPGRADE_BLOCKED,
        (
            upstream("upgrade over ssh not allowed", "DistUpgradeController._checkSSH"),
            upstream(
                "Upgrading over remote connection not supported",
                "DistUpgradeController._checkSSH",
            ),
        ),
        "the upgrade was refused because it was started over SSH",
        Severity.MEDIUM,
        14,
    ),
    (
        "env.esp-unusable",
        Cause.ESP_UNUSABLE,
        (
            upstream(
                "EFI System Partition (ESP) not usable",
                "DistUpgradeQuirks._checkAndInstallBiosGrub",
            ),
        ),
        "the EFI system partition is not usable",
        Severity.HIGH,
        15,
    ),
    (
        "env.unsupported-path",
        Cause.UNSUPPORTED_UPGRADE_PATH,
        (
            upstream(
                "An upgrade from '%s' to '%s' is not supported",
                "DistUpgradeController._checkUpgradePath",
                "source",
                "target",
            ),
        ),
        "upgrading from {source} to {target} is not a supported path",
        Severity.HIGH,
        16,
    ),
    (
        "env.lxd-installed",
        Cause.UNSUPPORTED_UPGRADE_PATH,
        (upstream("lxd is installed", "DistUpgradeController._checkLxd"),),
        "lxd is installed, which the upgrader refuses to upgrade through",
        Severity.MEDIUM,
        17,
    ),
    # -- network and archive --------------------------------------------
    (
        "net.auth-failed",
        Cause.PACKAGE_AUTH_FAILED,
        (
            upstream(
                "Unauthenticated packages found: '%s'",
                "DistUpgradeController._verifyAPTAuthentication",
                "packages",
            ),
        ),
        "packages could not be authenticated: {packages}",
        Severity.HIGH,
        20,
    ),
    (
        "net.download-failed",
        Cause.DOWNLOAD_FAILED,
        (
            upstream(
                "giving up on fetching after maximum retries",
                "DistUpgradeController._fetchArchives",
            ),
            upstream(
                "'%s' was not downloadable",
                "DistUpgradeController._verifyAPTAuthentication",
                "item",
            ),
            upstream(
                "No '%s' available/downloadable after sources.list rewrite+update",
                "DistUpgradeController._checkMetaPkgs",
                "item",
            ),
        ),
        "the upgrade could not be downloaded",
        Severity.HIGH,
        21,
    ),
    (
        "net.update-failed",
        Cause.UPDATE_FAILED,
        (
            upstream("doUpdate() failed completely", "DistUpgradeController.doUpdate"),
            upstream(
                "openCache() failed: '%s'",
                "DistUpgradeController.openCache",
                "error",
            ),
        ),
        "refreshing the package lists failed",
        Severity.HIGH,
        22,
    ),
    # -- upgrader internals ---------------------------------------------
    (
        "upgrader.view-depends",
        Cause.VIEW_DEPENDS_MISSING,
        (
            upstream("checkViewDepends() failed", "DistUpgradeController.run"),
            upstream(
                "depends '%s' is not satisfied",
                "DistUpgradeController._checkDep",
                "dependency",
            ),
            upstream("No view can be imported, aborting", "DistUpgrade.main"),
        ),
        "the upgrader's own frontend dependencies are not satisfied",
        Severity.HIGH,
        30,
    ),
    (
        "upgrader.python-symlink",
        Cause.PYTHON_SYMLINK_BROKEN,
        (
            upstream(
                "pythonSymlinkCheck() failed, aborting",
                "DistUpgradeController._pythonSymlinkCheck",
            ),
        ),
        "/usr/bin/python3 does not point where the upgrader expects",
        Severity.HIGH,
        31,
    ),
    (
        "upgrader.downgrade",
        Cause.UNSUPPORTED_UPGRADE_PATH,
        (
            upstream(
                "Packages to downgrade found: '%s'",
                "DistUpgradeCache._checkForDowngrades",
                "packages",
            ),
        ),
        "the upgrade would downgrade packages: {packages}",
        Severity.HIGH,
        32,
    ),
    (
        "upgrader.post-install-script",
        Cause.POST_INSTALL_SCRIPT_ERROR,
        (
            upstream(
                "got error from PostInstallScript %s (%s)",
                "DistUpgradeController._runPostInstallScripts",
                "script",
                "error",
            ),
        ),
        "a post-install script failed: {script}",
        Severity.MEDIUM,
        33,
    ),
    (
        "upgrader.broken-after-upgrade",
        Cause.BROKEN_PACKAGES_AFTER_UPGRADE,
        (
            upstream(
                "Broken packages after upgrade: %s",
                "DistUpgradeController.doPostUpgrade",
                "packages",
            ),
        ),
        "packages were left broken after the upgrade finished: {packages}",
        Severity.HIGH,
        34,
    ),
)


def _register_pattern_rules() -> None:
    """Build a rule per entry in the table above.

    Generated rather than hand-written so that adding an upstream string is a
    one-line change and cannot accidentally skip the provenance or the
    evidence indices.
    """
    for name, cause, patterns, template, severity, priority in _ENVIRONMENT_RULES:
        _make_rule(name, cause, patterns, template, severity, priority)


def _make_rule(
    name: str,
    cause: Cause,
    patterns: Sequence[ErrorPattern],
    template: str,
    severity: Severity,
    priority: int,
) -> None:
    sources = "; ".join(sorted({p.source for p in patterns}))

    def check(context: RuleContext) -> Sequence[Finding]:
        for pattern in patterns:
            for message in context.error_messages:
                match = pattern.pattern.search(message)
                if match is None:
                    continue
                captured = {
                    key: (value or "").strip() for key, value in (match.groupdict() or {}).items()
                }
                try:
                    summary = template.format(**captured)
                except (KeyError, IndexError):
                    summary = template
                return (
                    context.finding(
                        rule=name,
                        cause=cause,
                        summary=summary,
                        severity=severity,
                        confidence=Confidence.STRONG,
                        evidence=context.event_indices(match.group(0)[:40])[:4],
                        detail={**captured, "upstream": sources},
                    ),
                )
        return ()

    rule(
        name,
        cause,
        priority=priority,
        severity=severity,
        confidence=Confidence.STRONG,
        provenance=sources,
    )(check)


_register_pattern_rules()


# ---------------------------------------------------------------------------
# Rules that need more than a pattern match
# ---------------------------------------------------------------------------

#: apt's own ``E:`` text for an interrupted dpkg, from libapt-pkg.
_DPKG_INTERRUPTED_RE: Final = re.compile(
    r"dpkg was interrupted, you must manually run", re.IGNORECASE
)


@rule(
    "dpkg.interrupted",
    Cause.DPKG_INTERRUPTED,
    priority=5,
    severity=Severity.HIGH,
    confidence=Confidence.CERTAIN,
    phase_hint="CACHE_OPEN",
    provenance="libapt-pkg: 'dpkg was interrupted, you must manually run ...'",
    remedy="Run `sudo dpkg --configure -a` first, then retry the upgrade",
)
def dpkg_interrupted(context: RuleContext) -> Sequence[Finding]:
    """A previous dpkg run left the system half-configured.

    The lowest priority number of any rule, because it is a precondition
    failure: nothing the resolver says about this system is trustworthy while
    dpkg is mid-transaction, and every dependency problem reported alongside is
    a consequence rather than a cause.
    """
    haystack = (*context.apt_errors, *context.error_messages)
    for message in haystack:
        if _DPKG_INTERRUPTED_RE.search(message):
            return (
                context.finding(
                    rule="dpkg.interrupted",
                    cause=Cause.DPKG_INTERRUPTED,
                    summary=("a previous dpkg run was interrupted, so the upgrade could not start"),
                    severity=Severity.HIGH,
                    confidence=Confidence.CERTAIN,
                    evidence=context.event_indices("dpkg was interrupted")[:4],
                    detail={"remedy_command": "sudo dpkg --configure -a"},
                ),
            )
    return ()


@rule(
    "dpkg.failures",
    Cause.DPKG_MAINTSCRIPT_FAILED,
    priority=40,
    severity=Severity.HIGH,
    confidence=Confidence.STRONG,
    phase_hint="COMMIT",
    provenance="apt-term.log, parsed by uru_doctor.parsers.aptterm",
    remedy="Fix the named package's maintainer script, not its dependents",
)
def dpkg_failures(context: RuleContext) -> Sequence[Finding]:
    """Findings for packages dpkg could not process.

    Only roots. A dpkg cascade reports every affected package with equal
    prominence -- ``Errors were encountered while processing:`` lists
    thirty-five names when one package failed and thirty-four merely depended
    on it -- so emitting a finding per name would multiply one fault into
    thirty-five.

    Where a byte-compile or trigger hook named a different package, that
    package is blamed instead. ``python3``'s postinst failing because
    ``llvm-21-tools`` ships a file Python cannot parse is a bug in
    ``llvm-21-tools``, and filing it against ``python3`` wastes everyone's time.
    """
    if context.term is None:
        return ()

    out: list[Finding] = []
    for failure in context.term.roots:
        culprit = failure.culprit or failure.package or failure.archive
        cause = _dpkg_cause(failure.kind)
        victims = tuple(
            context.package(name)
            for block in context.term.blocks
            for name in block.summary
            if name != failure.package
        )

        detail = {
            "action": failure.action,
            "reason": failure.reason,
            "kind": failure.kind,
        }
        if failure.blamed_package:
            detail["named_by_hook"] = failure.blamed_package
            detail["failing_package"] = failure.package
        if failure.conflicting_package:
            detail["conflicts_with"] = failure.conflicting_package
            detail["path"] = failure.conflicting_path
        if failure.exit_status:
            detail["exit_status"] = str(failure.exit_status)

        out.append(
            context.finding(
                rule="dpkg.failures",
                cause=cause,
                summary=_dpkg_summary(failure, culprit, len(victims)),
                severity=Severity.HIGH,
                confidence=Confidence.STRONG,
                root_pkgs=(context.package(culprit),),
                victim_pkgs=victims,
                cascade_size=len(victims),
                phase=Phase.COMMIT,
                detail=detail,
            )
        )
    return out


def _dpkg_cause(kind: str) -> Cause:
    if kind == FailureKind.FILE_CONFLICT:
        return Cause.DPKG_UNPACK_OVERWRITE
    if kind == FailureKind.DEPENDENCY:
        return Cause.DPKG_UNMET_DEPS_UNCONFIGURED
    if kind == FailureKind.UNPACK:
        return Cause.DPKG_UNPACK_OVERWRITE
    return Cause.DPKG_MAINTSCRIPT_FAILED


def _dpkg_summary(failure: object, culprit: str, victims: int) -> str:
    kind = getattr(failure, "kind", "")
    tail = f", leaving {victims} package{'s' if victims != 1 else ''} unconfigured"
    suffix = tail if victims else ""

    if kind == FailureKind.FILE_CONFLICT:
        other = getattr(failure, "conflicting_package", "")
        path = getattr(failure, "conflicting_path", "")
        return f"{culprit} tries to overwrite {path}, which belongs to {other}"
    if kind == FailureKind.UNPACK:
        return f"{culprit} could not be unpacked{suffix}"

    hook = getattr(failure, "blamed_package", "")
    failing = getattr(failure, "package", "")
    if hook and failing and hook != failing:
        return f"{failing}'s maintainer script failed while running a hook from {hook}{suffix}"
    status = getattr(failure, "exit_status", 0)
    status_text = f" (exit status {status})" if status else ""
    return f"{culprit}'s maintainer script failed{status_text}{suffix}"


@rule(
    "upgrader.crash",
    Cause.UPGRADER_CRASH,
    priority=6,
    severity=Severity.HIGH,
    confidence=Confidence.CERTAIN,
    provenance=(
        "apport ProblemType: Crash, with the DuplicateSignature apport computed from the traceback"
    ),
    remedy="Deduplicate on apport's own signature; it is authoritative here",
)
def upgrader_crash(context: RuleContext) -> Sequence[Finding]:
    """The upgrader itself raised.

    Near the top of the order because a traceback explains everything after it.
    Deduplication is free for these: apport already computed a signature from
    the traceback with the temporary directory scrubbed, so there is no need to
    reason about package graphs at all.
    """
    meta = context.meta
    if meta is None or not meta.is_crash:
        return ()

    exception = _exception_line(meta.traceback)
    return (
        context.finding(
            rule="upgrader.crash",
            cause=Cause.UPGRADER_CRASH,
            summary=(f"the upgrader crashed: {exception}" if exception else "the upgrader crashed"),
            severity=Severity.HIGH,
            confidence=Confidence.CERTAIN,
            detail={
                "exception": exception,
                "has_apport_signature": str(bool(meta.duplicate_signature)).lower(),
            },
        ),
    )


def _exception_line(traceback: str) -> str:
    """The last line of a traceback, which names the exception."""
    lines = [line.strip() for line in traceback.splitlines() if line.strip()]
    return lines[-1] if lines else ""


@rule(
    "evidence.truncated",
    Cause.NO_FAILURE_RECORDED,
    priority=900,
    severity=Severity.INFO,
    confidence=Confidence.CERTAIN,
    provenance="uru_doctor.ingest._evidence_complete",
    remedy="Ask the reporter for the complete logs before triaging further",
    requires_complete_evidence=False,
)
def truncated_evidence(context: RuleContext) -> Sequence[Finding]:
    """Say so when the logs do not record an ending.

    The single most important rule in the file, and the only one whose output
    is a refusal. Bug 2169028's ``main.log`` stops at
    ``Quirks.PreDistUpgradeCache`` with no error and no abort; its resolver
    trace is full of genuine conflicts, so every other rule has plenty to say
    and all of it is speculation about why the run ended.

    Fires last so it appears as a caveat alongside the findings rather than
    instead of them -- the resolver roots are still the most useful thing on
    such a bug, provided nobody claims they are the cause.
    """
    run = context.run
    if run.evidence_complete:
        return ()

    missing = [
        source.value for source in (LogSource.MAIN, LogSource.APT) if source not in run.logs_present
    ]
    reason = (
        f"logs not provided: {', '.join(missing)}"
        if missing
        else f"the log stops during {run.terminal_phase.name} with no error recorded"
    )
    return (
        context.finding(
            rule="evidence.truncated",
            cause=Cause.NO_FAILURE_RECORDED,
            summary=f"no failure was recorded -- {reason}",
            severity=Severity.INFO,
            confidence=Confidence.CERTAIN,
            detail={
                "terminal_phase": run.terminal_phase.name,
                "logs_present": ", ".join(s.value for s in run.logs_present),
            },
        ),
    )
