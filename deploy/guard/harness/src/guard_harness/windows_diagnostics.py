"""Finite Windows lifecycle failure observations; never receipts or raw output."""

import re
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from guard_harness.runner import RunError

STEPS = frozenset(
    {
        "per-user-lifecycle",
        "per-user-readiness",
        "per-user-shutdown",
        "per-user-journal-audit",
        "crash-policy-prepare",
        "scm-install",
    }
)
REFUSALS = {
    "stored-key per-user runtime exited": "per-user-runtime-exited",
    "per-user testnet identity mismatch": "per-user-identity-mismatch",
    "per-user testnet readiness deadline": "per-user-readiness-deadline",
    "candidate crash-policy refusal probe did not complete": "crash-policy-probe-incomplete",
    "candidate did not emit the exact crash-policy refusal": "crash-policy-refusal-mismatch",
    "cannot read hosted Windows crash policy": "crash-policy-unreadable",
    "cannot remove hosted Windows crash policy": "crash-policy-removal-failed",
    "hosted crash-policy removal did not confirm four absent keys": "crash-policy-still-present",
}


# Explicit literals from the signed Windows loader/helper. No paths, SIDs, accounts,
# rights masks, exception details or input fragments are copied into observations.
# This frozen allow-list is diagnostic only; it never admits a lifecycle or a receipt.
INSTALLER_WRAPPER = (
    "Verified service helper did not complete. Organization execution policy "
    "remains authoritative; no policy was changed. Inspect the preceding error "
    "and use the retained helper Status/Resume only for an owned pending setup."
)
INSTALLER_REFUSALS = frozenset(
    {
        "A transaction is pending; use its exact retained helper Resume.",
        "Archive member exceeds installer size bound.",
        "Binding differs from owned transaction.",
        "Broker identity mismatch.",
        "Builder fee readiness fields must be present booleans.",
        "Case-colliding signed asset refused.",
        "Completed lifecycle: use explicit Upgrade or Start; loader never reinitializes.",
        "Configuration or journal changed during disabled upgrade; no rollback of state attempted.",
        "Consumed asset must appear exactly once in signed checksums.",
        "Different licence supplied on resume; use explicit service licence-set.",
        "Equity cap is outside the existing mainnet ceiling.",
        "Equity cap must be a decimal string.",
        "Exact explicit ConfirmAccount is required.",
        "Exact stable or release candidate tag required.",
        "Executable differs from admitted binding.",
        "Existing journal is never initialized again or resumed automatically.",
        "Existing machine file entry refused.",
        "Existing transaction identity differs; nothing was changed.",
        "Explicit Startup Manual or DelayedAuto is required; no default activation.",
        "Explicit account/confirmation and decimal cap required.",
        "Explicit human review note required.",
        "Explicit repeated account confirmation did not match.",
        "Explicit scoped journal initialization is required.",
        "Fee-free status requires an active licence.",
        "Guard public metadata validation failed.",
        "Guard refused this lifecycle step; no following step was performed.",
        "Image rollback requires explicit pre-start upgrade recovery and unchanged journal.",
        "Initialized Testnet risk journal is missing; no reset permitted.",
        "Instance already exists. Use retained helper Resume/Upgrade; never Force or reinitialize.",
        "Interrupted activation left disabled. Review Status and explicitly Start again.",
        "Invalid instance ID.",
        "Invalid public licence key.",
        "Invalid rules code.",
        "Invalid service instance Id.",
        "Journal changed while quiescing; rollback refused.",
        "Journal not committed; explicitly invoke JournalInit with a review note.",
        "Listener is not the admitted broker child.",
        "Listener virtual account differs.",
        "Loopback readiness request did not succeed.",
        "Machine file absence could not be admitted.",
        "Main account must have 40 hex digits.",
        "Mainnet needs an elevated interactive console; EOF or cancellation never confirms setup.",
        "Mainnet refuses NonInteractive, KeyStdin, InstallOnly, Force and alternate InstallDir.",
        "Mainnet requires native Windows x64 PowerShell.",
        "Mainnet runtime cannot report paper fee state.",
        "Mainnet service readiness must use explicit loopback IP.",
        "Malformed signed checksum line refused.",
        "Missing old binding backup and unexpected active binding.",
        "Missing old image backup and unexpected active digest.",
        "Missing or reparse machine path refused.",
        "Missing or unsupported builder approval state.",
        "NUL in SCM argument refused; transaction remains pending.",
        "New admitted release digest changed.",
        "No owned transaction. Refusing to adopt existing state.",
        "No unique owned loopback listener.",
        "Noncanonical machine file refused.",
        "Noncanonical machine path refused.",
        "Old binding backup changed.",
        "Old image backup changed.",
        (
            "Open a trusted elevated PowerShell window explicitly; the loader will not "
            "elevate a downloaded script."
        ),
        "Oversized owned transaction refused.",
        "Oversized readiness response.",
        "Oversized transaction refused.",
        "Owned executable still has a live process; no mutation permitted.",
        (
            "Owned runtime did not meet mainnet/account/risk/licence readiness; service "
            "is being disabled."
        ),
        "Owned service must be stopped with startup Disabled.",
        "Partial installation image differs from transaction.",
        (
            "Pending transaction belongs to another release. Use its retained helper "
            "Status/Resume; no service was changed."
        ),
        "Pinned verifier checksum mismatch.",
        "Prepared service metadata differs from transaction.",
        "Private unattended key input is Testnet Prepare/Resume only.",
        "Protected Testnet key setup requires explicit private redirected stdin.",
        "Protected Testnet requires NonInteractive, private KeyStdin and the machine installation.",
        "Protected Testnet requires explicit account, repeated account, equity cap and rules.",
        "Recovered API wallet differs from transaction.",
        "Recovery backup does not match durable admission.",
        "Release signature verification failed.",
        "Release source must be HTTPS or an offline release directory.",
        "Reparse ACL target refused.",
        "Required executable or notice missing.",
        "Resume must use the exact transaction release cache.",
        "Retained lifecycle helper changed.",
        "Running lifecycle helper is not the signed release helper.",
        "Runtime changed during readiness proof.",
        "Runtime equity cap differs.",
        "Runtime has no fresh synchronization for this start.",
        "Runtime mainnet/account/risk admission not ready.",
        "Runtime readiness field missing.",
        "Runtime risk readiness requires boolean fields.",
        "Runtime schema must be an integer.",
        "Runtime start timestamp must be an integer.",
        "Runtime synchronization timestamp must be an integer.",
        "Runtime version/status schema differs from admitted release.",
        "SCM broker not running.",
        "SCM client cleanup failed; transaction remains pending.",
        "SCM client could not start; transaction remains pending.",
        "SCM client did not exit after termination.",
        "SCM client timed out; transaction remains pending.",
        "SCM did not disable startup.",
        "SCM operation failed; transaction remains pending.",
        "SCM registration is not this owned installation.",
        "Signed release asset checksum mismatch.",
        "Testnet cannot adopt a Mainnet journal transaction.",
        (
            "Testnet journal is created only during fresh init; no reinitialization or "
            "automatic resume."
        ),
        "Testnet requires a separate testnet- instance identity.",
        "Testnet requires fee mode off or an active fee-free licence.",
        "Transaction account differs from explicit confirmation.",
        "Transaction belongs to another sending network; adoption refused.",
        "Transaction identity or phase is ambiguous; refuse recovery.",
        (
            "Uncommitted config staging exists. Retained helper Status/Resume requires "
            "manual inspection; no init or deletion repeated."
        ),
        "Uninstalled instance data is retained; automatic adoption/reinitialization is refused.",
        "Unknown interrupted image state.",
        "Unknown transaction operation.",
        "Unsafe, repeated or unexpected archive member.",
        "Unsupported fee mode; trading readiness cannot be established.",
        "Unsupported owned sending network.",
        "Unsupported protected service network.",
        "Upgrade needs an owned installed instance.",
        "Use the exact retained helper named by this transaction.",
        "Validated licence is not active/fee-free in this runtime.",
        "Verified binary does not report the release version.",
        "Windows mainnet requires native x64, not ARM emulation.",
    }
)
PATH_KINDS = ("drive-root", "program-data-root", "program-files-root", "protected-path")
INSTALLER_REFUSALS |= frozenset(
    f"Untrusted machine path owner ({kind}, owner={owner})."
    for kind in PATH_KINDS
    for owner in ("current-user", "other")
)
INSTALLER_REFUSALS |= frozenset(
    f"Organization {scope} execution policy is {policy} and prevents this Sigstore-verified "
    "helper. No policy was changed; contact the policy administrator."
    for scope in ("MachinePolicy", "UserPolicy")
    for policy in ("Restricted", "AllSigned")
)
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
ERROR_PREFIX = re.compile(
    r"^(?:.*\.ps1\s*:\s*|(?:Exception|Write-Error):\s*|"
    r"\+\s*FullyQualifiedErrorId\s*:\s*)"
)


def installer_refusal(stderr: str) -> str:
    """Recognize PS5.1/PS7 error payloads; return only a frozen, public literal.

    PS7 decorates/wraps payload lines with a pipe; PS5.1 prefixes the script
    filename and wraps long messages. Source excerpts, unknown messages and
    appended private data cannot match a complete allow-listed payload.
    """
    lines = []
    for line in ANSI.sub("", stderr[:65536]).splitlines():
        line = line.strip()
        line = re.sub(r"^\|\s*", "", line)
        lines.append(ERROR_PREFIX.sub("", line).strip())
    wrapper = False
    for index in range(len(lines)):
        # Bounded unfolding, returning the allow-list value rather than captured text.
        for count in range(1, 9):
            payload = " ".join(lines[index : index + count])
            if payload in INSTALLER_REFUSALS:
                return next(message for message in INSTALLER_REFUSALS if message == payload)
            for kind in PATH_KINDS:
                if re.fullmatch(
                    re.escape(f"Unprivileged machine path mutation rights refused ({kind}, rights=")
                    + r"[0-9a-f]{8}\)\.",
                    payload,
                ):
                    return (
                        f"Unprivileged machine path mutation rights refused ({kind}, "
                        "rights withheld)."
                    )
            wrapper |= payload == INSTALLER_WRAPPER
    return INSTALLER_WRAPPER if wrapper else "unknown"


def reason(error: Exception) -> str:
    if isinstance(error, ModuleNotFoundError) and error.name == "pwd":
        return "posix-pwd-unavailable"
    if isinstance(error, subprocess.TimeoutExpired):
        return "command-timeout"
    if isinstance(error, RunError):
        return "command-failed"
    # Return only a literal from this table; exception details never enter artifacts.
    return REFUSALS.get(str(error), "unknown")


@contextmanager
def observe(
    work: Path, step: str, *, installer: bool = False
) -> Iterator[Callable[[str], str] | None]:
    step = step if step in STEPS else "unknown"
    capture = installer and step == "scm-install"
    refusal = "unknown"

    def classify(stderr: str) -> str:
        nonlocal refusal
        refusal = installer_refusal(stderr)
        return "unknown"  # runner's finite category; the literal lives only in this observation.

    try:
        yield classify if capture else None
    except Exception as error:
        work.mkdir(parents=True, exist_ok=True)
        (work / f"windows-{step}-failure.log").write_text(
            f"Windows lifecycle failure step: {step}\nfailure reason: {reason(error)}\n"
            + (
                f"installer refusal: {refusal if isinstance(error, RunError) else 'unknown'}\n"
                if capture
                else ""
            )
        )
        raise
