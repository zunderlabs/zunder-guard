import json
import re
from pathlib import Path
from typing import Any

import pytest

import guard_harness.attestation as attestation
from guard_harness.runner import RunError, RunResult

TYPE = "https://example.com/predicate/v1"


def verify(tmp_path: Path) -> attestation.VerifiedPredicate:
    return attestation.verify_predicate(
        tmp_path / "manifest.json",
        tmp_path / "bundle.json",
        workflow="verify.yml",
        commit="a" * 40,
        tag="v1.0.0",
        predicate_type=TYPE,
        log=tmp_path / "verification.log",
    )


def install_verifier(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: Any) -> None:
    def fake_run(argv: list[str], *, log: Path, timeout: int) -> RunResult:
        assert argv[:3] == ["gh", "attestation", "verify"]
        # These are the verifier's trust boundaries, not a workflow text assertion.
        assert argv[argv.index("--repo") + 1] == attestation.REPOSITORY
        identity = argv[argv.index("--cert-identity-regex") + 1]
        assert "--signer-workflow" not in argv
        assert "--signer-repo" not in argv
        assert "--cert-identity" not in argv
        base = f"https://github.com/{attestation.REPOSITORY}/.github/workflows/verify.yml@"
        assert re.fullmatch(identity, base + "refs/tags/v1.0.0")
        assert re.fullmatch(identity, base + "refs/heads/main")
        for refused in (
            base + "refs/heads/preview/topic",
            base + "refs/tags/v1.0.1",
            base + "refs/tags/v1.0.0-extra",
            base.replace("verify.yml", "release.yml") + "refs/tags/v1.0.0",
            base.replace("zunderlabs", "other-owner") + "refs/tags/v1.0.0",
        ):
            assert re.fullmatch(identity, refused) is None
        assert argv[argv.index("--source-digest") + 1] == "a" * 40
        assert "--deny-self-hosted-runners" in argv
        assert argv[argv.index("--predicate-type") + 1] == TYPE
        assert (
            argv[argv.index("--cert-oidc-issuer") + 1]
            == "https://token.actions.githubusercontent.com"
        )
        assert timeout == 60
        return RunResult(0, json.dumps(response), log)

    monkeypatch.setattr(attestation, "run", fake_run)


def test_reads_only_authenticated_predicate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    result = [
        {"verificationResult": {"statement": {"predicateType": TYPE, "predicate": {"revision": 1}}}}
    ]
    install_verifier(monkeypatch, tmp_path, result)
    verified = verify(tmp_path)
    assert verified.predicate == {"revision": 1}
    assert verified.source_commit == "a" * 40
    assert verified.workflow == "verify.yml"


@pytest.mark.parametrize(
    "response",
    [
        [],
        {},
        [{"attestation": {"predicate": {"result": "pass"}}}],
        [{"verificationResult": {"statement": {"predicateType": "wrong", "predicate": {}}}}],
        [{"verificationResult": {"statement": {"predicateType": TYPE, "predicate": "pass"}}}],
        [{"verificationResult": {}}, {"verificationResult": {}}],
    ],
)
def test_unverified_or_ambiguous_results_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, response: Any
) -> None:
    install_verifier(monkeypatch, tmp_path, response)
    with pytest.raises(attestation.AttestationError):
        verify(tmp_path)


def test_signature_verification_failure_propagates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def fail(*args: Any, **kwargs: Any) -> RunResult:
        raise RunError("bad signature")

    monkeypatch.setattr(attestation, "run", fail)
    with pytest.raises(RunError, match="bad signature"):
        verify(tmp_path)
