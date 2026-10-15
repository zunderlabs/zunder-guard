import json
import re
from pathlib import Path
from typing import Any

import pytest

import guard_harness.attestation as attestation
from guard_harness.runner import RunError, RunResult

TYPE = "https://example.com/predicate/v1"


def verify(
    tmp_path: Path, *, run_id: str | None = None, attempt: str | None = None
) -> attestation.VerifiedPredicate:
    return attestation.verify_predicate(
        tmp_path / "manifest.json",
        tmp_path / "bundle.json",
        workflow="verify.yml",
        commit="a" * 40,
        tag="v1.0.0",
        predicate_type=TYPE,
        log=tmp_path / "verification.log",
        expected_run_id=run_id,
        expected_run_attempt=attempt,
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
        {
            "verificationResult": {
                "statement": {"predicateType": TYPE, "predicate": {"revision": 1}},
                "signature": {
                    "certificate": {
                        "runInvocationURI": "https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/2"
                    }
                },
            }
        }
    ]
    install_verifier(monkeypatch, tmp_path, result)
    verified = verify(tmp_path)
    assert verified.predicate == {"revision": 1}
    assert verified.source_commit == "a" * 40
    assert verified.workflow == "verify.yml"
    assert verified.run_id == "123" and verified.run_attempt == "2"


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


def authenticated(uri: object) -> list[dict[str, Any]]:
    return [
        {
            "verificationResult": {
                "statement": {"predicateType": TYPE, "predicate": {"revision": 1}},
                "signature": {"certificate": {"runInvocationURI": uri}},
            }
        }
    ]


@pytest.mark.parametrize("run_id,attempt", [("123", "2"), (None, None)])
def test_exact_invocation_from_official_verified_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, run_id: str | None, attempt: str | None
) -> None:
    uri = "https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/2"
    install_verifier(monkeypatch, tmp_path, authenticated(uri))
    value = verify(tmp_path, run_id=run_id, attempt=attempt)
    assert value.invocation_uri == uri and value.run_id == "123" and value.run_attempt == "2"


@pytest.mark.parametrize(
    "uri",
    [
        "https://github.com/zunderlabs/zunder-guard/actions/runs/124/attempts/2",
        "https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/3",
    ],
)
def test_same_commit_predicate_from_other_run_or_attempt_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uri: str
) -> None:
    install_verifier(monkeypatch, tmp_path, authenticated(uri))
    with pytest.raises(attestation.AttestationError, match="differs from expected invocation"):
        verify(tmp_path, run_id="123", attempt="2")


@pytest.mark.parametrize(
    "uri",
    [
        None,
        {},
        123,
        "https://github.com/other/repo/actions/runs/123/attempts/2",
        "https://github.com/zunderlabs/zunder-guard/actions/runs/0123/attempts/2",
        "https://github.com/zunderlabs/zunder-guard/actions/runs/123",
        "https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/2?run=123",
        "https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/2\n",
    ],
)
def test_missing_or_noncanonical_verified_invocation_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uri: object
) -> None:
    install_verifier(monkeypatch, tmp_path, authenticated(uri))
    with pytest.raises(attestation.AttestationError):
        verify(tmp_path, run_id="123", attempt="2")


def test_raw_bundle_and_predicate_run_claims_cannot_replace_verified_certificate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    uri = "https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/2"
    response = authenticated(uri)
    result = response[0]["verificationResult"]
    del result["signature"]
    result["statement"]["predicate"]["runInvocationURI"] = uri
    response[0]["attestation"] = {"certificate": {"runInvocationURI": uri}}
    install_verifier(monkeypatch, tmp_path, response)
    with pytest.raises(
        attestation.AttestationError, match="verified certificate invocation URI missing"
    ):
        verify(tmp_path, run_id="123", attempt="2")


@pytest.mark.parametrize("run_id,attempt", [("123", None), (None, "2"), ("0", "2"), ("123", "02")])
def test_expected_invocation_must_be_complete_canonical_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, run_id: str | None, attempt: str | None
) -> None:
    monkeypatch.setattr(
        attestation, "run", lambda *args, **kwargs: pytest.fail("must validate first")
    )
    with pytest.raises(attestation.AttestationError, match="paired canonical positive IDs"):
        verify(tmp_path, run_id=run_id, attempt=attempt)


def verify_latest(
    tmp_path: Path, *, run_id: str | None, latest: str, attempt: str | None = None
) -> attestation.VerifiedPredicate:
    return attestation.verify_predicate(
        tmp_path / "manifest.json",
        tmp_path / "bundle.json",
        workflow="verify.yml",
        commit="a" * 40,
        tag="v1.0.0",
        predicate_type=TYPE,
        log=tmp_path / "verification.log",
        expected_run_id=run_id,
        expected_run_attempt=attempt,
        latest_run_attempt=latest,
    )


@pytest.mark.parametrize("signed", ["1", "2", "3"])
def test_latest_attempt_admits_any_earlier_attempt_of_the_same_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, signed: str
) -> None:
    uri = f"https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/{signed}"
    install_verifier(monkeypatch, tmp_path, authenticated(uri))
    value = verify_latest(tmp_path, run_id="123", latest="3")
    assert (value.run_id, value.run_attempt) == ("123", signed)


@pytest.mark.parametrize(
    "uri",
    [
        "https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/4",
        "https://github.com/zunderlabs/zunder-guard/actions/runs/123/attempts/10",
        "https://github.com/zunderlabs/zunder-guard/actions/runs/124/attempts/1",
    ],
)
def test_latest_attempt_refuses_later_attempt_or_other_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uri: str
) -> None:
    install_verifier(monkeypatch, tmp_path, authenticated(uri))
    with pytest.raises(attestation.AttestationError, match="attempt follows the expected"):
        verify_latest(tmp_path, run_id="123", latest="3")


@pytest.mark.parametrize(
    "run_id,latest,attempt,message",
    [
        ("123", "3", "2", "exclusive"),
        (None, "3", None, "paired canonical"),
        ("123", "03", None, "paired canonical"),
        ("123", "0", None, "paired canonical"),
    ],
)
def test_latest_attempt_requires_a_run_and_excludes_an_exact_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    run_id: str | None,
    latest: str,
    attempt: str | None,
    message: str,
) -> None:
    monkeypatch.setattr(
        attestation, "run", lambda *args, **kwargs: pytest.fail("must validate first")
    )
    with pytest.raises(attestation.AttestationError, match=message):
        verify_latest(tmp_path, run_id=run_id, latest=latest, attempt=attempt)
