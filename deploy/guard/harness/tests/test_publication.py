import hashlib
import io
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

import guard_harness.publication as publisher
from guard_harness.attestation import AttestationError
from guard_harness.state_verifier import VerifiedState


@pytest.fixture
def source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    manifest: dict[str, Any] = {"assets": {}}
    for name, content in {"i": b"unix\n", "i.ps1": b"windows\r\n"}.items():
        (tmp_path / name).write_bytes(content)
        manifest["assets"][name] = {"sha256": hashlib.sha256(content).hexdigest()}
    (tmp_path / "release-manifest.json").write_text(json.dumps(manifest))
    (tmp_path / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ["release-manifest.json", "i", "i.ps1"]
        )
    )
    (tmp_path / "SHA256SUMS.sigstore.json").write_text('"fixture-signature"')
    state = {"stage": "staged"}
    (tmp_path / "state.json").write_text(json.dumps(state))
    (tmp_path / "state.sigstore.json").write_text('"fixture-bundle"')
    calls: list[str] = []

    def signature(argv: list[str], **kwargs: Any) -> None:
        assert argv[0:2] == ["cosign", "verify-blob"]
        assert (
            "https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/v1.0.0"
            in argv
        )
        calls.append("signature")

    def authenticate(*args: Any, **kwargs: Any) -> VerifiedState:
        assert "signature" in calls
        assert args[0].read_bytes() == (tmp_path / "release-manifest.json").read_bytes()
        calls.append("state")
        return VerifiedState(json.loads(args[1].read_bytes()), "a" * 64)

    monkeypatch.setattr(publisher, "run", signature)
    monkeypatch.setattr(publisher, "authenticate_state", authenticate)
    monkeypatch.setattr(publisher, "authenticate_gate", authenticate)
    return {
        "assets": tmp_path,
        "served": tmp_path / "state.json",
        "state_bundle": tmp_path / "state.sigstore.json",
        "manifest_schema": tmp_path / "schema",
        "state_schema": tmp_path / "schema",
        "commit": "b" * 40,
        "tag": "v1.0.0",
        "workflow": "verify.yml",
        "previous": None,
        "expected": None,
        "journeys": {},
        "logs": tmp_path / "logs",
    }


def test_publication_preserves_signed_loader_bytes(source: dict[str, Any]) -> None:
    value = publisher.prepare(**source)
    capsule = json.loads(value.body)
    assert capsule["windows"] == "windows\r\n"
    assert capsule["unix"] == "unix\n"
    assert capsule["bundle"] == '"fixture-bundle"'
    assert capsule["channel"] == "staging" and capsule["expected"] is None
    assert hashlib.sha256(capsule["predicate"].encode()).hexdigest() == value.digest


@pytest.mark.parametrize("name", ["i", "i.ps1", "release-manifest.json"])
def test_changed_signed_bytes_refused(source: dict[str, Any], name: str) -> None:
    (source["assets"] / name).write_bytes(b"tampered")
    with pytest.raises(AttestationError, match="signed checksums"):
        publisher.prepare(**source)


def test_unsigned_checksum_change_refused(
    source: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    def refused(*args: Any, **kwargs: Any) -> None:
        raise AttestationError("signature refused")

    monkeypatch.setattr(publisher, "run", refused)
    with pytest.raises(AttestationError, match="signature refused"):
        publisher.prepare(**source)


def test_duplicate_signed_checksum_refused(source: dict[str, Any]) -> None:
    sums = source["assets"] / "SHA256SUMS"
    sums.write_text(sums.read_text() * 2)
    with pytest.raises(AttestationError, match="duplicate"):
        publisher.prepare(**source)


@pytest.mark.parametrize(
    "stage,prior,channel",
    [
        ("gated", "staged", "staging"),
        ("promoted", "gated", "canonical"),
        ("withdrawn", "promoted", "canonical"),
        ("withdrawn", "staged", "staging"),
    ],
)
def test_verified_lifecycle_selects_channel(
    source: dict[str, Any],
    stage: str,
    prior: str,
    channel: str,
) -> None:
    source["served"].write_text(json.dumps({"stage": stage}))
    source["previous"] = VerifiedState({"stage": prior}, "a" * 64)
    source["expected"] = "c" * 64
    value = publisher.prepare(**source)
    assert json.loads(value.body)["channel"] == channel
    assert json.loads(value.body)["expected"] == "c" * 64


def test_gate_requires_authenticated_predecessor(source: dict[str, Any]) -> None:
    source["served"].write_text('{"stage":"promoted"}')
    with pytest.raises(AttestationError, match="predecessor"):
        publisher.prepare(**source)


@pytest.mark.parametrize("expected", ["", "wrong", "A" * 64])
def test_bad_expected_head_refused(source: dict[str, Any], expected: str) -> None:
    source["expected"] = expected
    with pytest.raises(AttestationError, match="channel head"):
        publisher.prepare(**source)


class Reply(io.BytesIO):
    status = 201


@pytest.mark.parametrize(
    "receipt", [b'{"digest":"wrong"}', b"not-json", b'{"digest":"' + b"a" * 64 + b'","extra":1}']
)
def test_bad_receipt_is_unknown_outcome(monkeypatch: pytest.MonkeyPatch, receipt: bytes) -> None:
    class Opener:
        def open(self, request: Any, **kwargs: Any) -> Reply:
            assert request.full_url == "https://zunderlabs.com/guard/publish"
            assert request.get_header("Authorization") == "Bearer fixture-credential"
            return Reply(receipt)

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(AttestationError, match="outcome unknown"):
        publisher.publish(publisher.Publication(b"{}", "a" * 64), token="fixture-credential")


def test_network_failure_withholds_server_and_request_details(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Opener:
        def open(self, request: Any, **kwargs: Any) -> Reply:
            raise urllib.error.URLError("fixture-credential plus private server response")

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(AttestationError) as caught:
        publisher.publish(publisher.Publication(b"{}", "a" * 64), token="fixture-credential")
    assert "fixture-credential" not in str(caught.value)
    assert caught.value.__suppress_context__


def test_receipt_matches_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    class Opener:
        def open(self, request: Any, **kwargs: Any) -> Reply:
            assert kwargs["timeout"] == 45
            assert request.get_header("User-agent") == "zunder-guard-release/1.0"
            return Reply(json.dumps({"digest": "a" * 64}).encode())

    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    assert publisher.publish(publisher.Publication(b"{}", "a" * 64), token="fixture") == "a" * 64


def test_redirect_handler_never_forwards_credentials() -> None:
    request = urllib.request.Request("https://zunderlabs.com/guard/publish")
    handler = publisher._NoRedirect()
    result = handler.redirect_request(request, None, 307, "", {}, "https://other.example")
    assert result is None


def test_loader_descriptor_must_match_signed_loader(source: dict[str, Any]) -> None:
    manifest = source["assets"] / "release-manifest.json"
    build = json.loads(manifest.read_bytes())
    build["assets"]["i"]["sha256"] = "f" * 64
    manifest.write_text(json.dumps(build))
    sums = source["assets"] / "SHA256SUMS"
    lines = sums.read_text().splitlines()
    lines[0] = f"{hashlib.sha256(manifest.read_bytes()).hexdigest()}  release-manifest.json"
    sums.write_text("\n".join(lines) + "\n")
    with pytest.raises(AttestationError, match="immutable build descriptor"):
        publisher.prepare(**source)


def test_lifecycle_authentication_failure_refuses_publication(
    source: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refused(*args: Any, **kwargs: Any) -> VerifiedState:
        raise AttestationError("unauthenticated lifecycle")

    monkeypatch.setattr(publisher, "authenticate_state", refused)
    with pytest.raises(AttestationError, match="unauthenticated lifecycle"):
        publisher.prepare(**source)


@pytest.mark.parametrize("token", ["", "bad\ncredential", "bad credential"])
def test_bad_token_never_opens_connection(monkeypatch: pytest.MonkeyPatch, token: str) -> None:
    def forbidden(*args: Any) -> Any:
        pytest.fail("invalid credential attempted a connection")

    monkeypatch.setattr(urllib.request, "build_opener", forbidden)
    with pytest.raises(ValueError, match="token"):
        publisher.publish(publisher.Publication(b"{}", "a" * 64), token=token)
