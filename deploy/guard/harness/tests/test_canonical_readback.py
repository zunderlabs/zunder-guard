import hashlib
import json
import urllib.error
import urllib.request
from typing import Any

import pytest

from guard_harness import canonical_readback as reader
from guard_harness.attestation import AttestationError
from guard_harness.publication import Publication, _NoRedirect


@pytest.fixture
def publication() -> Publication:
    # Cryptographic admission is publication.prepare's tested responsibility.
    # This fixture represents its captured authenticated output, never live input.
    predicate = json.dumps({"stage": "promoted", "commit": "b" * 40})
    capsule = dict(
        channel="canonical",
        predicate=predicate,
        bundle="signed bundle",
        unix="#!/bin/sh\necho released\n",
        windows="Write-Output released\n",
    )
    return Publication(json.dumps(capsule).encode(), hashlib.sha256(predicate.encode()).hexdigest())


PATHS = {
    "/guard/release.json": "predicate",
    "/guard/release.json.sigstore": "bundle",
    "/i": "unix",
    "/i.ps1": "windows",
}


@pytest.mark.parametrize("bad_path", [None, *PATHS])
@pytest.mark.parametrize("failure", ["status", "digest", "body"])
def test_all_served_bytes_and_headers_bind_to_one_promotion_without_retry(
    publication: Publication,
    bad_path: str | None,
    failure: str,
) -> None:
    capsule = json.loads(publication.body)
    calls: list[str] = []

    def read(path: str) -> reader.Response:
        calls.append(path)
        status, digest, body = 200, publication.digest, capsule[PATHS[path]].encode()
        if path == bad_path:
            if failure == "status":
                status = 302
            elif failure == "digest":
                digest = "a" * 64
            else:
                body += b"\n"  # Same claimed digest does not admit changed bytes.
        return reader.Response(status, digest, body)

    if bad_path is None:
        assert reader.check(publication, read=read) == publication.digest
        assert calls == list(PATHS)
    else:
        with pytest.raises(AttestationError, match="differs"):
            reader.check(publication, read=read)
        assert calls == list(PATHS)[: list(PATHS).index(bad_path) + 1]


@pytest.mark.parametrize("stage", ["staged", "gated", "withdrawn"])
def test_non_promoted_state_never_reads_production(publication: Publication, stage: str) -> None:
    capsule = json.loads(publication.body)
    capsule["predicate"] = json.dumps({"stage": stage})
    predicate = capsule["predicate"].encode()
    value = Publication(json.dumps(capsule).encode(), hashlib.sha256(predicate).hexdigest())
    with pytest.raises(AttestationError, match="promotion"):
        reader.check(value, read=lambda _: pytest.fail("production must not be read"))


def test_wrong_state_digest_never_reads_production(publication: Publication) -> None:
    with pytest.raises(AttestationError, match="digest"):
        reader.check(
            Publication(publication.body, "a" * 64),
            read=lambda _: pytest.fail("production must not be read"),
        )


def test_transport_is_bounded_fixed_origin_get_and_no_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class Reply:
        status = 200
        headers = {"x-zunder-state-sha256": "a" * 64}

        def __enter__(self) -> "Reply":
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def read(self, size: int) -> bytes:
            assert size == reader.LIMIT + 1
            return b"public bytes"

    class Opener:
        def open(self, request: Any, *, timeout: int) -> Reply:
            calls.append(request.full_url)
            assert request.get_method() == "GET" and timeout == 30
            assert request.data is None and request.headers == {}
            return Reply()

    def opener(handler: Any) -> Opener:
        assert isinstance(handler, _NoRedirect)
        assert (
            handler.redirect_request(
                urllib.request.Request("https://zunderlabs.com/i"),
                None,
                302,
                "",
                None,
                "https://other.test",
            )
            is None
        )
        return Opener()

    monkeypatch.setattr(urllib.request, "build_opener", opener)
    assert reader.fetch("/i").body == b"public bytes"
    assert calls == ["https://zunderlabs.com/i"]
    with pytest.raises(AttestationError, match="outside C5"):
        reader.fetch("/api/licence/order/check")
    assert len(calls) == 1


def test_transport_error_is_sanitized_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    class Opener:
        def open(self, *args: Any, **kwargs: Any) -> None:
            nonlocal calls
            calls += 1
            raise urllib.error.URLError("untrusted response diagnostics")

    monkeypatch.setattr(urllib.request, "build_opener", lambda _: Opener())
    with pytest.raises(AttestationError, match="no automatic retry") as error:
        reader.fetch("/guard/release.json")
    assert "untrusted" not in str(error.value) and calls == 1
