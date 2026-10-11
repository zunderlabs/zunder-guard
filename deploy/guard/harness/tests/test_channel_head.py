import hashlib
import io
import urllib.error
from email.message import Message
from typing import Any

import pytest

from guard_harness import channel_head
from guard_harness.attestation import AttestationError


@pytest.mark.parametrize(
    "outcome", ["present", "absent", "redirect", "forbidden", "bad-digest", "oversize"]
)
def test_channel_read_distinguishes_absent_from_unknown(
    monkeypatch: pytest.MonkeyPatch, outcome: str
) -> None:
    body = b'{"manifest_sha256":"' + b"a" * 64 + b'"}'

    class Response(io.BytesIO):
        status = 200
        headers = {"x-zunder-state-sha256": hashlib.sha256(body).hexdigest()}

    class Opener:
        def open(self, request: Any, *, timeout: int) -> Response:
            assert request.full_url == "https://zunderlabs.com/guard/release-staging.json"
            assert request.headers == {"User-agent": "zunder-guard-release/1.0"}
            assert timeout == 30
            if outcome in {"absent", "redirect", "forbidden"}:
                code = {"absent": 404, "redirect": 302, "forbidden": 403}[outcome]
                raise urllib.error.HTTPError(request.full_url, code, "fixture", Message(), None)
            response = Response(body if outcome != "oversize" else b"x" * 65537)
            if outcome == "bad-digest":
                response.headers = {"x-zunder-state-sha256": "b" * 64}
            return response

    monkeypatch.setattr(
        "guard_harness.channel_head.urllib.request.build_opener", lambda handler: Opener()
    )
    if outcome == "present":
        assert channel_head.read("staging") == (
            hashlib.sha256(body).hexdigest(),
            {"manifest_sha256": "a" * 64},
        )
    elif outcome == "absent":
        assert channel_head.read("staging") == (None, None)
    else:
        with pytest.raises(AttestationError):
            channel_head.read("staging")
