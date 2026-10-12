import json
from typing import Any

import pytest

from guard_harness.aws_evidence import CONTEXT, predicate
from guard_harness.lifecycle_coverage import LIFECYCLE_COVERAGE

TAG, COMMIT = "v1.0.0-rc.7", "a" * 40
URL = f"https://example.invalid/guard/{TAG}/cloudformation.yaml"
TEMPLATE_SHA = "c" * 64
MANIFEST = json.dumps(
    {
        "tag": TAG,
        "commit": COMMIT,
        "distribution": {"aws_template": {"url": URL}},
        "assets": {"cloudformation.yaml": {"sha256": TEMPLATE_SHA}},
    }
).encode()


def receipt() -> dict[str, Any]:
    return dict(
        result="passed",
        cleanup_complete=True,
        diagnostic=False,
        tag=TAG,
        commit=COMMIT,
        harness_commit=COMMIT,
        coverage=sorted(LIFECYCLE_COVERAGE["I7"] - CONTEXT),
        template_launch=dict(
            channel="cloudformation",
            template_url=URL,
            template_sha256=TEMPLATE_SHA,
            installer_channel="staging",
            stack_create_complete=True,
            instance_online=True,
        ),
    )


def test_complete_literal_aws_channel_and_cleanup_coverage() -> None:
    value = predicate(receipt(), MANIFEST, tag=TAG, commit=COMMIT)
    assert set(value["coverage"]) == LIFECYCLE_COVERAGE["I7"]
    assert "D6:cloudformation" in value["coverage"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("result", "failed"),
        ("cleanup_complete", False),
        ("diagnostic", True),
        ("commit", "b" * 40),
        ("harness_commit", "b" * 40),
        ("tag", "v1.0.0"),
        ("coverage", []),
        ("coverage", ["signed-template-url"]),
        ("coverage", [None]),
    ],
)
def test_no_partial_or_unbound_aws_credit(field: str, value: object) -> None:
    record = receipt()
    record[field] = value
    with pytest.raises(ValueError):
        predicate(record, MANIFEST, tag=TAG, commit=COMMIT)


@pytest.mark.parametrize(
    "field",
    [
        "channel",
        "template_url",
        "template_sha256",
        "installer_channel",
        "stack_create_complete",
        "instance_online",
    ],
)
def test_literal_d6_cannot_be_derived_without_each_measured_launch_field(field: str) -> None:
    record = receipt()
    del record["template_launch"][field]
    with pytest.raises(ValueError):
        predicate(record, MANIFEST, tag=TAG, commit=COMMIT)


@pytest.mark.parametrize(
    "field,value",
    [
        ("stack_create_complete", 1),
        ("instance_online", 1),
        ("template_url", "https://wrong.invalid/template"),
        ("template_sha256", "d" * 64),
    ],
)
def test_d6_rejects_unmeasured_or_different_template_identity(field: str, value: object) -> None:
    record = receipt()
    record["template_launch"][field] = value
    with pytest.raises(ValueError):
        predicate(record, MANIFEST, tag=TAG, commit=COMMIT)
