from typing import Any

import pytest

from guard_harness.template_target import validate


@pytest.mark.parametrize("tag", ["v1.0.0-rc.7", "v1.0.0"])
def test_exact_signed_destination_required_before_credentials(tag: str) -> None:
    config = dict(
        tag=tag,
        role="fixture-role",
        bucket="fixture-bucket",
        region="ap-northeast-1",
        base="https://fixture-bucket.s3.ap-northeast-1.amazonaws.com",
    )
    build: dict[str, Any] = {
        "tag": tag,
        "distribution": {
            "aws_template": {"url": config["base"] + "/guard/" + tag + "/cloudformation.yaml"}
        },
    }
    validate(build, **config)
    for field, value in (
        ("role", ""),
        ("bucket", "other-bucket"),
        ("region", "eu-west-1"),
        ("base", "https://other.example.test"),
        ("tag", "v2.0.0"),
    ):
        with pytest.raises(ValueError):
            validate(build, **{**config, field: value})
    build["distribution"]["aws_template"]["url"] = "https://other.example.test/cloudformation.yaml"
    with pytest.raises(ValueError):
        validate(build, **config)
