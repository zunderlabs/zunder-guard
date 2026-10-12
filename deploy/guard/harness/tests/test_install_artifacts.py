import json
from pathlib import Path

import pytest
from test_install_evidence import fixture as install_fixture
from test_native_evidence import fixture as native_fixture

from guard_harness.install_artifacts import merge
from guard_harness.native_evidence import VARIANTS
from guard_harness.testnet_process import ProcessError


@pytest.mark.parametrize("row", ["I1", "I2", "I3", "I4", "I5", "I6"])
def test_independent_scenarios_are_merged_without_relabelling(tmp_path: Path, row: str) -> None:
    import shutil

    fixture = tmp_path / "fixture"
    fixture.mkdir()
    parts = tmp_path / "parts"
    parts.mkdir()
    if row in VARIANTS:
        native_fixture(fixture, row)
        for variant in VARIANTS[row]:
            for scenario in ("fresh", "upgrade"):
                shutil.copytree(
                    fixture / variant / scenario, parts / f"install-matrix-{variant}-{scenario}"
                )
    else:
        _, evidence, _ = install_fixture(fixture, row)
        for scenario in ("fresh", "upgrade"):
            for channel in ("docker", "compose") if row == "I5" else (None,):
                source = parts / (
                    f"install-matrix-I5-{scenario}-{channel}"
                    if row == "I5"
                    else f"install-matrix-{row}-{scenario}"
                )
                source.mkdir()
                if channel is not None:
                    shutil.copyfile(
                        evidence / scenario / channel / "receipt.json", source / "receipt.json"
                    )
                for mode in ("paper", "testnet"):
                    target = source / mode / scenario
                    target.parent.mkdir()
                    if channel:
                        target.mkdir()
                    shutil.copytree(
                        evidence / mode / scenario / channel
                        if channel
                        else evidence / mode / scenario,
                        target / channel if channel else target,
                    )
                if row in {"I1", "I2"} and scenario == "fresh":
                    shutil.copytree(evidence / "channels", source / "channels")
    output = tmp_path / "merged"
    merge(row, parts, output)
    for receipt in output.rglob("*.json"):
        value = json.loads(receipt.read_bytes())
        if "scenario" in value and "channels" not in receipt.parts:
            assert value["scenario"] in receipt.parts
    with pytest.raises(ProcessError):
        merge(row, parts, output)


@pytest.mark.parametrize("linked", [False, True])
def test_missing_or_linked_scenario_never_completes(tmp_path: Path, linked: bool) -> None:
    parts = tmp_path / "parts"
    parts.mkdir()
    if linked:
        (parts / "install-matrix-macos-fresh").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ProcessError):
        merge("I3", parts, tmp_path / "output")
