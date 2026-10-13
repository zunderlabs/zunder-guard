"""Run authenticated helper admission branches without services, volumes or keys."""

import ast
import importlib.util
import shutil
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

CONTAINER = Path(__file__).resolve().parents[2] / "container"
ACCOUNT = "0x" + "1" * 40


@pytest.fixture
def helper(tmp_path: Path) -> Any:
    for original, staged in (
        ("install-container.py", "install-container.py"),
        ("operations.py", "container-operations.py"),
        ("supervisor.py", "container-supervisor.py"),
    ):
        shutil.copyfile(CONTAINER / original, tmp_path / staged)
    spec = importlib.util.spec_from_file_location(
        "container_admission_fixture", tmp_path / "install-container.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def admission(helper: Any, existing: Any, pending: Any, rules: str = "") -> None:
    function = next(
        node
        for node in ast.parse((CONTAINER / "install-container.py").read_text()).body
        if isinstance(node, ast.FunctionDef) and node.name == "main"
    )
    guard = next(
        node
        for node in function.body
        if isinstance(node, ast.If)
        and any(
            isinstance(child, ast.Constant)
            and child.value == "Unattended fresh Testnet setup requires explicit rules."
            for child in ast.walk(node)
        )
    )
    nodes: list[ast.stmt] = [
        guard,
        *[
            next(
                node
                for node in function.body
                if isinstance(node, ast.If)
                and isinstance(node.test, ast.Name)
                and node.test.id == name
            )
            for name in ("existing", "pending_record")
        ],
    ]
    # Admission runs before any transaction, managed service, volume or stdin-key action.
    mutation_names = {"prepare_receipt", "inhibit", "phase", "install_files", "create_volume"}
    actions = [
        node
        for node in ast.walk(function)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id in mutation_names)
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "read_key_frame")
        )
    ]
    assert actions and all(guard.lineno < node.lineno for node in actions)
    args = SimpleNamespace(
        non_interactive=True, network="testnet", rules=rules, equity_cap="", ip_share="", licence=""
    )
    helper.validate_input(
        SimpleNamespace(network="testnet", account=ACCOUNT, non_interactive=True, key_stdin=True),
        False,
    )
    context = {
        **vars(helper),
        "args": args,
        "existing": existing,
        "pending_record": pending,
        "account": ACCOUNT,
        "volume": "fixture-volume",
    }
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]), "actual-helper-admission", "exec"), context
    )


def test_fresh_unattended_rules_required_before_any_custody_or_transaction(helper: Any) -> None:
    with pytest.raises(
        helper.ops.Refused, match="Unattended fresh Testnet setup requires explicit rules"
    ):
        admission(helper, None, None)
    admission(helper, None, None, "zr1_fixture")


@pytest.mark.parametrize("pending", [False, True])
def test_owned_existing_and_pending_choices_are_preserved(helper: Any, pending: bool) -> None:
    owned = {"mode": "testnet", "account": ACCOUNT, "volume": "fixture-volume"}
    admission(helper, None if pending else owned, owned if pending else None)
    with pytest.raises(
        helper.ops.Refused, match="(?:cannot be replaced|preserves existing choices)"
    ):
        admission(helper, None if pending else owned, owned if pending else None, "zr1_fixture")
    wrong_network = dict(owned, mode="mainnet")
    with pytest.raises(helper.ops.Refused, match="another network"):
        admission(helper, None if pending else wrong_network, wrong_network if pending else None)


def test_owned_existing_account_and_volume_cannot_change(helper: Any) -> None:
    for owned in (
        {"mode": "testnet", "account": "0x" + "2" * 40, "volume": "fixture-volume"},
        {"mode": "testnet", "account": ACCOUNT, "volume": "different-volume"},
    ):
        with pytest.raises(helper.ops.Refused, match="Existing account/volume cannot change"):
            admission(helper, owned, None)
