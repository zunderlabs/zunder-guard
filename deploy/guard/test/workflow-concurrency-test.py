#!/usr/bin/env python3
"""Secret custody inherited at any leaf-job level must hold the C6 queue."""
import importlib.util
import tempfile
from pathlib import Path
import unittest
import yaml

spec = importlib.util.spec_from_file_location("queues", Path(__file__).with_name("workflow-concurrency.py"))
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class QueueCustody(unittest.TestCase):
    def test_channel_mutations_preserve_pending_recovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workflow.yml"
            concurrency = {"group": "guard-release-channel-mutation", "queue": "max", "cancel-in-progress": False}
            doc = {"jobs": {"mutation": {"runs-on": "ubuntu-24.04", "concurrency": concurrency}}}
            path.write_text(yaml.safe_dump(doc))
            module.validate([path])
            for bad in ({"queue": "single"}, {"queue": None}, {"cancel-in-progress": True}):
                doc["jobs"]["mutation"]["concurrency"] = concurrency | bad
                path.write_text(yaml.safe_dump(doc))
                with self.assertRaisesRegex(ValueError, "queue"):
                    module.validate([path])

    def test_runtime_deadline_is_bound_to_hosted_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workflow.yml"
            job = {"runs-on": "ubuntu-24.04", "timeout-minutes": 120,
                   "steps": [{"run": "true", "env": {"JOB_TIMEOUT_SECONDS": "7200"}}]}
            path.write_text(yaml.safe_dump({"jobs": {"leaf": job}}))
            module.validate([path])
            for seconds in ("7100", "${{ inputs.timeout }}"):
                job["steps"][0]["env"]["JOB_TIMEOUT_SECONDS"] = seconds
                path.write_text(yaml.safe_dump({"jobs": {"leaf": job}}))
                with self.assertRaisesRegex(ValueError, "deadline must match"):
                    module.validate([path])

    def test_inherited_custody_requires_durable_lock(self):
        for level in ("workflow", "job", "step"):
            for secret in ("E2E_TESTNET_API_WALLET_KEY", "E2E_TESTNET_OWNER_KEY"):
                with self.subTest(level=level, secret=secret), tempfile.TemporaryDirectory() as tmp:
                    env = {"KEY": "${{ secrets." + secret + " }}"}
                    job = {"runs-on": "ubuntu-24.04", "steps": [{"run": "true"}]}
                    doc = {"jobs": {"leaf": job}}
                    if level == "workflow": doc["env"] = env
                    elif level == "job": job["env"] = env
                    else: job["steps"][0]["env"] = env
                    path = Path(tmp) / "workflow.yml"
                    path.write_text(yaml.safe_dump(doc))
                    with self.assertRaises(ValueError): module.validate([path])
                    job["concurrency"] = {"group": "guard-e2e-testnet", "queue": "max", "cancel-in-progress": False}
                    path.write_text(yaml.safe_dump(doc))
                    module.validate([path])

    def test_forwarding_caller_is_not_leaf_custody(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "workflow.yml"
            path.write_text(yaml.safe_dump({"jobs": {"caller": {"uses": "./journey.yml", "secrets": {"key": "${{ secrets.E2E_TESTNET_OWNER_KEY }}"}}}}))
            module.validate([path])




class RecoveryQueueGraph(unittest.TestCase):
    def test_operator_leaf_admitted_only_by_complete_sealed_contract(self):
        names = ("verify.yml", "nightly.yml", "install-matrix.yml", "journey.yml")
        project = Path(__file__).resolve().parents[3]
        base = project / "deploy/guard/github/workflows"
        if not base.is_dir():
            base = project / ".github/workflows"
        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for name in names:
                path = Path(tmp) / name
                path.write_text((base / name).read_text())
                paths.append(path)
            module.validate(paths)
            install = paths[2]
            original = install.read_text()
            doc = module.contract.document(original)
            doc["jobs"]["operator-recovery"]["if"] = "${{ always() }}"
            install.write_text(yaml.safe_dump(doc))
            with self.assertRaises(ValueError): module.validate(paths)
            install.write_text(original)
            doc = module.contract.document(original)
            doc["jobs"]["unknown-custody"] = {
                "runs-on": "ubuntu-24.04", "steps": [{"run": "true", "env": {
                    "KEY": "${{ secrets.E2E_TESTNET_API_WALLET_KEY }}"}}]}
            install.write_text(yaml.safe_dump(doc))
            with self.assertRaises(ValueError): module.validate(paths)

if __name__ == "__main__": unittest.main()
