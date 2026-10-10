"""Pure branch/context/source fixtures; never run getter, vendor or native code."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import branch_observation as observation
REPO=HERE.parents[4]
WORKFLOW=REPO/'.github/workflows/hosted-linux-acquisition-branch-preparation.yml'


class BranchObservationFixtures(unittest.TestCase):
    def test_exact_positive_context_is_closed_bounded_and_has_no_authority(self):
        value=observation.make_observation('a'*40,38000000000,1)
        self.assertEqual(observation.validate_observation(observation.canonical(value)),value)
        self.assertLessEqual(len(observation.canonical(value).encode()),1024)
        self.assertEqual(value['ref'],'refs/heads/codex/no-key-linux-acquisition-preparation')
        self.assertEqual(value['artifactName'],'linux-acquisition-branch-inert-38000000000-1')
        for name in observation.FLAGS:self.assertIs(value[name],False)

    def test_context_cannot_claim_main_other_candidate_or_any_authority(self):
        original=observation.make_observation('a'*40,1,1)
        for key,value in [('ref','refs/heads/main'),('kind','actual-controller-source-admission'),('artifactName','linux-acquisition-runtime-inert-1-1'),('candidateVerified',True),*[(name,True)for name in observation.FLAGS]]:
            with self.assertRaises(ValueError):observation.validate_observation(observation.canonical({**original,key:value}))

    def test_duplicate_unknown_partial_noncanonical_or_oversize_refuses(self):
        raw=observation.canonical(observation.make_observation('a'*40,1,1))
        for value in [raw.replace('"schema":1','"schema":1,"schema":1'),raw+' ',raw.replace('"attempt":1,',''),'{"privateInput":false}','x'*1025,'[1]',raw.replace('"schema":1','"schema":true')]:
            with self.assertRaises((ValueError,TypeError)):observation.validate_observation(value)

    def test_exact_original_run_source_attempt_grammar_and_bounds(self):
        for source,run,attempt in [('a'*39,1,1),('A'*40,1,1),('a'*40,0,1),('a'*40,True,1),('a'*40,2**53,1),('a'*40,1,0),('a'*40,1,True),('a'*40,1,1001)]:
            with self.assertRaises(ValueError):observation.make_observation(source,run,attempt)
        self.assertEqual(observation.make_observation('a'*40,9007199254740991,1000)['attempt'],1000)

    def test_cli_failure_exports_only_closed_false_flags(self):
        for args in [['script','SECRET/private/key','1','1'],['script','a'*40,'1;id','1'],['script','a'*40,'0','1']]:
            out=io.StringIO()
            with patch.object(observation.sys,'argv',args),contextlib.redirect_stdout(out):self.assertEqual(observation.main(),1)
            value=json.loads(out.getvalue());self.assertEqual(value['kind'],'fixed-branch-observation-context-refused')
            self.assertNotIn('SECRET',out.getvalue());self.assertNotIn('/private',out.getvalue())
            for name in observation.FLAGS:self.assertIs(value[name],False)

    def test_fixed_push_branch_scope_and_exact_commit_checkout(self):
        text=WORKFLOW.read_text()
        self.assertIn('push:\n    branches: [codex/no-key-linux-acquisition-preparation]',text)
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/codex/no-key-linux-acquisition-preparation'",text)
        self.assertIn("github.repository == 'zunderlabs/zunder-guard' && github.event.repository.private == false",text)
        self.assertIn("github.ref_type == 'branch'",text)
        self.assertIn('ref: ${{ github.sha }}',text);self.assertNotIn('github.workflow_sha',text)
        self.assertIn('test "$(git rev-parse HEAD)" = "$CONTROL_SOURCE"',text)
        self.assertIn('test -z "$(git status --porcelain)"',text)
        for forbidden in ['workflow_dispatch','workflow_call','pull_request','schedule:','branches: [main]']:self.assertNotIn(forbidden,text)

    def test_permissions_environment_runtime_and_actions_remain_fixed(self):
        text=WORKFLOW.read_text()
        self.assertIn('permissions:\n  contents: read\n',text);self.assertEqual(text.count('permissions:'),1)
        self.assertIn('runs-on: ubuntu-24.04',text);self.assertIn('timeout-minutes: 30',text)
        self.assertIn('persist-credentials: false',text);self.assertIn('sudo /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8',text)
        self.assertIn('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',text)
        self.assertIn('actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',text)
        for forbidden in ['environment:','id-token:','secrets.','GH_TOKEN:','GITHUB_TOKEN:','aws-actions','setup-node','create-github-app-token','verifyOriginalPaperCandidate','verify-image','verify-artifact','shutdown']:
            self.assertNotIn(forbidden,text)

    def test_artifact_is_separate_branch_observation_not_main_receipt(self):
        text=WORKFLOW.read_text()
        self.assertIn('name: linux-acquisition-branch-inert-${{ github.run_id }}-${{ github.run_attempt }}',text)
        self.assertIn('observation-context.json',text);self.assertIn('retention-days: 7',text)
        self.assertIn('for name in summary failure runtime-closure trust-closure complete-trees bootstrap;',text)
        self.assertNotIn('linux-acquisition-runtime-inert-',text)

    def test_reviewed_getter_maps_tests_and_wrapper_are_byte_identical(self):
        pins={'prepare_runtime.py':'b08ce9be1df8d9c0f50bee5712bb7be0c17c0ec231a11a2b52bd6eefc349c5fa','runtime_maps.py':'cce8160f30b2aa86cab06342e20bb222aa5f0a796e64b9cb811ea11da51d97f2','test_runtime_preparation.py':'ff8af8b455dee74c1b353de94fdd4982c4f649171f102cfbd3546b86ede9aa62'}
        for name,digest in pins.items():self.assertEqual(hashlib.sha256((HERE/name).read_bytes()).hexdigest(),digest)
        wrapper=REPO/'deploy/guard/github/hosted-reboot/fixed-acquisition-stage.py'
        self.assertEqual(hashlib.sha256(wrapper.read_bytes()).hexdigest(),'539dbd0feaab3ad235a3fb5484b8f6f2ea1bf813cf5ed526868d94555523d421')


if __name__=='__main__':unittest.main()
