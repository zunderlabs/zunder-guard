#!/usr/bin/env python3
"""Offline private-image admission tests; never real registry/credential evidence."""
import argparse
import base64
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SOURCE=Path(__file__).resolve().parents[1]
IMAGE='ghcr.io/zunderlabs/zunder-guard@sha256:'+'a'*64
SOURCE_SHA='b'*40
IMAGE_ID='sha256:'+'c'*64
TOKEN='fixture-user:public_synthetic_token'


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


class PrivateImage(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name).resolve()
        self.stage=self.root/'stage';self.stage.mkdir()
        for original,target in [('install-container.py','install-container.py'),('operations.py','container-operations.py'),('supervisor.py','container-supervisor.py')]:
            shutil.copyfile(SOURCE/'container'/original,self.stage/target)
        self.helper=load('private_image_helper',self.stage/'install-container.py')
        self.sup=load('private_image_sup',self.stage/'container-supervisor.py')
        self.prepared=self.root/'prepared';self.sup.PREPARED_IMAGE=self.prepared
        self.auth=self.root/'auth';self.auth.mkdir(mode=0o700)
        self.file=self.auth/'config.json'
        self.file.write_text(json.dumps({'auths':{'ghcr.io':{'auth':base64.b64encode(TOKEN.encode()).decode()}}}));self.file.chmod(0o600)
        self.owner=patch.object(self.helper.ops,'trusted');self.owner.start()
        self.parents=patch.object(self.helper.ops,'parents');self.parents.start()
        self.sup_owner=patch.object(self.sup,'trusted');self.sup_owner.start()
        (self.stage/'zunder-guard-v1.0.2.image.txt').write_text(IMAGE+'\n')
        (self.stage/'SHA256SUMS').write_text('signed-public-fixture-manifest\n')
        self.args=argparse.Namespace(network='testnet',rules='',account='',volume='',equity_cap='',ip_share='',licence='',key_stdin=False,non_interactive=False,prepared_image=False,source_commit=SOURCE_SHA,registry_auth_dir=str(self.auth),version='v1.0.2')
        self.calls=[]
    def tearDown(self):
        self.sup_owner.stop();self.parents.stop();self.owner.stop();self.tmp.cleanup()
    def command(self,words,**options):
        self.calls.append((words,options))
        self.assertNotIn(TOKEN,repr(words)+repr(options))
        self.assertEqual(options['stdin'],subprocess.DEVNULL)
        self.assertEqual(options['env']['DOCKER_CONFIG'],str(self.auth))
        raw=json.dumps([{'Id':IMAGE_ID,'RepoDigests':[IMAGE],'Config':{'User':'65532:65532'}}]).encode()
        return subprocess.CompletedProcess(words,0,raw if 'inspect'in words else b'public result',b'')
    def run_prepare(self):
        with patch.object(self.helper.subprocess,'run',side_effect=self.command),contextlib.redirect_stdout(io.StringIO())as output:
            self.helper.prepare_image(self.args,self.sup)
        self.assertNotIn(TOKEN,output.getvalue())
    def test_success_scrubs_auth_before_receipt_and_never_reads_wallet(self):
        self.run_prepare();self.assertFalse(self.auth.exists())
        value=json.loads((self.prepared/'receipt.json').read_text())
        self.assertEqual(value['image_id'],IMAGE_ID);self.assertEqual(value['source_commit'],SOURCE_SHA)
        self.assertEqual((self.prepared/'receipt.json').stat().st_mode&0o777,0o600)
        self.assertEqual(len(self.calls),3)
        self.assertTrue(all('key'not in repr(call[0])for call in self.calls))
    def test_artifact_failure_still_scrubs_before_any_receipt(self):
        with patch.object(self.helper.subprocess,'run',return_value=subprocess.CompletedProcess([],1,b'',b'private response')),self.assertRaises(self.helper.ops.Refused)as raised:
            self.helper.prepare_image(self.args,self.sup)
        self.assertFalse(self.auth.exists());self.assertFalse(self.prepared.exists());self.assertNotIn('private response',str(raised.exception))
    def test_wallet_and_mainnet_inputs_refuse_before_child(self):
        for field,value in [('network','mainnet'),('account','0x'+'1'*40),('key_stdin',True),('rules','zr1_fixture'),('prepared_image',True),('source_commit','bad')]:
            args=argparse.Namespace(**vars(self.args));setattr(args,field,value)
            with self.subTest(field=field),patch.object(self.helper.subprocess,'run')as child,self.assertRaises(self.helper.ops.Refused):
                self.helper.prepare_image(args,self.sup)
            child.assert_not_called()
    def test_config_helpers_stores_other_hosts_extra_files_refuse(self):
        encoded=base64.b64encode(TOKEN.encode()).decode()
        for value in [{'auths':{'ghcr.io':{'auth':encoded}},'credsStore':'desktop'},
                      {'auths':{'other.example':{'auth':encoded}}},
                      {'auths':{'ghcr.io':{'auth':encoded,'identitytoken':'other'}}},
                      {'auths':{'ghcr.io':{'auth':'bad'}}}]:
            self.file.write_text(json.dumps(value))
            with self.subTest(value=value),self.assertRaises(self.helper.ops.Refused):self.helper.registry_auth(self.auth)
        self.file.write_text(json.dumps({'auths':{'ghcr.io':{'auth':encoded}}}));(self.auth/'extra').touch()
        with self.assertRaises(self.helper.ops.Refused):self.helper.registry_auth(self.auth)
    def test_duplicate_and_unconfined_config_refuse(self):
        original=self.file.read_text();self.file.write_text('{"auths":{},"auths":{}}')
        with self.assertRaises(self.helper.ops.Refused):self.helper.registry_auth(self.auth)
        self.file.write_text(original);self.file.chmod(0o644)
        with self.assertRaises(self.helper.ops.Refused):self.helper.registry_auth(self.auth)
        self.file.chmod(0o600);self.auth.chmod(0o755)
        with self.assertRaises(self.helper.ops.Refused):self.helper.registry_auth(self.auth)
    def test_auth_identity_change_never_blindly_deletes(self):
        identity=self.helper.registry_auth(self.auth);old=self.auth/'old';self.file.rename(old)
        self.file.write_bytes(old.read_bytes());self.file.chmod(0o600);old.unlink()
        with self.assertRaises(self.helper.ops.Refused):self.helper.scrub_registry_auth(self.auth,identity)
        self.assertTrue(self.file.exists())
    def test_prepared_image_exact_manifest_source_digest_and_id(self):
        self.run_prepare();receipt=json.loads((self.prepared/'receipt.json').read_text())
        config={'mode':'testnet','image':IMAGE,'tag':'v1.0.2'}
        raw=[{'Id':IMAGE_ID,'RepoDigests':[IMAGE],'Config':{'User':'65532:65532'}}]
        with patch.object(self.sup,'docker_json',return_value=raw):
            self.sup.prepared_image(config,receipt['manifest_sha256'],SOURCE_SHA)
            for value,manifest,source in [(dict(config,tag='v1.0.3'),receipt['manifest_sha256'],SOURCE_SHA),
                                          (dict(config,mode='mainnet'),receipt['manifest_sha256'],SOURCE_SHA),
                                          (config,'d'*64,SOURCE_SHA),(config,receipt['manifest_sha256'],'e'*40)]:
                with self.subTest(value=value,manifest=manifest,source=source),self.assertRaises(self.sup.Refused):
                    self.sup.prepared_image(value,manifest,source)
        with patch.object(self.sup,'docker_json',return_value=[dict(raw[0],Id='sha256:'+'f'*64)]),self.assertRaises(self.sup.Refused):
            self.sup.prepared_image(config,receipt['manifest_sha256'],SOURCE_SHA)
    def test_existing_prepared_receipt_refuses_and_scrubs_new_auth(self):
        self.prepared.mkdir();(self.prepared/'receipt.json').write_text('{}')
        with patch.object(self.helper.subprocess,'run')as child,self.assertRaises(self.helper.ops.Refused):self.helper.prepare_image(self.args,self.sup)
        child.assert_not_called();self.assertFalse(self.auth.exists())

    def test_shell_refuses_ambiguous_preparation_before_fetch(self):
        common=['/bin/sh',str(SOURCE/'install.sh')]
        bad=[['--prepare-image'],['--container','--network','mainnet','--prepare-image'],
             ['--container','--network','testnet','--prepare-image','--source-commit',SOURCE_SHA],
             ['--container','--network','testnet','--prepared-image','--source-commit',SOURCE_SHA,'--registry-auth-dir','/root/auth'],
             ['--container','--network','testnet','--prepare-image','--source-commit',SOURCE_SHA,'--registry-auth-dir','/root/auth','--key-stdin']]
        for words in bad:
            with self.subTest(words=words):
                result=subprocess.run(common+words,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
                self.assertNotEqual(result.returncode,0);self.assertNotIn(b'downloading',result.stdout)


if __name__=='__main__':unittest.main()
