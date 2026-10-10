"""Fixed-root inert fixtures; never create host directories or run preparation."""
import ast
from contextlib import ExitStack
from pathlib import Path
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from . import bootstrap as p
from . import contracts as c
from . import inventory as inventory
from . import prepare_website as recipe
from . import prepare_website_entry as entry


class ProtectedAncestors(unittest.TestCase):
    def setUp(self):
        self.context=p._INVENTORY_CONTEXT;self.stage=p._STAGE
        self.addCleanup(self.restore)
    def restore(self):p._INVENTORY_CONTEXT=self.context;p._STAGE=self.stage
    def observe(self, selected=None, *, mode=stat.S_IFDIR|0o755, uid=0, canonical=True, missing=False):
        visits=[]
        def lstat(path):
            visits.append(str(path))
            if str(path)==selected:
                if missing:raise FileNotFoundError('inert missing ancestor')
                return SimpleNamespace(st_mode=mode,st_uid=uid)
            return SimpleNamespace(st_mode=stat.S_IFDIR|0o755,st_uid=0)
        def resolve(path,strict=False):
            self.assertTrue(strict)
            return Path('/other-canonical-parent')if str(path)==selected and not canonical else path
        with patch.object(Path,'lstat',lstat),patch.object(Path,'resolve',resolve),\
             patch.object(Path,'mkdir')as mkdir,patch.object(Path,'chmod')as chmod,patch.object(p.os,'chown')as chown:
            p.preparation_ancestors()
            mkdir.assert_not_called();chmod.assert_not_called();chown.assert_not_called()
        return visits
    def test_fixed_both_ancestor_chains_top_down_and_no_permission_repairs(self):
        self.assertEqual(self.observe(),['/','/var','/var/lib','/','/run'])
        self.assertEqual(str(p.ROOT),'/var/lib/zunder-hosted-ordinary')
        self.assertEqual(str(p.PUBLIC),'/run/zunder-hosted-ordinary')
    def test_every_ancestor_foreign_owner_or_write_bit_refuses(self):
        for selected in ('/','/var','/var/lib','/run'):
            for mode,uid in ((stat.S_IFDIR|0o755,1),(stat.S_IFDIR|0o757,0),
                             (stat.S_IFDIR|0o775,0),(stat.S_IFDIR|0o777,0)):
                with self.subTest(selected=selected,mode=mode,uid=uid),self.assertRaises(RuntimeError):
                    self.observe(selected,mode=mode,uid=uid)
    def test_missing_symlink_file_device_and_noncanonical_parents_refuse(self):
        for selected in ('/','/var','/var/lib','/run'):
            for mode in (stat.S_IFLNK|0o755,stat.S_IFREG|0o444,stat.S_IFCHR|0o600):
                with self.subTest(selected=selected,mode=mode),self.assertRaises(RuntimeError):
                    self.observe(selected,mode=mode)
            with self.subTest(selected=selected),self.assertRaises(RuntimeError):self.observe(selected,canonical=False)
            with self.subTest(selected=selected),self.assertRaises(FileNotFoundError):self.observe(selected,missing=True)
    def test_relative_constant_refuses_without_parent_inspection(self):
        with patch.object(p,'ROOT',Path('relative/root')),patch.object(Path,'lstat')as observed,self.assertRaises(RuntimeError):
            p.preparation_ancestors()
        observed.assert_not_called()
    def test_actual_prepare_guard_failure_precedes_mkdir_and_all_actions(self):
        # Modeled failed lstat only. No caller-selected destination or actual OS setup.
        with ExitStack()as stack:
            actions=[stack.enter_context(patch.object(p,name))for name in ('capabilities','source','node','website','command','python_runtime','protect','tree','runtime_observation','write_new')]
            mkdir=stack.enter_context(patch.object(Path,'mkdir'))
            stack.enter_context(patch.object(Path,'exists',return_value=False))
            stack.enter_context(patch.object(p.os,'geteuid',return_value=0))
            stack.enter_context(patch.object(Path,'resolve',lambda path,strict=False:path))
            stack.enter_context(patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=stat.S_IFDIR|0o777,st_uid=0)))
            with self.assertRaisesRegex(RuntimeError,'^Fixed protected preparation ancestors required$'):
                p.prepare('/inert-workspace','a'*40)
            for action in [mkdir,*actions]:action.assert_not_called()
    def test_freshness_and_root_identity_are_still_required_before_new_guard(self):
        for uid,exists in ((1,False),(0,True)):
            with patch.object(p.os,'geteuid',return_value=uid),patch.object(Path,'exists',return_value=exists),\
                 patch.object(p,'preparation_ancestors')as check,patch.object(Path,'mkdir')as mkdir,self.assertRaises(RuntimeError):
                p.prepare('/inert-workspace','a'*40)
            check.assert_not_called();mkdir.assert_not_called()
    def test_original_inventory_member_ancestor_guard_remains_independent(self):
        for mode,uid in ((stat.S_IFDIR|0o777,0),(stat.S_IFDIR|0o755,1),(stat.S_IFLNK|0o777,0)):
            with patch.object(Path,'resolve',lambda path,strict=False:path),\
                 patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=mode,st_uid=uid)),\
                 patch.object(inventory.os,'open')as opened,self.assertRaises(RuntimeError):
                inventory.read(c.SOURCE/'member.py')
            opened.assert_not_called()
    def test_new_fixed_guard_is_before_both_creations_and_has_no_external_action(self):
        tree=ast.parse(Path(p.__file__).read_text())
        prepare=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='prepare')
        calls=[(i,ast.unparse(n))for i,n in enumerate(prepare.body)]
        checked=next(i for i,text in calls if text=='preparation_ancestors()')
        created=[i for i,text in calls if text in ('PUBLIC.mkdir(mode=448)','ROOT.mkdir(mode=448)')]
        self.assertEqual(len(created),2);self.assertTrue(all(checked<i for i in created))
        helper=next(n for n in tree.body if isinstance(n,ast.FunctionDef)and n.name=='preparation_ancestors')
        self.assertEqual(len(helper.args.args),0)
        functions={ast.unparse(n.func)for n in ast.walk(helper)if isinstance(n,ast.Call)}
        self.assertEqual(functions,{'need','directory.is_absolute','reversed','parent.lstat','stat.S_ISDIR','parent.resolve'})


class FixedConsumers(unittest.TestCase):
    def setUp(self):self.repo=Path(__file__).resolve().parents[4]
    def test_all_derived_source_checkout_runtime_and_report_roots(self):
        self.assertEqual(c.ROOT,Path('/var/lib/zunder-hosted-ordinary'))
        self.assertEqual(c.PUBLIC,Path('/run/zunder-hosted-ordinary'))
        self.assertEqual(c.SOURCE,c.ROOT/'source');self.assertEqual(c.CHECKOUT,c.ROOT/'checkout')
        self.assertEqual(c.WEBSITE,c.ROOT/'runtime/website/source')
        self.assertFalse(c.CHECKOUT.is_relative_to(c.SOURCE));self.assertFalse(c.WEBSITE.is_relative_to(c.SOURCE))
        self.assertEqual(recipe.PACKAGES,c.ROOT/'runtime/website')
        self.assertEqual(recipe.SOURCE,recipe.PACKAGES/'build-source')
        for name,suffix in (('PYTHON','runtime/python/bin/python3.12'),('NODE','runtime/node/bin/node'),
                            ('NPM','runtime/node/lib/node_modules/npm/bin/npm-cli.js'),('RUSTUP','runtime/node/bin/rustup')):
            self.assertEqual(getattr(entry,name),c.ROOT/suffix)
    def test_raw_reader_fixed_packages_equals_actual_recipe_without_executing_reader(self):
        file=self.repo/'deploy/guard/github/hosted-delivery/raw_build_reader.py'
        tree=ast.parse(file.read_text())
        assignment=next(n for n in tree.body if isinstance(n,ast.Assign)and any(isinstance(t,ast.Name)and t.id=='PACKAGES'for t in n.targets))
        self.assertIsInstance(assignment.value,ast.Call);self.assertEqual(ast.unparse(assignment.value.func),'Path')
        self.assertEqual(assignment.value.args[0].value,str(recipe.PACKAGES))
    def test_bundle_fixed_path_and_three_workflow_invocations_have_same_root(self):
        bundle=Path(__file__).with_name('build_bundle.mjs').read_text()
        self.assertIn("root==='"+str(c.WEBSITE)+"'&&await fs.realpath(root)===root",bundle)
        text=(self.repo/'.github/workflows/hosted-website-build-preparation.yml').read_text()
        python=str(c.ROOT/'runtime/python/bin/python3.12');script=str(c.SOURCE/'deploy/guard/e2e/hosted_launch/prepare_website_entry.py')
        self.assertEqual(text.count(python),3);self.assertEqual(text.count(script),3)
        self.assertNotIn('/opt/zunder-hosted-ordinary',text);self.assertNotIn('/opt/zunder-hosted-ordinary',bundle)
    def test_root_documents_track_fixed_paths(self):
        readme=Path(__file__).with_name('README.md').read_text()
        for directory in (c.SOURCE,c.CHECKOUT,c.WEBSITE):self.assertIn(str(directory),readme)
        raw=(self.repo/'deploy/guard/github/hosted-delivery/RAW-BUILD-READER.md').read_text()
        for directory in (recipe.SOURCE,recipe.INPUT/'source.json'):self.assertIn(str(directory),raw)
        self.assertNotIn('/opt/zunder-hosted-ordinary',readme+raw)


if __name__=='__main__':unittest.main()
