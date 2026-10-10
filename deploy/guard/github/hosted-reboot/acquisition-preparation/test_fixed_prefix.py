"""Pure fixed-prefix consistency/inverses; no root/getter/provider operations."""
import hashlib
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[4]
OLD='/opt/zunder-public-reboot-acquisition';NEW='/var/lib/zunder-public-reboot-acquisition'
OLD_WRAPPER='539dbd0feaab3ad235a3fb5484b8f6f2ea1bf813cf5ed526868d94555523d421'
NEW_WRAPPER='d726a4d7518b6d67e4326626c5bdb959bc682f3812f93be23308151326d13dc0'
spec=importlib.util.spec_from_file_location('prefix_getter',HERE/'prepare_runtime.py')
g=importlib.util.module_from_spec(spec);spec.loader.exec_module(g)
spec=importlib.util.spec_from_file_location('prefix_stdout',HERE/'getter_stdout.py')
e=importlib.util.module_from_spec(spec);spec.loader.exec_module(e)


def normalize_migration(source):
    source=source.replace('b2ca993359b330d80c1e9c06734edb84c76a2d01ece3e96a1ae4465743250ee7','97171bc3ccef3a64247d3e4a02ea4212c4c203fe6f8a5c2caa9f5c6502605898')
    source=source.replace("        read_observation=maps.current_read_observation()\n        if read_observation is not None:value['diagnostic']['readObservation']=read_observation\n",'')
    if source.count(NEW)!=2 or source.count(NEW_WRAPPER)!=1:raise ValueError('Exact migration inverse required')
    source=source.replace(NEW,OLD).replace(NEW_WRAPPER,OLD_WRAPPER)
    new="Path('/'):'rootfs',Path('/var'):'var',Path('/var/lib'):'lib',Path('/run'):'run',"
    old="Path('/'):'rootfs',Path('/opt'):'opt',Path('/run'):'run',"
    if source.count(new)!=1:raise ValueError('Exact ancestor enum inverse required')
    return source.replace(new,old)


class FixedPrefixFixtures(unittest.TestCase):
    def test_whole_getter_inverse_is_exact_r6(self):
        inverse=normalize_migration((HERE/'prepare_runtime.py').read_text())
        self.assertEqual(hashlib.sha256(inverse.encode()).hexdigest(),'b08ce9be1df8d9c0f50bee5712bb7be0c17c0ec231a11a2b52bd6eefc349c5fa')
        self.assertEqual(g.ROOT,Path(NEW));self.assertEqual(g.SOURCE,g.ROOT/'source')
        self.assertEqual(g.MATERIAL,Path(NEW+'-material'))
        self.assertEqual(g.REPORTS,Path('/run/zunder-public-reboot-acquisition-preparation'))
        self.assertEqual(g.WORK,Path('/run/zunder-public-reboot-acquisition'))

    def test_maps_and_wrapper_exact_path_inverse(self):
        source=(HERE/'runtime_maps.py').read_text();self.assertEqual(source.count(NEW),1)
        source=source.replace('from hosted_launch.inventory import read, tree, clear_read_diagnostic, read_diagnostic','from hosted_launch.inventory import read, tree').replace('    clear_read_diagnostic()\n','')
        bridge="def current_read_observation():\n    if CONTEXT is None or CONTEXT['operation']!='protected-member':return None\n    return read_diagnostic(CONTEXT['memberSha256'])\n\n\n"
        self.assertEqual(source.count(bridge),1);source=source.replace(bridge,'')
        self.assertEqual(hashlib.sha256(source.replace(NEW,OLD).encode()).hexdigest(),'cce8160f30b2aa86cab06342e20bb222aa5f0a796e64b9cb811ea11da51d97f2')
        wrapper=REPO/'deploy/guard/github/hosted-reboot/fixed-acquisition-stage.py'
        source=wrapper.read_text();self.assertEqual(source.count(NEW),2);self.assertNotIn(OLD,source)
        self.assertEqual(hashlib.sha256(source.encode()).hexdigest(),NEW_WRAPPER)
        self.assertEqual(hashlib.sha256(source.replace(NEW,OLD).encode()).hexdigest(),OLD_WRAPPER)
        self.assertEqual(g.VERIFIERS['deploy/guard/github/hosted-reboot/fixed-acquisition-stage.py'][1],NEW_WRAPPER)

    def test_all_new_ancestors_guarded_without_opt_queries(self):
        calls=[]
        def stat(path):calls.append(str(path));return SimpleNamespace(st_mode=0o40755,st_uid=0)
        with patch.object(Path,'resolve',lambda p,**k:p),patch.object(Path,'lstat',stat):g.guard_fixed_paths()
        expected=['/','/var','/var/lib',NEW,'/','/var','/var/lib',NEW,NEW+'/source',
                  '/','/var','/var/lib',NEW+'-material','/','/run',str(g.REPORTS),'/', '/run',str(g.WORK)]
        self.assertEqual(calls,expected);self.assertTrue(all(not p.startswith('/opt')for p in calls))

    def test_original_guard_rejects_bad_new_ancestors_and_old_opt(self):
        for directory,badpath,mode,uid in ((g.ROOT,'/var',0o40777,0),(g.ROOT,'/var/lib',0o40755,1),
                                          (g.ROOT,'/var/lib',0o120755,0),(Path(OLD),'/opt',0o40777,0)):
            calls=[]
            def query(path):
                calls.append(str(path));return SimpleNamespace(st_mode=mode if str(path)==badpath else 0o40755,st_uid=uid if str(path)==badpath else 0)
            with patch.object(Path,'resolve',lambda p,**k:p),patch.object(Path,'lstat',query),patch.object(Path,'mkdir')as create,patch.object(g.os,'chmod')as chmod,patch.object(g.os,'chown')as chown:
                with self.assertRaises(RuntimeError):g.protected_ancestors(directory)
                create.assert_not_called();chmod.assert_not_called();chown.assert_not_called()
            self.assertEqual(calls[-1],badpath)

    def test_new_canonical_false_refuses_before_stat_or_create(self):
        with patch.object(Path,'resolve',return_value=Path('/different')),patch.object(Path,'lstat')as stat,patch.object(Path,'mkdir')as create:
            with self.assertRaises(RuntimeError):g.guard_fixed_paths()
            stat.assert_not_called();create.assert_not_called()

    def test_diagnostic_new_var_lib_and_historical_opt_are_inert(self):
        g.STAGE='source-ancestors'
        for path,label in ((Path('/var'),'var'),(Path('/var/lib'),'lib')):
            g.ancestor_context(g.ROOT,path,'lstat','observed','true',SimpleNamespace(st_mode=0o40755,st_uid=0))
            self.assertEqual(g.SOURCE_ANCESTOR_CONTEXT['ancestor'],label);e.validate_ancestor(g.SOURCE_ANCESTOR_CONTEXT)
        old={'kind':'fixed-source-ancestor-observation','target':'root','ancestor':'opt','query':'lstat','result':'observed','canonical':'true','uid':0,'mode':16895,'fileType':'directory'}
        e.validate_ancestor(old)
        g.ancestor_context(g.ROOT,Path('/opt'),'lstat','observed','true',SimpleNamespace(st_mode=16895,st_uid=0))
        self.assertIsNone(g.SOURCE_ANCESTOR_CONTEXT)


if __name__=='__main__':unittest.main()
