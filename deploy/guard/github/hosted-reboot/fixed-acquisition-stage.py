#!/usr/bin/env python3
"""Fixed Actions stage/readback; no verifier-success receipt or admission output."""
import sys,os,json,hashlib
from pathlib import Path
import importlib.util
_spec=importlib.util.spec_from_file_location("fixed_actions_transport","/opt/zunder-public-reboot-acquisition/source/actions-artifacts.py")
_module=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(_module)
stage,stream,run_binding=_module.stage,_module.stream,_module.run_binding
P='/opt/zunder-public-reboot-acquisition/source'
# Fixed loader path is independently included in the mandatory runtime/source inventory.
SOURCE='0f64fa0f822fb2e9fffc414883ca843bd4e992a7';TAG='v1.0.5';RUN=38022247487;CI=38020585250
ARTIFACTS=[(11659481192,19959858,'sha256:fef553a23e7297d919716e53bf8dc989b0419e0a6a2579f979c317defbdcb8cf'),(11659731833,11996,'sha256:b4729e59dfadd41cf5f36328306dd1f78bf9c60a80dd5b5b0ec8b9ce288dde2d')]
def need(v):
 if not v:raise RuntimeError('Fixed acquisition refused')
def readback():
 run_binding(stream(f'repos/zunderlabs/zunder-guard/actions/runs/{RUN}/attempts/1'),TAG,SOURCE,RUN,1)
 run_binding(stream(f'repos/zunderlabs/zunder-guard/actions/runs/{RUN}'),TAG,SOURCE,RUN,1)
 ci=stream(f'repos/zunderlabs/zunder-guard/actions/runs/{CI}/attempts/1')
 current_ci=stream(f'repos/zunderlabs/zunder-guard/actions/runs/{CI}')
 need(current_ci['run_attempt']==1 and current_ci['head_sha']==SOURCE and current_ci['status']=='completed' and current_ci['conclusion']=='success')
 need(ci['id']==CI and ci['run_attempt']==1 and ci['head_sha']==SOURCE and ci['head_branch']=='main' and ci['event']=='push' and ci['path']=='.github/workflows/ci.yml' and ci['status']=='completed' and ci['conclusion']=='success' and ci['repository']['id']==1409357189 and ci['head_repository']['id']==1409357189)
 for id,size,digest in ARTIFACTS:
  a=stream(f'repos/zunderlabs/zunder-guard/actions/artifacts/{id}')
  need(a['id']==id and a['expired'] is False and a['size_in_bytes']==size and a['digest']==digest and a['workflow_run']['id']==RUN and a['workflow_run']['head_sha']==SOURCE)
def main():
 need(len(sys.argv)in(2,3) and len(sys.argv[1])==64 and all(c in '0123456789abcdef' for c in sys.argv[1]) and (len(sys.argv)==2 or sys.argv[2]=='readback'))
 need(os.getuid()==0 and os.path.realpath(__file__)==P+'/fixed-acquisition-stage.py')
 readback()
 if len(sys.argv)==2:
  work=Path('/run/zunder-public-reboot-acquisition')/sys.argv[1]
  report=stage(TAG,SOURCE,RUN,1,work/'staged',work/'transport.json')
  need([(a['id'],a['bytes'],'sha256:'+a['zip_sha256'])for a in report['artifacts']]==ARTIFACTS)
  readback()
if __name__=='__main__':main()
