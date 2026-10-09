#!/usr/bin/env python3
"""Frozen pre-exec barrier. No work/private stdin until privileged cgroup admission."""
import ctypes
import json
import os
import resource
import select
import sys
import time

try:
    if len(sys.argv)!=4 or os.geteuid()==0:raise RuntimeError()
    descriptor=int(sys.argv[1]);deadline=int(sys.argv[2]);argv=json.loads(sys.argv[3])
    if descriptor<3 or not isinstance(argv,list) or not argv or any(type(x)is not str for x in argv):raise RuntimeError()
    if resource.getrlimit(resource.RLIMIT_CORE)!=(0,0):raise RuntimeError()
    if ctypes.CDLL(None).prctl(39,0,0,0,0)!=1:raise RuntimeError() # PR_GET_NO_NEW_PRIVS
    if not select.select([descriptor],[],[],10)[0] or os.read(descriptor,2)!=b'1':raise RuntimeError()
    os.close(descriptor)
    if int(time.time()*1000)>=deadline:raise RuntimeError()
    os.execvpe(argv[0],argv,os.environ)
except BaseException:os._exit(126)
