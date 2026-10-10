"""Darwin libproc public process identity, including microsecond birth time.

Layout comes from the installed Apple SDK sys/proc_info.h; no process memory read.
"""
import ctypes,os,sys

def need(ok):
 if not ok:raise RuntimeError('Exact Mac process identity unavailable')
class BSD(ctypes.Structure):
 _fields_=[(name,ctypes.c_uint32)for name in('flags','status','xstatus','pid','ppid','uid','gid','ruid','rgid','svuid','svgid','reserved')]+[('comm',ctypes.c_char*16),('name',ctypes.c_char*32)]+[(name,ctypes.c_uint32)for name in('nfiles','pgid','jobc','tdev','tpgid')]+[('nice',ctypes.c_int32),('start_sec',ctypes.c_uint64),('start_usec',ctypes.c_uint64)]
class DarwinProcesses:
 def __init__(self):
  need(sys.platform=='darwin');self.lib=ctypes.CDLL('/usr/lib/libproc.dylib',use_errno=True)
  self.lib.proc_pidinfo.argtypes=[ctypes.c_int,ctypes.c_int,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_int];self.lib.proc_pidinfo.restype=ctypes.c_int
  self.lib.proc_pidpath.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_uint32];self.lib.proc_pidpath.restype=ctypes.c_int
  self.lib.proc_listallpids.argtypes=[ctypes.c_void_p,ctypes.c_int];self.lib.proc_listallpids.restype=ctypes.c_int
 def read(self,pid):
  need(type(pid)is int and pid>1);value=BSD();n=self.lib.proc_pidinfo(pid,3,0,ctypes.byref(value),ctypes.sizeof(value))
  if n==0:return None
  need(n==ctypes.sizeof(value)and value.pid==pid)
  if value.status==5:return None # Apple SDK SZOMB: no live descriptors or executable.
  path=ctypes.create_string_buffer(4096);length=self.lib.proc_pidpath(pid,path,len(path));need(length>0)
  return {'pid':pid,'start_sec':int(value.start_sec),'start_usec':int(value.start_usec),'uid':int(value.uid),'ppid':int(value.ppid),'pgid':int(value.pgid),'path':path.value.decode()}
 def all(self):
  ids=(ctypes.c_int*10000)();n=self.lib.proc_listallpids(ids,ctypes.sizeof(ids));need(0<n<10000)
  result={}
  for pid in ids[:n]:
   if pid>1:
    value=self.read(pid)
    if value is not None:result[pid]=value
  return result

def birth(value):return {'pid':value['pid'],'start_sec':value['start_sec'],'start_usec':value['start_usec']}
def same(value,expected):return value is not None and all(type(expected[k])is int and value[k]==expected[k]for k in('pid','start_sec','start_usec'))
