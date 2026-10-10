"""Fixed public stdin program: one empty KVM context, no VM configuration."""
import fcntl,json,os,platform,resource,stat,sys

def observe():
    row={'schema':1,'kind':'public-empty-kvm-context','status':'refused',
         'privileged':False,'api_version':None,'errno':None,
         'empty_vm_context_created':False,'context_closed':False,
         'device_closed':False,'owned_fd_cleanup_confirmed':True,
         'core_dumps_disabled':False,'guest_started':False}
    dev=vm=None
    try:
        if sys.platform!='linux'or platform.machine()!='x86_64'or os.geteuid()!=0:
            return row
        row['privileged']=True
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        if resource.getrlimit(resource.RLIMIT_CORE)!=(0,0):return row
        row['core_dumps_disabled']=True
        before=os.lstat('/dev/kvm')
        if not stat.S_ISCHR(before.st_mode)or (os.major(before.st_rdev),os.minor(before.st_rdev))!=(10,232):
            row['status']='device-refused';return row
        dev=os.open('/dev/kvm',os.O_RDWR|os.O_CLOEXEC|os.O_NOFOLLOW)
        row['owned_fd_cleanup_confirmed']=False
        current=os.fstat(dev)
        if not stat.S_ISCHR(current.st_mode)or (current.st_dev,current.st_ino,current.st_rdev)!=(before.st_dev,before.st_ino,before.st_rdev):
            row['status']='device-changed';return row
        api=fcntl.ioctl(dev,0xAE00,0)
        row['api_version']=api if type(api)is int and 0<=api<=65535 else None
        if api!=12:row['status']='api-refused';return row
        vm=fcntl.ioctl(dev,0xAE01,0)
        if type(vm)is not int or vm<0:raise OSError(9,'fixed VM descriptor refused')
        row['empty_vm_context_created']=True;row['status']='empty-context-created'
    except OSError as exc:
        row['status']='unavailable';row['errno']=exc.errno if type(exc.errno)is int and 1<=exc.errno<=4095 else None
    finally:
        cleanup=True
        for fd,field in ((vm,'context_closed'),(dev,'device_closed')):
            if fd is not None:
                try:os.close(fd);row[field]=True
                except OSError:cleanup=False
        row['owned_fd_cleanup_confirmed']=cleanup
        if not cleanup:row['status']='cleanup-unconfirmed'
    return row

if __name__=='__main__':
    if sys.argv!=['-']:raise SystemExit(126)
    row=observe()
    sys.stdout.write(json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=True)+'\n')
    raise SystemExit(0 if row['owned_fd_cleanup_confirmed']else 1)
