#!/usr/bin/env python3
"""Fixed fresh Ubuntu stdlib copy probe. No credential or private admission."""
import os
from pathlib import Path
import platform
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hosted_launch import bootstrap as b
from hosted_launch.contracts import ROOT, canonical, need


def main():
    need(sys.platform == 'linux' and platform.machine() == 'x86_64' and os.geteuid() == 0,
         'Actual Ubuntu AMD64 root probe required')
    need(not ROOT.exists(), 'Fresh fixed public probe root required')
    ROOT.mkdir(mode=0o700); (ROOT/'runtime').mkdir(mode=0o700)
    value = {'schema': 1, 'kind': 'actual-public-python-copy-probe',
             'privateInput': False, 'releaseReady': False, 'runtimeAdmitted': False}
    status = 0
    try:
        aliases = b.python_runtime()
        value.update({'copied': True, 'regularizedAliases': aliases})
    except BaseException as error:
        value.update({'copied': False, 'diagnostic': b.python_failure_diagnostic(b._PYTHON_CONTEXT, error)})
        status = 1
    raw = canonical(value)
    need(len(raw) <= 65536, 'Bounded closed public probe output required')
    sys.stdout.buffer.write(raw+b'\n'); sys.stdout.buffer.flush()
    return status


if __name__ == '__main__':
    raise SystemExit(main())
