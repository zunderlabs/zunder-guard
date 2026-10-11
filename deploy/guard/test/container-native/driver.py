#!/usr/bin/python3
"""TEST ONLY: exact production runtime/cleanup with local fixture identity and paths.

Only image metadata admission differs: the locally built immutable image ID is not a
signed Guard release. This driver is never installed by a production release installer.
"""
import importlib.util
import json
from pathlib import Path

WORK = Path('/var/lib/zunder-container-native')
spec = importlib.util.spec_from_file_location('supervisor', WORK / 'supervisor.py')
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)
s.BASE = Path('/etc/zunder-container-native')
s.RUNTIME = Path('/run/zunder-container-native')
s.NAME = 'zunder-container-native'
s.UNIT = s.NAME + '.service'
s.IMAGE_RE = r'sha256:[a-f0-9]{64}'


def fixture_image_ready(config):
    images = s.docker_json('image', 'inspect', config['image'])
    s.require(len(images) == 1 and images[0]['Id'] == config['image'], 'Fixture immutable image ID mismatch.')
    s.require(images[0]['Config']['User'] == '65532:65532', 'Fixture must be nonroot.')


s.image_ready = fixture_image_ready
if __name__ == '__main__':
    # No install path and no signature bypass in the production helper.
    import sys
    s.require(sys.argv[1:] in (['run'], ['stop']), 'Fixture driver only supports lifecycle commands.')
    s.main()
