#!/usr/bin/env python3
"""Boot/reboot only our disposable QEMU guest. Never uses or restarts the host Docker daemon.

Requires qemu-system-x86, qemu-utils, cloud-image-utils, ubuntu-cloudimage-keyring,
gpgv, OpenSSH client, curl. Run on the dedicated GitHub Actions job; no cloud account.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile
import tempfile
import time
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
IMAGE_DIR = 'https://cloud-images.ubuntu.com/releases/noble/release-20260911/'
IMAGE = 'ubuntu-24.04-server-cloudimg-amd64.img'
IMAGE_SHA = '612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354'
SAFE = dict(PATH=os.environ.get('PATH', '/usr/bin:/bin'), HOME=os.environ.get('HOME', '/tmp'), LANG='C.UTF-8')


def run(argv, *, timeout=300, check=True):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=SAFE, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        if check:
            raise
        # Readiness probes retry until their enclosing startup/reboot deadline.
        return ''
    if check and result.returncode != 0:
        detail = result.stderr.decode(errors='replace').replace('ab' * 32, '[synthetic credential redacted]')[:4000]
        raise RuntimeError('Disposable VM command failed: ' + argv[0] + ': ' + detail)
    return result.stdout.decode().strip()


def main(output):
    output.mkdir(parents=True, exist_ok=True)
    marker = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix='zunder-container-guest-') as folder:
        temp = Path(folder)
        for asset in (IMAGE, 'SHA256SUMS', 'SHA256SUMS.gpg'):
            run(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
                 '--output', str(temp / asset), IMAGE_DIR + asset], timeout=900)
        run(['gpgv', '--keyring', '/usr/share/keyrings/ubuntu-cloudimage-keyring.gpg',
             str(temp / 'SHA256SUMS.gpg'), str(temp / 'SHA256SUMS')])
        entries = [line.split()[0] for line in (temp / 'SHA256SUMS').read_text().splitlines()
                   if len(line.split()) == 2 and line.split()[1].lstrip('*') == IMAGE]
        if entries != [IMAGE_SHA]:
            raise RuntimeError('Guest signed checksum differs from pinned Ubuntu image.')
        with (temp / IMAGE).open('rb') as stream:
            actual = hashlib.file_digest(stream, 'sha256').hexdigest()
        if actual != IMAGE_SHA:
            raise RuntimeError('Guest image checksum mismatch.')
        run(['qemu-img', 'create', '-f', 'qcow2', '-F', 'qcow2', '-b', str(temp / IMAGE), str(temp / 'guest.qcow2')])
        run(['qemu-img', 'resize', str(temp / 'guest.qcow2'), '14G'])
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(temp / 'ssh-key')])
        public = (temp / 'ssh-key.pub').read_text().strip()
        user_data = '#cloud-config\n' + json.dumps({
            'users': [{'name': 'ubuntu', 'shell': '/bin/bash', 'groups': ['sudo'],
                       'sudo': ['ALL=(ALL) NOPASSWD:ALL'], 'ssh_authorized_keys': [public]}],
            'package_update': True, 'packages': ['docker.io', 'python3', 'ca-certificates'],
            'write_files': [{'path': '/etc/zunder-native-disposable', 'owner': 'root:root',
                             'permissions': '0600', 'content': marker + '\n'}],
            'runcmd': [['systemctl', 'enable', '--now', 'docker.service']],
        }) + '\n'
        (temp / 'user-data').write_text(user_data)
        (temp / 'meta-data').write_text(json.dumps({'instance-id': marker, 'local-hostname': 'zunder-container-native'}))
        run(['cloud-localds', str(temp / 'seed.img'), str(temp / 'user-data'), str(temp / 'meta-data')])
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
        acceleration = 'kvm' if os.access('/dev/kvm', os.R_OK | os.W_OK) else 'tcg'
        cmd = ['qemu-system-x86_64', '-machine', 'q35', '-accel', acceleration, '-m', '4096', '-smp', '2',
               '-drive', 'file=' + str(temp / 'guest.qcow2') + ',format=qcow2,if=virtio',
               '-drive', 'file=' + str(temp / 'seed.img') + ',format=raw,if=virtio',
               '-nic', f'user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{port}-:22', '-nographic']
        ssh_base = ['ssh', '-i', str(temp / 'ssh-key'), '-p', str(port),
                    '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5', '-o', 'StrictHostKeyChecking=accept-new',
                    '-o', 'UserKnownHostsFile=' + str(temp / 'known-hosts'), 'ubuntu@127.0.0.1']
        def ssh(command, **kwargs):
            return run([*ssh_base, command], **kwargs)
        with (temp / 'qemu.log').open('wb') as log:
            process = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log, env=SAFE)
        try:
            deadline = time.monotonic() + 900
            while True:
                if process.poll() is not None:
                    raise RuntimeError('QEMU guest exited before startup.')
                if ssh('printf ready', timeout=10, check=False) == 'ready':
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('SSH guest startup deadline exceeded.')
                time.sleep(3)
            ssh('sudo cloud-init status --wait', timeout=1200)
            archive = temp / 'source.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                for path in ('deploy/guard/container', 'deploy/guard/test/container-native'):
                    tar.add(REPO / path, arcname=path, filter=lambda info: None if '__pycache__' in info.name else info)
            run(['scp', '-i', str(temp / 'ssh-key'), '-P', str(port), '-o', 'BatchMode=yes',
                 '-o', 'UserKnownHostsFile=' + str(temp / 'known-hosts'), str(archive), 'ubuntu@127.0.0.1:source.tar.gz'])
            ssh('sudo mkdir -p /opt/zunder-native-src && sudo tar -xzf source.tar.gz -C /opt/zunder-native-src')
            guest = 'sudo /usr/bin/python3 /opt/zunder-native-src/deploy/guard/test/container-native/guest.py '
            ssh(guest + 'setup --marker ' + marker, timeout=1200)
            ssh(guest + 'exercise --marker ' + marker, timeout=1200)
            installer = 'sudo /usr/bin/python3 /opt/zunder-native-src/deploy/guard/test/container-native/installer.py '
            ssh(installer + 'setup --marker ' + marker, timeout=1200)
            old_boot = ssh('cat /proc/sys/kernel/random/boot_id')
            ssh('sudo systemctl reboot', check=False)
            deadline = time.monotonic() + 600
            while True:
                boot = ssh('cat /proc/sys/kernel/random/boot_id', timeout=10, check=False)
                if boot and boot != old_boot:
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError('No actual guest reboot observed before deadline.')
                time.sleep(3)
            ssh(guest + 'after-reboot --marker ' + marker, timeout=360)
            ssh(installer + 'after-reboot --marker ' + marker, timeout=360)
            installer_record = json.loads(ssh('sudo cat /var/lib/zunder-container-installer-native/evidence.json'))
            if installer_record['status'] != 'passed-native-synthetic-installer-subset':
                raise RuntimeError('Native installer transaction subset did not pass.')
            (output / 'installer-evidence.json').write_text(json.dumps(installer_record, indent=2) + '\n')
            record = json.loads(ssh('sudo cat /var/lib/zunder-container-native/evidence.json'))
            if record['status'] != 'passed-native-synthetic-lifecycle':
                raise RuntimeError('Guest lifecycle did not pass.')
            record['guest_acceleration'] = acceleration
            record['guest_image_sha256'] = IMAGE_SHA
            record['guest_image_url'] = IMAGE_DIR + IMAGE
            (output / 'evidence.json').write_text(json.dumps(record, indent=2) + '\n')
            print('Native synthetic container lifecycle passed, including actual guest kernel reboot.')
        except Exception:
            # Only the fixture's redacted structured receipt is collected, never SSH keys,
            # decrypted credentials, raw Docker environments or entire guest file trees.
            try:
                data = ssh('sudo cat /var/lib/zunder-container-native/evidence.json', check=False)
                if data:
                    record = json.loads(data)
                    record['host_harness_result'] = 'failed-or-incomplete'
                    (output / 'incomplete-evidence.json').write_text(json.dumps(record, indent=2) + '\n')
            except Exception:
                pass
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    main(parser.parse_args().output.resolve())
