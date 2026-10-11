// Copyright 2026 Orcastrate UG (haftungsbeschränkt)
// SPDX-License-Identifier: Elastic-2.0
import { spawn } from 'node:child_process';

export function command(module: string, args: string[], env: NodeJS.ProcessEnv, input = ''): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.env['GUARD_PYTHON'] ?? 'python', ['-m', module, ...args], {
      env, detached: true, stdio: ['pipe', 'ignore', 'ignore'],
    });
    const timer = setTimeout(() => {
      if (child.pid) { try { process.kill(-child.pid, 'SIGKILL'); } catch { /* exited */ } }
    }, 180_000);
    child.stdin.on('error', () => { /* exit handler returns only a fixed error */ });
    child.stdin.end(input);
    child.once('error', () => { clearTimeout(timer); reject(new Error('Purchase subprocess could not start')); });
    child.once('close', code => {
      clearTimeout(timer);
      if (code === 0) resolve(); else reject(new Error('Purchase subprocess failed; reconcile private receipts; never retry payment'));
    });
  });
}

