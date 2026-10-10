import {open, mkdir, lstat} from 'node:fs/promises';
import {join} from 'node:path';
import {canonical} from './protocol.mjs';
import {requireTrue, hex} from './relay-schema.mjs';

// Append-only sequence files: never reopen or adopt an existing session after a
// controller exit. File fsync precedes dispatch; unknown is retained forever.
export class OriginalJournal {
  #directory; #sequence = 0; #held = false;
  static async create(parent, session) {
    requireTrue(hex(session) && parent.startsWith('/'));
    const stat = await lstat(parent); requireTrue(stat.isDirectory() && !stat.isSymbolicLink() && stat.uid === process.getuid() && (stat.mode & 0o077) === 0);
    const directory = join(parent,session); await mkdir(directory,{mode:0o700});
    const journal = new OriginalJournal(); journal.#directory = directory;
    await journal.append({kind:'ORIGINAL',session}); return journal;
  }
  async append(value) {
    requireTrue(!this.#held);
    const fd = await open(join(this.#directory,`${String(this.#sequence).padStart(4,'0')}.json`),'wx',0o600);
    try { await fd.writeFile(canonical(value)+'\n'); await fd.sync(); } finally { await fd.close(); }
    const directory = await open(this.#directory,'r'); try { await directory.sync(); } finally { await directory.close(); }
    this.#sequence++;
  }
  async hold(reason) { if(this.#held) return; await this.append({kind:'UNKNOWN',reason}); this.#held = true; }
}
