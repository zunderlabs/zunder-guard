"""Public-owned, pre-custody website preparation. Never an admission/grant.

The caller must have authenticated the reviewed private source and revoked its
reader token. No downloaded shell/npm helper is executed. All compilation uses
this fixed public recipe, without provider/publisher/payment credentials. The
original keeper must subsequently inventory ALL retained runtime bytes; this
receipt is provenance only. Run on a disposable public Ubuntu x64 runner only.
"""
import json
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import subprocess
import tempfile
import tomllib

from .contracts import ROOT, canonical, decode, digest, need, sha
from .inventory import read

PACKAGES = ROOT / 'runtime/website'
INPUT = PACKAGES / 'build-input'
SOURCE = PACKAGES / 'build-source'
TOOLS = PACKAGES / 'build-tools'
TOOLCHAIN = '1.97.0'
CORE = {'astro': '7.3.5', 'esbuild': '0.28.2', 'vite': '8.3.2',
        'rolldown': '1.2.12', '@rolldown/binding-linux-x64-gnu': '1.2.12'}
ROL_NATIVE = 'node_modules/@rolldown/binding-linux-x64-gnu/rolldown-binding.linux-x64-gnu.node'
STUBS = {'sharp': 'astro/stubs/sharp', 'lightningcss': 'vite/stubs/lightningcss'}

# Exact locked empty text modules/fixture. Do not normalize arbitrary empties.
EMPTY_TOOL_FILES = frozenset((
    'node_modules/@noble/hashes/index.d.ts',
    'node_modules/astro/dist/actions/runtime/types.js',
    'node_modules/astro/dist/assets/fonts/definitions.js',
    'node_modules/astro/dist/assets/fonts/types.js',
    'node_modules/astro/dist/assets/svg/types.js',
    'node_modules/astro/dist/assets/utils/vendor/image-size/types/interface.js',
    'node_modules/astro/dist/cli/create-key/definitions.js',
    'node_modules/astro/dist/cli/definitions.js',
    'node_modules/astro/dist/cli/docs/definitions.js',
    'node_modules/astro/dist/cli/docs/domain/cloud-ide.js',
    'node_modules/astro/dist/cli/domain/help-payload.js',
    'node_modules/astro/dist/cli/info/definitions.js',
    'node_modules/astro/dist/cli/info/domain/debug-info.js',
    'node_modules/astro/dist/content/loaders/types.js',
    'node_modules/astro/dist/core/app/types.js',
    'node_modules/astro/dist/core/build/types.js',
    'node_modules/astro/dist/core/cache/types.js',
    'node_modules/astro/dist/core/compile/types.js',
    'node_modules/astro/dist/core/fetch/types.js',
    'node_modules/astro/dist/core/logger/config.js',
    'node_modules/astro/dist/core/session/types.js',
    'node_modules/astro/dist/core/wait-until.js',
    'node_modules/astro/dist/transitions/types.js',
    'node_modules/astro/dist/type-utils.js',
    'node_modules/astro/dist/types/astro.js',
    'node_modules/astro/dist/types/public/common.js',
    'node_modules/astro/dist/types/public/config.js',
    'node_modules/astro/dist/types/public/content.js',
    'node_modules/astro/dist/types/public/context.js',
    'node_modules/astro/dist/types/public/elements.js',
    'node_modules/astro/dist/types/public/extendables.js',
    'node_modules/astro/dist/types/public/index.js',
    'node_modules/astro/dist/types/public/integrations.js',
    'node_modules/astro/dist/types/public/internal.js',
    'node_modules/astro/dist/types/public/manifest.js',
    'node_modules/astro/dist/types/public/preview.js',
    'node_modules/astro/dist/types/public/toolbar.js',
    'node_modules/astro/dist/types/public/view-transitions.js',
    'node_modules/astro/dist/types/typed-emitter.js',
    'node_modules/astro/dist/vite-plugin-astro/types.js',
    'node_modules/ethers/src.ts/utils/test.txt',
    'node_modules/node-fetch-native/lib/empty.cjs',
    'node_modules/node-fetch-native/lib/empty.mjs',
))
SOURCE_PREFIXES = ('web/site/src/', 'web/site/public/', 'web/site/scripts/',
                   'web/site/stubs/', 'web/docs-content/', 'web/waitlist/src/',
                   'web/waitlist/migrations/', 'web/waitlist/testnet-inbox-migrations/')
SOURCE_FILES = {'web/site/package.json', 'web/site/package-lock.json',
                'web/site/astro.config.mjs', 'web/site/tsconfig.json',
                'web/site/LICENSES.md', 'web/site/LICENSES.wasm.md',
                'web/site/LICENSES.generated.md', 'web/release-pin.ts',
                'web/deployment-profile.ts', 'web/testnet-journey/provision/lease.ts',
                *('web/testnet-journey/provision/'+n+'.entry.ts' for n in ('api', 'inbox', 'pages'))}
REQUIRED = {'web/site/public/live/src/engine.js',
            'web/site/public/live/pkg/zunder_risk_wasm_bg.wasm',
            'web/site/public/live/pkg/zunder_risk_wasm.js', 'web/site/LICENSES.wasm.md',
            'web/site/LICENSES.md', 'web/site/astro.config.mjs', 'web/release-pin.ts',
            'web/site/package.json', 'web/site/package-lock.json', 'web/deployment-profile.ts',
            'web/waitlist/testnet-inbox-migrations/0001_inbox.sql',
            *('web/site/scripts/'+n for n in ('copy-fonts.mjs', 'engine-defaults.mjs',
               'sample-snapshot.mjs', 'sync-docs.mjs', 'licenses.mjs', 'after-paint.mjs',
               'approve-csp.mjs', 'check-pages.mjs', 'check-placeholders.mjs', 'deployment-build.ts')),
            *('web/waitlist/migrations/'+n for n in ('0001_init.sql', '0002_licences.sql',
               '0003_licence_watch_start.sql', '0004_licence_renewal.sql')),
            *('web/waitlist/src/'+n for n in ('testnet-index.ts', 'testnet-inbox.ts', 'testnet-pages.ts')),
            'web/testnet-journey/provision/lease.ts',
            *('web/testnet-journey/provision/'+n+'.entry.ts' for n in ('api', 'inbox', 'pages'))}
ALLOWED = {'MIT', 'Apache-2.0', 'Unlicense', 'BSD-2-Clause', 'BSD-3-Clause',
           'ISC', 'Zlib', 'Unicode-3.0', 'BSL-1.0', 'Apache-2.0 WITH LLVM-exception', 'CC0-1.0'}


def member(name):
    need(type(name) is str and 0 < len(name) <= 512 and not name.startswith('/') and
         all(re.fullmatch(r'[A-Za-z0-9_.@+$\[\]-]+', p) and
             p.lower() not in ('.', '..', '.git', '.npmrc', '.netrc', '.ssh', '.aws',
                              '__proto__', 'prototype', 'constructor') and
             not p.lower().startswith('.env') and not re.search(r'\.(pem|key)$', p, re.I)
             for p in name.split('/')), 'Website preparation held')
    return name


def no_credentials(env):
    """A caller precondition, not proof that the whole runner has no credentials."""
    blocked = {'GITHUB_TOKEN', 'GH_TOKEN', 'NODE_OPTIONS', 'NODE_PATH', 'RUSTC_WRAPPER',
               'RUSTC_WORKSPACE_WRAPPER', 'CARGO_HOME', 'RUSTUP_HOME', 'NPM_CONFIG_USERCONFIG'}
    for name in env:
        need(name not in blocked and not re.search(r'(TOKEN|SECRET|PASSWORD|CREDENTIAL|PRIVATE_KEY|ACCESS_KEY)', name, re.I)
             and not name.startswith(('AWS_', 'CLOUDFLARE_', 'WAITLIST_', 'LD_', 'DYLD_')),
             'Website preparation held')


def inventory(root, maximum=50000):
    root = Path(root)
    need(root.is_absolute() and root.resolve(strict=True) == root and root.is_dir(), 'Website preparation held')
    rows = {}; seen = set(); total = 0
    for p in sorted(root.rglob('*')):
        st = p.lstat()
        need(stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode), 'Website preparation held')
        if stat.S_ISDIR(st.st_mode): continue
        name = member(str(p.relative_to(root))); lower = name.lower()
        need(lower not in seen and 0 < st.st_size <= 64*1024*1024 and st.st_nlink == 1,
             'Website preparation held')
        seen.add(lower); total += st.st_size
        need(total <= 768*1024*1024 and len(rows) < maximum, 'Website preparation held')
        rows[name] = digest(read(p, 64*1024*1024, protected=False))
    need(rows and all(not any('/'.join(k.split('/')[:i]).lower() in seen
         for i in range(1, len(k.split('/')))) for k in rows), 'Website preparation held')
    return {'schema': 1, 'files': rows}


def ref_bytes(ref, maximum=16*1024*1024):
    need(type(ref) is dict and set(ref) == {'file', 'sha256'}, 'Website preparation held')
    sha(ref['sha256']); p = Path(ref['file'])
    need(p.is_absolute() and p.resolve(strict=True) == p, 'Website preparation held')
    data = read(p, maximum, protected=False)
    need(digest(data) == ref['sha256'], 'Website preparation held')
    return data


def stage_input(ref):
    need(ref.get('file') == str(INPUT/'stage-receipt.json'), 'Website preparation held')
    receipt = decode(ref_bytes(ref))
    need(set(receipt) == {'schema', 'purpose', 'privateRepository', 'sourceCommit', 'sourceRef',
         'producer', 'artifact', 'inventorySha256', 'manifestSha256', 'source', 'candidate',
         'rawManifest', 'readerTokenRevoked'} and receipt['schema'] == 1 and
         receipt['purpose'] == 'original-guard-website-build-input' and
         receipt['readerTokenRevoked'] is True and
         type(receipt['privateRepository']) is dict and set(receipt['privateRepository']) == {'id', 'fullName'} and
         type(receipt['privateRepository']['id']) is int and receipt['privateRepository']['id'] > 0 and
         receipt['privateRepository']['fullName'] == 'zunderlabs/zunder' and
         receipt['sourceRef'] == 'refs/heads/main', 'Website preparation held')
    sha(receipt['sourceCommit'], 40)
    source = receipt['source']
    need(type(source) is dict and set(source) == {'root', 'manifest'} and
         source['root'] == str(SOURCE) and source['manifest']['file'] == str(INPUT/'source.json') and
         receipt['candidate']['file'] == str(INPUT/'candidate.json') and
         receipt['rawManifest']['file'] == str(INPUT/'raw-manifest.json'), 'Website preparation held')
    raw_inventory = ref_bytes(source['manifest']); raw_manifest = ref_bytes(receipt['rawManifest'])
    raw = decode(raw_manifest, 16*1024*1024)
    # Raw ordered wire inventory has a different digest from source.json.
    need(type(raw) is dict and type(raw.get('files')) is list and
         digest(json.dumps(raw['files'], ensure_ascii=True, separators=(',', ':')).encode()) == receipt['inventorySha256'] and
         digest(raw_manifest) == receipt['manifestSha256'] and raw.get('transformations') == [], 'Website preparation held')
    wanted = decode(raw_inventory)
    need(wanted == inventory(SOURCE, 12000), 'Website preparation held')
    # Authenticated candidate is data consumed later by the original keeper.
    candidate = decode(ref_bytes(receipt['candidate']))
    need(type(candidate) is dict and candidate.get('sourceCommit') and
         type(candidate.get('published')) is bool, 'Website preparation held')
    return receipt, wanted


def environment(scratch, node):
    return {'HOME': str(scratch/'home'), 'TMPDIR': str(scratch/'tmp'),
            'CARGO_HOME': str(scratch/'cargo'), 'RUSTUP_HOME': str(scratch/'rustup'),
            'CARGO_TARGET_DIR': str(scratch/'target'), 'LANG': 'C', 'LC_ALL': 'C',
            'CI': '1', 'ASTRO_TELEMETRY_DISABLED': '1',
            'PATH': str(Path(node).parent)+':/usr/bin:/bin',
            'NPM_CONFIG_CACHE': str(scratch/'npm'), 'NPM_CONFIG_USERCONFIG': '/dev/null',
            'NPM_CONFIG_IGNORE_SCRIPTS': 'true', 'NPM_CONFIG_AUDIT': 'false',
            'NPM_CONFIG_FUND': 'false'}


def command_plan(scratch, refs, bindgen_version):
    """Fixed argv only: no caller command, shell, downloaded script or npm hook."""
    need(re.fullmatch(r'0\.[0-9]+\.[0-9]+', bindgen_version), 'Website preparation held')
    src = scratch/'source'; live = src/'web/live'; site = src/'web/site'
    rust = refs['rustup']['file']; node = refs['node']['file']; npm = refs['npm']['file']
    cargo = lambda args: [rust, 'run', TOOLCHAIN, 'cargo', *args]
    return [
        ('toolchain', scratch, [rust, 'toolchain', 'install', TOOLCHAIN, '--profile', 'minimal', '--target', 'wasm32-unknown-unknown']),
        ('wasm-bindgen', src, cargo(['install', '--locked', 'wasm-bindgen-cli', '--version', bindgen_version, '--root', str(scratch/'bindgen')])),
        ('cargo-fetch', src, cargo(['fetch', '--locked'])),
        ('live-deps', live, [node, npm, 'ci', '--ignore-scripts', '--no-audit', '--no-fund']),
        ('wasm', src, cargo(['build', '--locked', '--offline', '-q', '-p', 'zunder-risk-wasm', '--target', 'wasm32-unknown-unknown', '--profile', 'wasm'])),
        ('wasm-glue', live, [str(scratch/'bindgen/bin/wasm-bindgen'), '--target', 'web', '--remove-name-section', '--remove-producers-section', '--out-dir', str(live/'pkg'), str(scratch/'target/wasm32-unknown-unknown/wasm/zunder_risk_wasm.wasm')]),
        ('live-types', live, [node, '--no-global-search-paths', '--no-addons', str(live/'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json', '--noEmit']),
        ('live-tests', live, [node, '--no-global-search-paths', '--no-addons', '--test', '--test-reporter=spec', 'test/*.test.ts']),
        ('live-build', live, [node, '--no-global-search-paths', '--no-addons', str(live/'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.build.json']),
        ('wasm-licenses', src, cargo(['tree', '--locked', '--offline', '-q', '-p', 'zunder-risk-wasm', '--target', 'wasm32-unknown-unknown', '-e', 'normal', '--prefix', 'none', '-f', '{p}|{l}'])),
        ('site-deps', site, [node, npm, 'install', '--ignore-scripts', '--no-audit', '--no-fund']),
    ]


def licenses(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 1024*1024, 'Website preparation held')
    rows = {}
    for line in raw.decode('utf-8', errors='strict').splitlines():
        parts = line.strip().split('|'); need(len(parts) <= 2, 'Website preparation held')
        if not parts[0]: continue
        # Cargo {p} also includes workspace path suffixes. Consume them without
        # carrying a private source path into the rendered licence table.
        m = re.fullmatch(r'([A-Za-z0-9_-]+) v([A-Za-z0-9_.+-]+)((?: \((?:proc-macro|\*|/[A-Za-z0-9_./+-]+)\))*)', parts[0])
        need(m, 'Website preparation held')
        name, version = m.group(1, 2)
        expression = re.sub(r'\s*\(\*\)\s*$', '', parts[1] if len(parts) == 2 else '').strip()
        if not expression and name.startswith('zunder'): expression = 'proprietary (this repository)'
        permitted = any(all(x.replace('(', '').replace(')', '').strip() in ALLOWED
                        for x in re.split(r'\s+AND\s+', branch))
                        for branch in re.split(r'\s+OR\s+|/', expression))
        need(name.startswith('zunder') or permitted, 'Website preparation held')
        need('|' not in expression and len(expression) <= 256, 'Website preparation held')
        rows[(name, version)] = (name+(' (build time only)' if '(proc-macro)' in m.group(3) else ''), version, expression)
    need(rows and len(rows) <= 512 and any(n == 'zunder-risk-wasm' for n, _ in rows), 'Website preparation held')
    text = ['## Compiled into the risk engine', '',
            'The crates in the WebAssembly module your browser runs (`zunder-risk-wasm`, built for `wasm32-unknown-unknown`), from `cargo tree`: '+str(len(rows))+' crates. The JavaScript glue that loads it is generated by wasm-bindgen (MIT or Apache-2.0).', '',
            '| Crate | Version | Licence |', '|---|---|---|',
            *('| '+' | '.join(r)+' |' for r in sorted(rows.values())), '']
    return '\n'.join(text).encode()


def elf_x64(raw):
    need(len(raw) >= 20 and raw[:6] == b'\x7fELF\x02\x01' and raw[18:20] == b'\x3e\x00', 'Website preparation held')


def write_file(path, data, executable=False):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700 if executable else 0o600)
    with os.fdopen(fd, 'wb') as f: f.write(data); f.flush(); os.fsync(f.fileno())


def run_fixed(argv, cwd, env, output):
    """No public compiler diagnostics; timeout kills the process group as well."""
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                             stdout=output, stderr=subprocess.DEVNULL,
                             shell=False, start_new_session=True)
    try:
        return child.wait(timeout=1800)
    except BaseException:
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        child.wait()
        raise RuntimeError('Website preparation held') from None


def normalize_tools(site):
    root = site/'node_modules'; transformations = []
    # npm's two repository-local overrides have fixed source-owned substitutes.
    for name, target in STUBS.items():
        p = root/name
        if p.is_symlink():
            need(os.readlink(p) == target, 'Website preparation held')
            p.unlink()
            src = site/'stubs'/name
            inventory(src, 32); shutil.copytree(src, p)
            transformations.append({'kind': 'fixed-source-stub', 'path': 'node_modules/'+name})
    for p in sorted(root.rglob('*')):
        if not p.is_symlink(): continue
        need(p.parent.name == '.bin', 'Website preparation held')
        target = p.resolve(strict=True)
        need(target.is_relative_to(root) and target.is_file(), 'Website preparation held')
        transformations.append({'kind': 'omit-bin-alias', 'path': str(p.relative_to(site)),
                                'target': str(target.relative_to(site))})
        p.unlink()
    for p in sorted(root.rglob('.bin'), reverse=True):
        need(p.is_dir() and not any(p.iterdir()), 'Website preparation held'); p.rmdir()
    for p in sorted(root.rglob('*')):
        info = p.lstat()
        need(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'Website preparation held')
        if not stat.S_ISREG(info.st_mode) or info.st_size != 0: continue
        name = member(str(p.relative_to(site)))
        need(name in EMPTY_TOOL_FILES and read(p, 0, protected=False) == b'', 'Website preparation held')
        # Empty JS/typing modules remain importable; the one exact empty .txt
        # fixture likewise gets LF. Never change JSON/native/unknown empties.
        p.unlink(); write_file(p, b'\n')
        transformations.append({'kind': 'fixed-empty-text-lf', 'path': name,
                                'beforeSha256': digest(b''), 'sha256': digest(b'\n')})
    native = root/'@esbuild/linux-x64/bin/esbuild'; data = read(native, 64*1024*1024, protected=False); elf_x64(data)
    installed = root/'esbuild/bin/esbuild'; before = digest(read(installed, 64*1024*1024, protected=False))
    installed.unlink(); write_file(installed, data, True)
    transformations.append({'kind': 'fixed-esbuild-elf', 'path': 'node_modules/esbuild/bin/esbuild',
                            'beforeSha256': before, 'sha256': digest(data)})
    for name, version in CORE.items():
        pkg = decode(read(root/name/'package.json', protected=False))
        need(pkg.get('name') == name and pkg.get('version') == version and pkg.get('license') == 'MIT', 'Website preparation held')
    native_pkg = decode(read(root/'@esbuild/linux-x64/package.json', protected=False))
    need(native_pkg.get('name') == '@esbuild/linux-x64' and native_pkg.get('version') == '0.28.2' and
         native_pkg.get('license') == 'MIT', 'Website preparation held')
    elf_x64(read(site/ROL_NATIVE, 64*1024*1024, protected=False))
    return transformations


def prepare(stage_ref, tool_refs):
    """Only generic public failures escape; filesystem errors may name inputs."""
    try:
        return _prepare(stage_ref, tool_refs)
    except Exception:
        raise RuntimeError('Website preparation held') from None


def _prepare(stage_ref, tool_refs):
    no_credentials(os.environ)
    need(os.name == 'posix' and os.uname().sysname == 'Linux' and os.uname().machine == 'x86_64' and
         os.geteuid() == 0 and set(tool_refs) == {'node', 'npm', 'rustup'}, 'Website preparation held')
    need(tool_refs['node']['file'] == str(ROOT/'runtime/node/bin/node') and
         tool_refs['npm']['file'] == str(ROOT/'runtime/node/lib/node_modules/npm/bin/npm-cli.js') and
         Path(tool_refs['rustup']['file']).name == 'rustup', 'Website preparation held')
    for ref in (*tool_refs.values(), stage_ref):
        data = read(Path(ref['file']), 128*1024*1024, protected=True)
        need(digest(data) == ref['sha256'], 'Website preparation held')
    receipt, raw_inv = stage_input(stage_ref)
    need(not TOOLS.exists() and not (INPUT/'built-source.json').exists() and
         not (INPUT/'built-tools.json').exists() and not (INPUT/'preparation.json').exists(), 'Website preparation held')
    scratch = Path(tempfile.mkdtemp(prefix='zunder-website-preparation-', dir='/var/tmp')).resolve()
    try:
        for n in ('home', 'tmp', 'cargo', 'rustup', 'npm'): (scratch/n).mkdir(mode=0o700)
        src = scratch/'source'; src.mkdir(mode=0o700)
        for name, h in raw_inv['files'].items():
            data = read(SOURCE/name, 64*1024*1024, protected=True); need(digest(data) == h, 'Website preparation held')
            write_file(src/name, data)
        toolchain = tomllib.loads(read(src/'rust-toolchain.toml', protected=False).decode())
        need(toolchain.get('toolchain', {}).get('channel') == TOOLCHAIN, 'Website preparation held')
        cargo = tomllib.loads(read(src/'Cargo.lock', protected=False).decode())
        versions = {p['version'] for p in cargo.get('package', []) if p.get('name') == 'wasm-bindgen'}
        need(len(versions) == 1, 'Website preparation held'); wb = next(iter(versions))
        env = environment(scratch, tool_refs['node']['file']); wasm_license = None
        site_lock = read(src/'web/site/package-lock.json', protected=False)
        # Public caller owns refs/review; hashing does not invent tool authority.
        for stage, cwd, argv in command_plan(scratch, tool_refs, wb):
            for ref in tool_refs.values(): ref_bytes(ref, 128*1024*1024)
            capture = scratch/'cargo-licenses.txt'
            with capture.open('xb') if stage == 'wasm-licenses' else open(os.devnull, 'wb') as output:
                code = run_fixed(argv, cwd, env, output)
            need(code == 0, 'Website preparation held: '+stage)
            if stage == 'wasm-licenses': wasm_license = licenses(read(capture, 1024*1024, protected=False))
        need(read(src/'web/site/package-lock.json', protected=False) == site_lock, 'Website preparation held')
        need(wasm_license is not None, 'Website preparation held')
        live = src/'web/live'; generated = inventory(live/'dist', 2000)
        need('src/engine.js' in generated['files'], 'Website preparation held')
        glue = read(live/'pkg/zunder_risk_wasm.js', protected=False)
        wasm = read(live/'pkg/zunder_risk_wasm_bg.wasm', 64*1024*1024, protected=False)
        need(wasm[:8] == b'\x00asm\x01\x00\x00\x00', 'Website preparation held')
        destination = SOURCE/'web/site/public/live'
        if destination.exists(): inventory(destination, 2000); shutil.rmtree(destination)
        for name, h in generated['files'].items():
            need(name.startswith('src/') and not name.endswith('.map'), 'Website preparation held')
            data = read(live/'dist'/name, protected=False); need(digest(data) == h, 'Website preparation held')
            write_file(destination/name, data)
        write_file(destination/'pkg/zunder_risk_wasm.js', glue); write_file(destination/'pkg/zunder_risk_wasm_bg.wasm', wasm)
        licence_path = SOURCE/'web/site/LICENSES.wasm.md'
        if licence_path.exists(): read(licence_path, protected=False); licence_path.unlink()
        write_file(licence_path, wasm_license)
        transforms = normalize_tools(src/'web/site')
        tool_inventory = inventory(src/'web/site/node_modules')
        TOOLS.mkdir(mode=0o700)
        for name, h in tool_inventory['files'].items():
            p = src/'web/site/node_modules'/name; data = read(p, 64*1024*1024, protected=False)
            need(digest(data) == h, 'Website preparation held')
            write_file(TOOLS/'node_modules'/name, data, name == 'esbuild/bin/esbuild' or data[:4] == b'\x7fELF')
        full = inventory(SOURCE, 12000)
        rows = {k: v for k, v in full['files'].items() if k in SOURCE_FILES or k.startswith(SOURCE_PREFIXES)}
        need(REQUIRED <= rows.keys(), 'Website preparation held')
        source_ref = {'file': str(INPUT/'built-source.json'), 'sha256': digest(canonical({'schema': 1, 'files': rows}))}
        tools_rows = inventory(TOOLS)['files']
        tools_ref = {'file': str(INPUT/'built-tools.json'), 'sha256': digest(canonical({'schema': 1, 'files': tools_rows}))}
        write_file(Path(source_ref['file']), canonical({'schema': 1, 'files': rows}))
        write_file(Path(tools_ref['file']), canonical({'schema': 1, 'files': tools_rows}))
        proof = {'schema': 1, 'purpose': 'public-fixed-pre-custody-website-preparation',
                 'rawStage': stage_ref, 'sourceCommit': receipt['sourceCommit'], 'candidate': receipt['candidate'],
                 'website': {'root': str(SOURCE), 'manifest': source_ref},
                 'tools': {'root': str(TOOLS), 'manifest': tools_ref}, 'executable': tool_refs['node'],
                 'toolRefs': tool_refs, 'toolchain': TOOLCHAIN, 'wasmBindgen': wb,
                 'generated': {str(p.relative_to(SOURCE)): digest(read(p, protected=False)) for p in
                               (licence_path, destination/'pkg/zunder_risk_wasm.js', destination/'pkg/zunder_risk_wasm_bg.wasm', destination/'src/engine.js')},
                 'transformations': transforms, 'runtimeAdmitted': False, 'releaseReady': False}
        raw = canonical(proof); write_file(INPUT/'preparation.json', raw)
        return {'file': str(INPUT/'preparation.json'), 'sha256': digest(raw)}
    finally:
        # Scratch is never a public artifact/cache or retained runtime root.
        shutil.rmtree(scratch)
