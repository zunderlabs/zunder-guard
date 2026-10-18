"""Offline Linux distribution regressions. Archives, signatures and binary are test doubles."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import stat
import subprocess
import tarfile
import tempfile
import unittest

GUARD = Path(__file__).resolve().parents[1]
TAG = 'v0.0.0'
IMAGE = 'ghcr.io/zunderlabs/zunder-guard@sha256:' + 'b' * 64
NOTICES = ('LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.md')


# The code that writes the protected machine tree, as PowerShell code with strings and
# comments blanked: the shared trust code, the loader's managed path, the helper's
# lifecycle, and i.ps1 without its per-user %LOCALAPPDATA% install (named below).
PER_USER_FUNCTIONS = frozenset({'Install-ZunderGuard'})
BANNED_CREATION = (
    r'\bOut-File\b', r'\bSet-Content\b', r'\bAdd-Content\b', r'\bTee-Object\b',
    r'\bStart-Transcript\b', r'\bCopy-Item\b', r'\bMove-Item\b', r'\bExpand-Archive\b',
    r'ExtractToDirectory', r'\bNew-Item\b[^\n]*-ItemType\s+(File|Directory)',
    r'\[(System\.)?IO\.File\]::(Open|OpenWrite|AppendAllText|AppendAllLines|AppendText|'
    r'WriteAllLines|WriteAllText|WriteAllBytes|CreateText|Create|Copy)\(',
    r'\[(System\.)?IO\.StreamWriter\]::new\(',
    r'New-Object\s+(-TypeName\s+)?(System\.)?IO\.(StreamWriter|FileStream)',
    r'\[(System\.)?IO\.FileInfo\]::new\([^)]*\)\.(Create|Open|OpenWrite|CreateText)\(',
    r'\[(System\.)?IO\.Directory\]::CreateDirectory\(\s*[^,()]+\)',
    r'OpenOrCreate', r'\[System\.IO\.FileStream\]::new\(',
    # A FileInfo (or other) variable creating or opening for write: .Create(), .CreateText(),
    # .OpenWrite(), .AppendText(), and .Open(mode...) with arguments (a zip entry's
    # argument-less .Open() reads).
    r'\$\w+\.(Create|CreateText|OpenWrite|AppendText)\(\s*\)', r'\$\w+\.Open\(\s*[^)\s]',
    # Aliases of the creating cmdlets, in command position.
    r'(?m)(?:^|[;|{(=])\s*(?:ni|mkdir|md|sc|ac|cp|cpi|copy|mv|mi|move|tee)(?=\s|$)',
    # File redirection: > and >> (2>&1 merges streams; > $null discards).
    r'(?<![\w\-=<>!&])\d?>>?(?!\s*(&|\$null))',
)
# Calls that create a file or folder. Each must pass an ACL that New-ZgAcl made in the
# same function (owner Administrators, protected DACL): a FileStream's last argument unless
# its mode is literally Open or Truncate (a mode in a variable counts as creating),
# FileSystemAclExtensions.Create's last, FileSystemAclExtensions.CreateDirectory's first and
# Directory.CreateDirectory's second (its one-argument form is banned above).
CREATING_PREFIXES = (
    '[IO.FileStream]::new(',
    '[IO.FileSystemAclExtensions]::Create(',
    '[IO.FileSystemAclExtensions]::CreateDirectory(',
    '[IO.Directory]::CreateDirectory(',
)
NON_CREATING_MODES = ('[IO.FileMode]::Open', '[IO.FileMode]::Truncate')


def ps_call_arguments(code, prefix):
    """The top-level arguments of every call starting with `prefix`, across lines."""
    start = code.find(prefix)
    while start >= 0:
        depth, i, args, current = 1, start + len(prefix), [], []
        while depth and i < len(code):
            c = code[i]
            if c in '([{':
                depth += 1
            elif c in ')]}':
                depth -= 1
            if depth == 1 and c == ',':
                args.append(''.join(current).strip())
                current = []
            elif depth:
                current.append(c)
            i += 1
        args.append(''.join(current).strip())
        yield start, [arg for arg in args if arg]
        start = code.find(prefix, i)


def creating_acl(prefix, args):
    """The ACL argument a creating call must carry, or None for an Open/Truncate stream."""
    if prefix == '[IO.FileStream]::new(':
        if len(args) >= 2 and args[1] in NON_CREATING_MODES:
            return None
        return args[-1] if args else ''
    if prefix == '[IO.FileSystemAclExtensions]::CreateDirectory(':
        return args[0] if args else ''
    return args[-1] if len(args) >= 2 else ''


def ps_code(text):
    """PowerShell text with string contents and comments blanked, lengths kept."""
    out, i, n = list(text), 0, len(text)
    while i < n:
        c = text[i]
        if c == '#' or text.startswith('<#', i):
            end = text.find('#>', i) + 2 if text.startswith('<#', i) else text.find('\n', i)
            end = n if end < (2 if text.startswith('<#', i) else 0) else end
            for j in range(i, end):
                if out[j] != '\n':
                    out[j] = ' '
            i = end
        elif c == "'":
            j = i + 1
            while j < n and not (text[j] == "'" and text[j + 1:j + 2] != "'"):
                j += 2 if text[j] == "'" else 1
            for k in range(i + 1, min(j, n)):
                if out[k] != '\n':
                    out[k] = ' '
            i = j + 1
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == '`' else 1
            for k in range(i + 1, min(j, n)):
                if out[k] != '\n':
                    out[k] = ' '
            i = j + 1
        else:
            i += 1
    return ''.join(out)


def ps_function_spans(code):
    spans = {}
    for match in re.finditer(r'(?mi)^[ \t]*function\s+([\w-]+)[^{\n]*\{', code):
        depth, i = 1, match.end()
        while depth and i < len(code):
            depth += {'{': 1, '}': -1}.get(code[i], 0)
            i += 1
        spans.setdefault(match[1], (match.start(), i))
    return spans


def ps_function_bodies(code):
    return {name: code[start:end] for name, (start, end) in ps_function_spans(code).items()}


def ps_function(code, text, name):
    """A function's original text (strings intact), located on the blanked code."""
    start, end = ps_function_spans(code)[name]
    return text[start:end]


def protected_sources():
    for relative in ('windows/bootstrap.ps1.inc', 'windows/lifecycle.ps1.inc',
                     'windows/loader-mainnet.ps1.inc', 'loader/i.ps1'):
        code = ps_code((GUARD / relative).read_text())
        if relative == 'loader/i.ps1':
            spans = ps_function_spans(code)
            assert PER_USER_FUNCTIONS <= set(spans), relative
            text = (GUARD / relative).read_text()
            for name in PER_USER_FUNCTIONS:
                start, end = spans[name]
                per_user = text[start:end]
                for machine in ('$ZgData', '$ZgBin', '$ZgRoot', '$ZgManagement', '$ZgHome',
                                '$ZgExe', 'CommonApplicationData', 'ProgramData',
                                'Get-ZgMachineFolder', 'New-ZgSecureFile', 'New-ZgDirectory'):
                    assert machine not in per_user, (name, machine)
            for name in PER_USER_FUNCTIONS:
                start, end = spans[name]
                code = code[:start] + ''.join('\n' if c == '\n' else ' ' for c in code[start:end]) + code[end:]
        yield relative, code


class WindowsAclPolicy(unittest.TestCase):
    """Offline bit-contract check; real PowerShell selector execution is in its fixture."""

    def test_service_can_open_the_shared_bases_and_nothing_more(self):
        # The SCM service's virtual account re-checks the two shared anchors'
        # owner and ACL at every start; without a read entry it cannot open
        # them and its admission refuses before Guard starts.
        lifecycle = (GUARD / 'windows/lifecycle.ps1.inc').read_text()
        body = re.search(r'function Set-ZgBaseAcl\(\[string\[\]\]\$Bases\) \{\n(.*?)\n\}\n', lifecycle, re.S)
        self.assertIsNotNone(body)
        self.assertIn("foreach ($base in $Bases)", body[1])
        # Always written, never skipped by a comparison that could miss an entry.
        self.assertNotIn("Test-ZgBaseAcl", lifecycle)
        self.assertIn("Microsoft.PowerShell.Security\\Set-Acl -LiteralPath $base -AclObject $acl",
                      body[1])
        grants = re.findall(r'FileSystemAccessRule\]::new\((.*?)\)\)$', body[1], re.M)
        self.assertEqual(len(grants), 1)
        self.assertEqual(
            grants[0],
            "[Security.Principal.SecurityIdentifier]::new('S-1-5-11'),'ReadAndExecute',"
            "[Security.AccessControl.InheritanceFlags]::None,'None','Allow'",
        )
        self.assertIn("$acl = New-ZgAcl $true ''", body[1])
        # Both anchors, in the owned install (and its resume) before the service's own
        # paths, and in an upgrade; never in the read-only actions.
        calls = [line for line in lifecycle.splitlines() if 'Set-ZgBaseAcl @(' in line]
        self.assertEqual(calls, ['  Set-ZgBaseAcl @($ZgData,$ZgBin)'] * 2)
        prepare = re.search(r'function Complete-ZgPrepare \{\n(.*?)\n\}\n', lifecycle, re.S)
        self.assertIsNotNone(prepare)
        steps = prepare[1].splitlines()
        settle = steps.index('  Set-ZgBaseAcl @($ZgData,$ZgBin)')
        self.assertLess(steps.index("  Save-ZgPhase 'paths-created'"), settle)
        self.assertLess(settle, next(i for i, line in enumerate(steps)
                                     if line.startswith('  Ensure-ZgService;')))
        upgrade = re.search(r'function Complete-ZgUpgrade \{\n(.*?)\n\}\n', lifecycle, re.S)
        self.assertIsNotNone(upgrade)
        self.assertIn('  Set-ZgBaseAcl @($ZgData,$ZgBin)', upgrade[1].splitlines())

    def test_machine_folders_fail_closed_on_an_incomplete_environment(self):
        # rc.1 I4: under an environment without ALLUSERSPROFILE/SystemDrive, Windows
        # PowerShell 5.1 resolved ProgramData to '' and the installer died on an
        # ArgumentException before its first step. Both anchors now come only from a
        # checked resolution, and an empty path is a fixed refusal.
        source = (GUARD / 'windows/bootstrap.ps1.inc').read_text()
        self.assertIn("$script:ZgData = [IO.Path]::Combine((Get-ZgMachineFolder "
                      "'CommonApplicationData'),'ZunderGuard')", source)
        self.assertIn("$script:ZgBin = [IO.Path]::Combine((Get-ZgMachineFolder "
                      "'ProgramFiles'),'ZunderGuard')", source)
        check = re.search(r'function Get-ZgMachineFolder\(\[string\]\$Name\) \{\n(.*?)\n\}\n',
                          source, re.S)
        self.assertIsNotNone(check)
        for condition in ("-not $folder", "$folder.Contains('%')", "$folder.StartsWith('\\\\')",
                          "-not [IO.Path]::IsPathRooted($folder)",
                          # Exactly its own full path: no trailing separator or other form.
                          "[IO.Path]::GetFullPath($folder) -cne $folder)"):
            self.assertIn(condition, check[1])
        self.assertIn("throw 'Windows did not resolve ProgramData or Program Files for this "
                      "process; run the installer with the complete Windows environment.'",
                      check[1])
        assert_path = source.index('function Assert-ZgPath(')
        self.assertTrue(source[assert_path:].splitlines()[1].strip()
                        == "if (-not $Path) { throw 'Noncanonical machine path refused.' }")

    def test_every_protected_file_is_created_with_its_owner(self):
        # rc.1 I4: the helper's lock file was created plainly, so its owner followed the
        # creating token. Under Git Bash/MSYS (the I4 harness) that is the user, and the next
        # helper action refused the lock as "Untrusted machine path owner (protected-path,
        # owner=current-user)". In the code that writes the protected machine tree (the shared
        # trust code, the loader's managed path, the helper; i.ps1 except its per-user
        # %LOCALAPPDATA% install), no API may create a file or folder unless it supplies an
        # ACL from New-ZgAcl, which sets owner Administrators and protects the DACL.
        shared = (GUARD / 'windows/bootstrap.ps1.inc').read_text()
        new_acl = ps_function(ps_code(shared), shared, 'New-ZgAcl')
        self.assertIn('$acl.SetAccessRuleProtection($true,$false)', new_acl)
        self.assertIn("$acl.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))",
                      new_acl)
        checked = []
        for name, code in protected_sources():
            for pattern in BANNED_CREATION:
                found = re.search(pattern, code)
                self.assertIsNone(found, f'{name}: {found and found[0]}')
            for function, body in ps_function_bodies(code).items():
                for prefix in CREATING_PREFIXES:
                    for _, args in ps_call_arguments(body, prefix):
                        acl = creating_acl(prefix, args)
                        if acl is None:
                            continue
                        where = f'{name} {function}: {prefix}{", ".join(args)})'
                        variable = re.fullmatch(r'\$(\w+)', acl)
                        self.assertIsNotNone(variable, where)
                        self.assertRegex(body, r'\$' + variable[1] + r'\s*=\s*New-ZgAcl\b',
                                         f'{where} has no owner-setting ACL')
                        checked.append(where)
        # The creating calls the sources have today: New-ZgDirectory (two), New-ZgSecureFile
        # (two) in each of bootstrap and i.ps1, and the lock (two).
        self.assertGreaterEqual(len(checked), 10, checked)
        writer = ps_function(ps_code(shared), shared, 'Write-ZgJson')
        self.assertIn('$file = New-ZgSecureFile $next', writer)
        lifecycle = (GUARD / 'windows/lifecycle.ps1.inc').read_text()
        main = ps_function(ps_code(lifecycle), lifecycle, 'Invoke-ZgLifecycle')
        self.assertIn('[IO.FileMode]::CreateNew,$lockRights,[IO.FileShare]::None,4096,'
                      '[IO.FileOptions]::None,$lockAcl)', main)
        self.assertIn('$lockAcl = New-ZgAcl $false', main)
        # An existing lock is asserted before it is opened, never adopted or re-owned; a held
        # lock or a lost creation race is one fixed refusal.
        self.assertLess(main.index('if ($lockExists) { Assert-ZgPath $lockPath }'),
                        main.index('[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite'))
        catch = main[main.index('$reason = $_.Exception.GetBaseException()'):]
        catch = catch[:catch.index('\n  }')]
        self.assertIn("if ($reason -is [IO.IOException] -and $reason.HResult -in "
                      "@(-2147024864,-2147024863,-2147024816,-2147024713)) { throw "
                      "'Another helper holds this instance''s lock.' }", catch)
        # Every other I/O error is rethrown unchanged.
        self.assertEqual(catch.rstrip().splitlines()[-1].strip(), 'throw')
        # 0x80070020 sharing, 0x80070021 lock violation, 0x80070050 and 0x800700B7 exists.
        self.assertEqual([h - 2**32 for h in (0x80070020, 0x80070021, 0x80070050, 0x800700B7)],
                         [-2147024864, -2147024863, -2147024816, -2147024713])

    def test_no_powershell_function_is_defined_twice(self):
        # A later definition silently replaces an earlier one in the same script: the
        # helper's path copy once shadowed the shared stream Copy-ZgSecureFile.
        shared = (GUARD / 'windows/bootstrap.ps1.inc').read_text()
        sources = {
            relative: (GUARD / relative).read_text()
            for relative in ('windows/service.ps1', 'loader/i.ps1')
        }
        # The sources they are assembled from, so an edit is caught before re-embedding.
        for part in ('windows/lifecycle.ps1.inc', 'windows/loader-mainnet.ps1.inc'):
            sources['bootstrap.ps1.inc + ' + part] = shared + '\n' + (GUARD / part).read_text()
        for relative, source in sources.items():
            names = re.findall(r'(?mi)^\s*function\s+([\w-]+)', ps_code(source))
            duplicates = sorted({n for n in names if names.count(n) > 1})
            self.assertEqual(duplicates, [], relative)
            self.assertGreater(len(names), 20, relative)

    def test_a_path_copy_is_complete_or_absent_at_its_final_name(self):
        lifecycle = (GUARD / 'windows/lifecycle.ps1.inc').read_text()
        copy = ps_function(ps_code(lifecycle), lifecycle, 'Copy-ZgSecureFileFromPath')
        steps = [line.strip() for line in copy.splitlines()]
        self.assertIn("$next = $Destination + '.copy-' + [Guid]::NewGuid().ToString('N')", steps)
        self.assertIn('try { Copy-ZgSecureFile $reader $next } finally { $reader.Dispose() }',
                      steps)
        self.assertIn('[IO.File]::Move($next,$Destination)', steps)
        # The copy's own error survives a failed cleanup, which is swallowed, then rethrown.
        cleanup = 'try { if ([IO.File]::Exists($next)) { [IO.File]::Delete($next) } } catch { }'
        self.assertIn(cleanup, steps)
        self.assertEqual(steps[steps.index(cleanup) + 1], 'throw')
        self.assertLess(steps.index('[IO.File]::Move($next,$Destination)'),
                        steps.index('} catch {'))
        self.assertEqual(steps[-2:], ['Assert-ZgPath $Destination', '}'])
        for call in ('Copy-ZgSecureFileFromPath $source $next;',
                     "Copy-ZgSecureFileFromPath $ZgExe $backup; Set-ZgAcl $backup ''",
                     "Copy-ZgSecureFileFromPath $ZgBinding $oldBinding; Set-ZgAcl $oldBinding ''",
                     'Copy-ZgSecureFileFromPath $backup $next;'):
            self.assertIn(call, lifecycle)
        # The shared Copy-ZgSecureFile takes a stream; every call passes one.
        for match in re.finditer(r'Copy-ZgSecureFile (\$\w+)', ps_code(lifecycle)):
            self.assertIn(match[1], ('$reader',))

    def test_mainnet_journal_is_protected_on_init_and_on_resume(self):
        lifecycle = (GUARD / 'windows/lifecycle.ps1.inc').read_text()
        protect = 'Set-ZgAcl ((Get-ZgJournalPath)) $ZgSid $true'
        main = ps_function(ps_code(lifecycle), lifecycle, 'Invoke-ZgLifecycle')
        journal_init = main[main.index("'JournalInit' {"):main.index("'Start' {")]
        self.assertEqual(journal_init.count('Set-ZgAcl'), 1)
        self.assertLess(journal_init.index("'journal-init','--mode','mainnet'"),
                        journal_init.index(protect))
        self.assertLess(journal_init.index(protect), journal_init.index("Save-ZgPhase 'journal-present'"))
        # Resume after a JournalInit that stopped in journal-requested: the journal Guard
        # created gets the same protected form before journal-present is recorded.
        resume = main[main.index("if ($phase -eq 'journal-requested') {"):main.index("} elseif ($phase -in")]
        self.assertLess(resume.index("'journal-show','--mode','mainnet'"), resume.index(protect))
        self.assertLess(resume.index(protect), resume.index("Save-ZgPhase 'journal-present'"))

    def test_programdata_exception_cannot_grant_destructive_or_anchor_rights(self):
        source = (GUARD / 'windows/bootstrap.ps1.inc').read_text()
        base = int(re.search(r'\$allowed = (0x[0-9a-f]+) #', source)[1], 16)
        self.assertIn("if ($current -in $known) { $allowed = $allowed -bor 6 }", source)
        extra = re.search(
            r'if \(\$item -is \[IO.DirectoryInfo\] -and \$current -eq \$known\[0\]\) '
            r'\{ \$allowed = \$allowed -bor (0x[0-9a-f]+) \}', source,
        )
        self.assertIsNotNone(extra)
        metadata = int(extra[1], 16)
        # Microsoft FileSystemRights: read/execute=0xa9, ReadControl=0x20000,
        # Synchronize=0x100000; create children=0x6, WriteEA=0x10, WriteAttrs=0x100.
        self.assertEqual(base, 0x1200a9)
        self.assertEqual(metadata, 0x110)
        root = base | 6 | metadata
        self.assertEqual(root, 0x1201bf)
        self.assertEqual(0x116 & ~root, 0)
        self.assertNotEqual(0x116 & ~(base | 6), 0)
        self.assertNotEqual(0x116 & ~base, 0)
        for destructive in (0x40, 0x10000, 0x40000, 0x80000):
            self.assertEqual(root & destructive, 0)
        # The metadata allowance remains subordinate to existing plain-path,
        # trusted-owner and post-create anchor admission, with protected ACLs.
        self.assertIn('($item.Attributes -band [IO.FileAttributes]::ReparsePoint)', source)
        self.assertIn('throw "Untrusted machine path owner ($kind, owner=$ownerClass)."', source)
        self.assertIn('$acl.SetAccessRuleProtection($true,$false)', source)
        self.assertIn('  Assert-ZgPath $Path\n', source)


class DockerBuildContext(unittest.TestCase):
    """Static admission contract; no Docker daemon or image-build claim."""
    def patterns(self):
        return [line.strip() for line in (GUARD / 'Dockerfile.dockerignore').read_text().splitlines()
                if line.strip() and not line.lstrip().startswith('#')]

    def test_runtime_data_copy_has_existing_narrow_context_admission(self):
        # Derive the real COPY input rather than checking an unrelated constant.
        copies = [shlex.split(line) for line in (GUARD / 'Dockerfile').read_text().splitlines()
                  if line.startswith('COPY ') and shlex.split(line)[-1] == '/data/']
        self.assertEqual(len(copies), 1)
        sources = [part for part in copies[0][1:-1] if not part.startswith('--')]
        self.assertEqual(sources, ['deploy/guard/container/volume-root/'])
        source = sources[0]
        volume = GUARD.parents[1] / source
        self.assertTrue(volume.is_dir())
        self.assertEqual(sorted(path.name for path in volume.iterdir()), ['.keep'])
        self.assertTrue((volume / '.keep').is_file())
        patterns = self.patterns()
        self.assertEqual(patterns[0], '*')
        self.assertEqual(patterns.count('!' + source), 1)
        # Do not repair a COPY by exposing the container helpers or all deploy files.
        for ancestor in Path(source).parents:
            if str(ancestor) != '.':
                self.assertNotIn('!' + ancestor.as_posix() + '/', patterns)
                self.assertNotIn('!' + ancestor.as_posix(), patterns)
        self.assertNotIn('!*', patterns)
        self.assertNotIn('!**', patterns)

    def test_secret_and_target_exclusions_override_every_allowlist_entry(self):
        patterns = self.patterns()
        final_allow = max(index for index, pattern in enumerate(patterns) if pattern.startswith('!'))
        # Docker uses the last matching rule. These recursive exclusions must
        # remain after ALL admissions, including the volume-root directory.
        exclusions = ['**/target', '**/.env', '**/.env.*', '**/*.key', '**/*.pem']
        for exclusion in exclusions:
            self.assertIn(exclusion, patterns)
            self.assertGreater(patterns.index(exclusion), final_allow)
        self.assertEqual(patterns[final_allow + 1:], exclusions)


class HomebrewServicePolicy(unittest.TestCase):
    """Formula policy contract; native lifecycle remains a separate hosted check."""
    def test_restart_policy_covers_systemd_and_preserves_launchd(self):
        text = (GUARD / 'packaging/homebrew/zunder-guard.rb.in').read_text()
        service = text.split('  service do\n', 1)[1].split('\n  end', 1)[0]
        policy = [line.strip() for line in service.splitlines()
                  if line.strip().startswith('keep_alive ')]
        # Homebrew selects SuccessfulExit by key presence for launchd, but
        # requires a truthy :crashed or :always value for systemd on-failure.
        # successful_exit:false alone silently omits Linux's Restart directive.
        self.assertEqual(policy, ['keep_alive successful_exit: false, crashed: true'])
        self.assertIn('run [opt_bin/"zunder-guard", "run", "--network", "paper"]', service)
        self.assertIn('environment_variables ZUNDER_GUARD_HOME: var/"zunder-guard"', service)


class ReleaseRendering(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dist = self.root / 'dist'
        self.dist.mkdir()
        for target in ('linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64', 'windows-amd64'):
            ext = 'zip' if target.startswith('windows') else 'tar.gz'
            (self.dist / f'zunder-guard-{TAG}-{target}.{ext}').write_text('packaging fixture only\n')
        self.descriptor = self.dist / f'zunder-guard-{TAG}.image.txt'
        self.descriptor.write_text(IMAGE + '\n')

    def render(self):
        return subprocess.run(['bash', str(GUARD / 'packaging/render.sh'), TAG, str(self.dist)],
                              capture_output=True, text=True)

    def test_candidate_archives_render_exact_pinned_version(self):
        tag = 'v1.0.0-rc.12'
        binary = self.root / 'binary'
        binary.write_bytes(b'packaging-only fixture')
        for target in ('linux-amd64', 'linux-arm64', 'darwin-amd64', 'darwin-arm64', 'windows-amd64'):
            result = subprocess.run(['bash', str(GUARD / 'packaging/package.sh'), tag,
                                     target, str(binary), str(self.dist)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
        (self.dist / f'zunder-guard-{tag}.image.txt').write_text(IMAGE + '\n')
        result = subprocess.run(['bash', str(GUARD / 'packaging/render.sh'), tag, str(self.dist)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('version "1.0.0-rc.12"', (self.dist / 'zunder-guard.rb').read_text())
        cloud = (self.dist / 'cloudformation.yaml').read_text()
        self.assertIn(f'only this signed release ({tag})', cloud)
        self.assertIn(hashlib.sha256((self.dist / 'i').read_bytes()).hexdigest(), cloud)
        self.assertIn(f'V={tag} ', (self.dist / 'i').read_text())
        for target, ext in [('linux-amd64', 'tar.gz'), ('windows-amd64', 'zip')]:
            self.assertIn(f'zunder-guard-{tag}-{target}.{ext}', (self.dist / 'SHA256SUMS').read_text())

    def test_malformed_candidates_refuse_before_packaging_or_rendering(self):
        binary = self.root / 'binary'
        binary.write_bytes(b'packaging-only fixture')
        for tag in ('v1.0.0-rc.0', 'v1.0.0-rc.01', 'v1.0.0-rc1', 'v1.0.0-beta.1', 'v1.0.0-rc.1/other'):
            for script, args in [('package.sh', ['windows-amd64', str(binary), str(self.root / 'out')]),
                                 ('render.sh', [str(self.dist)])]:
                with self.subTest(tag=tag, script=script):
                    result = subprocess.run(['bash', str(GUARD / 'packaging' / script), tag, *args],
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / 'out').exists())
        self.assertFalse((self.dist / 'SHA256SUMS').exists())

    def test_digest_and_verified_cloud_loader_are_signed_payloads(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('compose.yaml',):
            text = (self.dist / name).read_text()
            self.assertIn(IMAGE, text)
            self.assertNotIn('ghcr.io/zunderlabs/zunder-guard:', text)
        sha = hashlib.sha256((self.dist / 'i').read_bytes()).hexdigest()
        for name in ('cloudformation.yaml',):
            text = (self.dist / name).read_text()
            self.assertIn(f'only this signed release ({TAG})', text)
            self.assertIn(sha, text)
            self.assertIn('sha256sum -c -', text)
            self.assertIn('sh "$loader" --non-interactive --network paper', text)
            self.assertIn('https://zunderlabs.com/${InstallerPath}', text)
            self.assertIn('InstallerPath: !If [StagingInstaller, i-staging, i]', text)
            self.assertLess(text.index('sha256sum -c -'), text.index('sh "$loader"'))
            self.assertIn(f'/blob/{TAG}/deploy/guard/systemd/ACTIVATION.md', text)
            self.assertIn('source commit in this release\'s provenance', text)
            self.assertIn('--service-instance testnet or --service-instance mainnet with matching --network', text)
            self.assertIn('Never use --force to activate bootstrap paper state.', text)
            self.assertNotIn('sudo sh i --force', text)
            self.assertIn('sudo -u zunder-guard env ZUNDER_GUARD_HOME=/var/lib/zunder-guard /usr/local/bin/zunder-guard pair', text)
        sums = (self.dist / 'SHA256SUMS').read_text()
        for name in ('i', self.descriptor.name, 'compose.yaml', 'cloudformation.yaml'):
            self.assertIn(hashlib.sha256((self.dist / name).read_bytes()).hexdigest() + '  ' + name, sums)

    def test_windows_service_helper_is_rendered_and_signed(self):
        result = self.render()
        self.assertEqual(result.returncode, 0, result.stderr)
        helper = self.dist / 'install-windows-service.ps1'
        self.assertIn('Invoke-ZgLifecycle', helper.read_text())
        line = hashlib.sha256(helper.read_bytes()).hexdigest() + '  ' + helper.name
        self.assertEqual((self.dist / 'SHA256SUMS').read_text().splitlines().count(line), 1)

    def test_windows_embedded_trust_and_lifecycle_sources_match(self):
        shared = (GUARD / 'windows/bootstrap.ps1.inc').read_text()
        journey = (GUARD / 'windows/loader-mainnet.ps1.inc').read_text()
        lifecycle = (GUARD / 'windows/lifecycle.ps1.inc').read_text()
        self.assertIn(shared + '\n' + journey, (GUARD / 'loader/i.ps1').read_text())
        self.assertIn(shared + '\n' + lifecycle, (GUARD / 'windows/service.ps1').read_text())

    def test_homebrew_preserves_every_notice_and_tests_the_installed_files(self):
        self.assertEqual(self.render().returncode, 0)
        formula = (self.dist / 'zunder-guard.rb').read_text()
        self.assertIn('pkgshare.install "LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.md"', formula)
        self.assertIn('%w[LICENSE NOTICE THIRD_PARTY_LICENSES.md].each do |notice|', formula)
        self.assertIn('assert_path_exists pkgshare/notice', formula)

    def test_missing_or_malformed_image_refuses_before_rendering(self):
        self.descriptor.unlink()
        self.assertNotEqual(self.render().returncode, 0)
        self.assertFalse((self.dist / 'i').exists())
        for value in ('ghcr.io/zunderlabs/zunder-guard:v1.0.0\n',
                      'ghcr.io/other/zunder-guard@sha256:' + 'a' * 64 + '\n',
                      IMAGE + '\n\n', IMAGE + 'extra', IMAGE.upper(), IMAGE[:-1]):
            with self.subTest(value=value):
                self.descriptor.write_text(value)
                self.assertNotEqual(self.render().returncode, 0)
                self.assertFalse((self.dist / 'i').exists())

    def test_missing_loader_refuses(self):
        fixture = self.root / 'source-fixture'
        shutil.copytree(GUARD, fixture, ignore=shutil.ignore_patterns('__pycache__', 'export'))
        (fixture / 'loader/i.sh').unlink()
        result = subprocess.run(['bash', str(fixture / 'packaging/render.sh'), TAG, str(self.dist)],
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.dist / 'SHA256SUMS').exists())

    def test_cloud_activation_template_drift_refuses_unsigned_manifest(self):
        fixture = self.root / 'source-fixture'
        shutil.copytree(GUARD, fixture, ignore=shutil.ignore_patterns('__pycache__', 'export'))
        template = fixture / 'templates/cloudformation.yaml'
        original = template.read_text()
        guide = "Follow deploy/guard/systemd/ACTIVATION.md at the source commit named in this release."
        download = 'curl -fsSL --proto \'=https\' --retry 3 -o "$loader" https://zunderlabs.com/${InstallerPath}'
        for changed in (original.replace(guide, 'unknown guide'), original + '\n# ' + guide + '\n',
                        original.replace(download, download.replace('zunderlabs.com', 'example.invalid')),
                        original + '\n# ' + download + '\n'):
            with self.subTest(changed=changed):
                template.write_text(changed)
                result = subprocess.run(['bash', str(fixture / 'packaging/render.sh'), TAG, str(self.dist)],
                                        capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('expected cloud bootstrap block absent or duplicated', result.stderr)
                self.assertFalse((self.dist / 'SHA256SUMS').exists())

    def test_deferred_provider_assets_refuse_and_repeated_render_is_stable(self):
        self.assertEqual(self.render().returncode, 0)
        first = (self.dist / 'SHA256SUMS').read_bytes()
        self.assertEqual(self.render().returncode, 0)
        self.assertEqual(first, (self.dist / 'SHA256SUMS').read_bytes())
        for name in ('fly.toml', 'render.yaml', 'railway.json', 'cloud-init.yaml'):
            self.assertFalse((self.dist / name).exists())
            (self.dist / name).write_text('stale provider fixture')
            result = self.render()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('deferred provider artifact', result.stderr)
            (self.dist / name).unlink()

    def test_cloud_bootstrap_checks_before_execution_and_cleans_temp(self):
        self.assertEqual(self.render().returncode, 0)
        cloud = (self.dist / 'cloudformation.yaml').read_text()
        command = cloud.split('            #!/bin/bash\n', 1)[1].split('\n          - ListenArg:', 1)[0]
        command = '\n'.join(line[12:] if line.startswith(' ' * 12) else line for line in command.splitlines())
        for name, value in {'AWS::Region': 'ap-northeast-1', 'AWS::StackId': 'fixture-stack',
                            'Rules': 'zr1_fixture', 'Account': '0x' + '1' * 40, 'ListenArg': ''}.items():
            command = command.replace('${' + name + '}', value)
        fakebin = self.root / 'bin'
        fakebin.mkdir()
        marker = self.root / 'executed'
        curl = fakebin / 'curl'
        curl.write_text('#!/bin/sh\ncase "$*" in *healthz*) exit 0;; esac\n'
                        'while [ "$1" != -o ]; do shift; done\n'
                        'printf "%s\\n" "$2" > "$TEMP_PATH"\n'
                        '[ "${FAIL_DOWNLOAD:-}" != 1 ] || exit 22\ncp "$TEST_LOADER" "$2"\n')
        curl.chmod(0o755)
        shell = fakebin / 'sh'
        shell.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$EXECUTED"\n')
        shell.chmod(0o755)
        for name in ('apt-get', 'snap', 'systemctl'):
            path = fakebin / name
            path.write_text('#!/bin/sh\n[ "${FAIL_TOOL:-}" != "' + name + '" ]\n')
            path.chmod(0o755)
        aws = fakebin / 'aws'
        aws.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$SIGNAL"\n')
        aws.chmod(0o755)
        self.assertIn('/snap/bin/aws cloudformation signal-resource', command)
        self.assertLess(command.index('trap finish EXIT'), command.index('apt-get update'))
        command = command.replace('/snap/bin/aws', shlex.quote(str(aws)))
        env = dict(os.environ, PATH=str(fakebin) + os.pathsep + os.environ['PATH'],
                   TEST_LOADER=str(self.dist / 'i'), EXECUTED=str(marker),
                   SIGNAL=str(self.root / 'signal'), TEMP_PATH=str(self.root / 'temp-path'))
        original = (self.dist / 'i').read_bytes()
        for channel in ('i', 'i-staging'):
          for mode in ('valid', 'tampered', 'download-fails', 'apt-fails', 'snap-fails'):
            with self.subTest(channel=channel, mode=mode):
                for old in ('signal', 'temp-path'):
                    (self.root / old).unlink(missing_ok=True)
                (self.dist / 'i').write_bytes(original if mode != 'tampered' else b'tampered fixture')
                env['FAIL_DOWNLOAD'] = '1' if mode == 'download-fails' else '0'
                env['FAIL_TOOL'] = 'apt-get' if mode == 'apt-fails' else 'snap' if mode == 'snap-fails' else ''
                result = subprocess.run(['bash', '-c', command.replace('${InstallerPath}', channel)], env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, mode == 'valid', result.stderr)
                signal = (self.root / 'signal').read_text()
                self.assertIn('--status ' + ('SUCCESS' if mode == 'valid' else 'FAILURE'), signal)
                self.assertEqual(marker.exists(), mode == 'valid')
                if marker.exists():
                    self.assertIn('--non-interactive --network paper --rules zr1_fixture --account 0x', marker.read_text())
                    marker.unlink()
                if mode in ('apt-fails', 'snap-fails'):
                    self.assertFalse((self.root / 'temp-path').exists())
                else:
                    self.assertFalse(Path((self.root / 'temp-path').read_text().strip()).exists())
                if mode != 'valid':
                    import re
                    diagnostic = re.search(r'root-only file (\S+);', result.stdout)
                    if diagnostic:
                        private_log = Path(diagnostic.group(1))
                        self.assertEqual(stat.S_IMODE(private_log.stat().st_mode), 0o600)
                        private_log.unlink()


class InstallerNotices(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.release = self.root / 'release'
        self.release.mkdir()
        self.script = self.root / 'install.sh'
        self.script.write_text((GUARD / 'install.sh').read_text().replace('@VERSION@', TAG))
        self.fakebin = self.root / 'bin'
        self.fakebin.mkdir()
        shutil.copy2(GUARD / 'test/fake-cosign', self.fakebin / 'cosign')
        sudo = self.fakebin / 'sudo'
        sudo.write_text('#!/bin/sh\nexit 1\n')
        sudo.chmod(0o755)
        arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[os.uname().machine]
        self.archive = self.release / f'zunder-guard-{TAG}-linux-{arch}.tar.gz'
        self.pack()

    def pack(self, omitted=None, symlink=None):
        # This executable only answers setup commands; it has no venue or order access.
        binary = b'#!/bin/sh\ncase "$1" in --version) echo "fixture 0.0.0";; config) echo paper;; esac\n'
        with tarfile.open(self.archive, 'w:gz') as archive:
            for name in ('zunder-guard',) + NOTICES:
                if name == omitted:
                    continue
                item = tarfile.TarInfo(name)
                item.mode = 0o755 if name == 'zunder-guard' else 0o644
                data = binary if name == 'zunder-guard' else ('notice fixture ' + name + '\n').encode()
                if name == symlink:
                    item.type, item.linkname = tarfile.SYMTYPE, '/etc/passwd'
                    archive.addfile(item)
                else:
                    item.size = len(data)
                    archive.addfile(item, io.BytesIO(data))
        sums = self.release / 'SHA256SUMS'
        sums.write_text(hashlib.sha256(self.archive.read_bytes()).hexdigest() + '  ' + self.archive.name + '\n')
        (self.release / 'SHA256SUMS.sigstore.json').write_text(json.dumps({
            'identity': f'https://github.com/zunderlabs/zunder-guard/.github/workflows/release.yml@refs/tags/{TAG}',
            'sha256': hashlib.sha256(sums.read_bytes()).hexdigest()}))

    def install(self, prefix=None, *, without_home=False, without_guard_home=False):
        args = ['/bin/sh', str(self.script), '--non-interactive', '--network', 'paper',
                '--rules', 'zr1_fixture', '--no-service', '--force']
        if prefix is not None:
            args += ['--prefix', str(prefix)]
        env = dict(os.environ, HOME=str(self.home), PATH=str(self.fakebin) + os.pathsep + os.environ['PATH'],
                   ZUNDER_GUARD_BASE_URL=self.release.as_uri(), ZUNDER_GUARD_HOME=str(self.home / 'guard'))
        if without_home:
            env.pop('HOME', None)
        if without_guard_home:
            env.pop('ZUNDER_GUARD_HOME', None)
        return subprocess.run(args, env=env, capture_output=True, text=True,
                              preexec_fn=lambda: os.umask(0o077))

    def assert_notices(self, destination):
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
        self.assertEqual(destination.stat().st_uid, os.getuid())
        for name in NOTICES:
            path = destination / name
            self.assertEqual(path.read_text(), 'notice fixture ' + name + '\n')
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            self.assertEqual(path.stat().st_uid, os.getuid())

    def test_custom_bin_prefix_and_upgrade_preserve_sidecars(self):
        prefix = self.root / 'custom prefix/bin'
        result = self.install(prefix)
        self.assertEqual(result.returncode, 0, result.stderr)
        destination = prefix.parent / 'share/licenses/zunder-guard'
        self.assert_notices(destination)
        (destination / 'local-note').write_text('keep me\n')
        (destination / 'LICENSE').write_text('old notice\n')
        self.assertEqual(self.install(prefix).returncode, 0)
        self.assert_notices(destination)
        self.assertEqual((destination / 'local-note').read_text(), 'keep me\n')
        self.assertFalse(list(destination.glob('.install.*')))

    def test_custom_non_bin_prefix(self):
        prefix = self.root / 'programs'
        self.assertEqual(self.install(prefix).returncode, 0)
        self.assert_notices(prefix / 'share/licenses/zunder-guard')

    def test_actual_root_prefix_selection_does_not_require_home(self):
        source = (GUARD / 'install.sh').read_text()
        block = 'if [ -z "$PREFIX" ]; then' + source.rsplit('if [ -z "$PREFIX" ]; then', 1)[1].split('# Use the binary', 1)[0]
        result = subprocess.run(['/bin/sh', '-eu', '-c',
            'id() { printf "0\\n"; };\n' + block + '\nprintf "%s:%s\\n" "$PREFIX" "$SUDO_BIN"'],
            env={'PATH': os.defpath, 'PREFIX': '', 'SUDO': ''}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '/usr/local/bin:')

    def test_nonroot_missing_home_refuses_before_install_mutation(self):
        if os.getuid() == 0:
            self.skipTest('non-root admission checked by the user fixture')
        prefix = self.root / 'missing-home-prefix'
        result = self.install(prefix, without_home=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HOME is required for native installation by a non-root user', result.stderr)
        self.assertNotIn('downloading', result.stdout)
        self.assertFalse(prefix.exists())
        self.assertFalse((self.home / 'guard').exists())

    def test_root_explicit_guard_home_without_home(self):
        if os.getuid() != 0:
            self.skipTest('root admission uses a private explicit temp prefix fixture')
        prefix = self.root / 'home-free-prefix/bin'
        result = self.install(prefix, without_home=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((prefix / 'zunder-guard').is_file())
        self.assertIn(str(self.home / 'guard'), result.stdout)

    def test_root_foreground_missing_both_homes_refuses_before_files(self):
        if os.getuid() != 0:
            self.skipTest('root admission uses a private explicit temp prefix fixture')
        prefix = self.root / 'missing-both-prefix/bin'
        result = self.install(prefix, without_home=True, without_guard_home=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HOME or explicit ZUNDER_GUARD_HOME is required', result.stderr)
        self.assertNotIn('downloading', result.stdout)
        self.assertFalse(prefix.exists())

    def test_default_user_prefix(self):
        if os.getuid() == 0:
            self.skipTest('default root path is checked only in a disposable root container')
        self.assertEqual(self.install().returncode, 0)
        self.assert_notices(self.home / '.local/share/licenses/zunder-guard')

    def test_default_root_prefix_in_disposable_container(self):
        if os.getuid() != 0 or os.environ.get('GUARD_NOTICE_TEST_ROOT_SANDBOX') != '1':
            self.skipTest('requires an explicitly disposable root container')
        self.assertEqual(self.install().returncode, 0)
        self.assert_notices(Path('/usr/local/share/licenses/zunder-guard'))

    def test_missing_or_symlink_archive_notice_refuses_before_install(self):
        prefix = self.root / 'programs'
        for name in NOTICES:
            with self.subTest(name=name):
                self.pack(omitted=name)
                self.assertNotEqual(self.install(prefix).returncode, 0)
                self.assertFalse(prefix.exists())
                self.pack(symlink=name)
                self.assertNotEqual(self.install(prefix).returncode, 0)
                self.assertFalse(prefix.exists())

    def test_destination_symlinks_refuse_without_overwriting_binary_or_target(self):
        prefix = self.root / 'programs/bin'
        prefix.mkdir(parents=True)
        binary = prefix / 'zunder-guard'
        binary.write_text('existing binary\n')
        outside = self.root / 'outside'
        outside.mkdir()
        share = prefix.parent / 'share'
        share.symlink_to(outside, target_is_directory=True)
        self.assertNotEqual(self.install(prefix).returncode, 0)
        self.assertEqual(binary.read_text(), 'existing binary\n')
        self.assertFalse(list(outside.iterdir()))
        share.unlink()
        destination = share / 'licenses/zunder-guard'
        destination.mkdir(parents=True)
        target = outside / 'LICENSE'
        target.write_text('untouched\n')
        (destination / 'LICENSE').symlink_to(target)
        self.assertNotEqual(self.install(prefix).returncode, 0)
        self.assertEqual(binary.read_text(), 'existing binary\n')
        self.assertEqual(target.read_text(), 'untouched\n')


if __name__ == '__main__':
    unittest.main()
