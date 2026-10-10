"""Inert route-name fixtures: no runtime admission, filesystem or provider I/O."""
import unittest
from . import contracts as c


class RelativeAstroRoutes(unittest.TestCase):
    def test_actual_literal_bracket_source_paths(self):
        for value in (
            'web/site/src/pages/[legal].astro',
            'web/site/src/pages/[slug].md.ts',
            'web/site/src/pages/docs/[...slug].md.ts',
            'web/site/src/pages/method/[slug].astro',
        ):
            with self.subTest(value=value):
                self.assertEqual(c.relative(value), value)

    def test_actual_language_server_dollar_paths(self):
        for value in (
            'node_modules/vscode-languageserver-protocol/lib/common/protocol.$.js',
            'node_modules/vscode-languageserver-protocol/lib/common/protocol.$.d.ts',
            'node_modules/vscode-languageserver/node_modules/vscode-languageserver-protocol/lib/common/protocol.$.js',
            'node_modules/vscode-languageserver/node_modules/vscode-languageserver-protocol/lib/common/protocol.$.d.ts',
        ):
            with self.subTest(value=value):
                self.assertEqual(c.relative(value), value)
        for value in ('node_modules/pkg/../protocol.$.js',
                      'node_modules/pkg/protocol.%24.js',
                      'node_modules/pkg/protocol.$(env).js',
                      'node_modules/pkg/protocol.${ENV}.js',
                      'node_modules/pkg/protocol.`env`.js'):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    c.relative(value)

    def test_existing_escape_and_empty_fences_remain(self):
        for value in (
            '', '/', '/web/site/src/pages/[slug].astro',
            'web/site/src/pages/../[slug].astro',
            'web/site/src/pages/./[slug].astro',
            'web//site/src/pages/[slug].astro',
            'web/site/src/pages/[slug].astro/',
            'web/site/src/pages/%5Bslug%5D.astro',
            r'web\site\src\pages\[slug].astro',
            'web/site/src/pages/[slug].astro\x00',
            'web/site/src/pages/[slug].astro\n',
            'web/site/src/pages/[slug].astro?private=1',
            'a' * 1025,
            None, 1, [], {},
        ):
            with self.subTest(value=value):
                with self.assertRaises(RuntimeError):
                    c.relative(value)

    def test_unrelated_preexisting_segment_semantics_unchanged(self):
        # relative() never supplied a prototype/credential policy. Do not invent
        # one in a finite lexical route fix; later admission owns those policies.
        for value in (
            'deploy/guard/e2e/hosted_launch/__init__.py',
            'web/site/src/__proto__/ordinary.ts',
            'web/site/src/.env.fixture',
            'node_modules/@scope/package/file.js',
        ):
            self.assertEqual(c.relative(value), value)

    def test_no_root_tool_or_runtime_cap_changes(self):
        self.assertEqual(str(c.ROOT), '/var/lib/zunder-hosted-ordinary')
        self.assertEqual(str(c.WEBSITE), '/var/lib/zunder-hosted-ordinary/runtime/website/source')
        self.assertFalse(c.WEBSITE.is_relative_to(c.SOURCE))
        # The existing full runtime schema's bounded cardinality remains active.
        files = {'/fixture/file-' + str(n): 'a' * 64 for n in range(19998)}
        files.update({'/usr/bin/systemd-run': 'a' * 64, '/usr/bin/systemctl': 'a' * 64})
        tools = {name: {'file': '/fixture/file-0', 'sha256': 'a' * 64} for name in c.TOOLS}
        tools['systemd_run']['file'] = '/usr/bin/systemd-run'
        tools['systemctl']['file'] = '/usr/bin/systemctl'
        fixture = {'schema': 1, 'files': files,
                   'roots': {'python': '/p', 'node': '/n', 'packages': '/w'},
                   'tools': tools}
        self.assertIs(c.runtime(fixture), fixture)
        files['/fixture/over-cap'] = 'a' * 64
        with self.assertRaises(RuntimeError):
            c.runtime(fixture)


if __name__ == '__main__':
    unittest.main()
