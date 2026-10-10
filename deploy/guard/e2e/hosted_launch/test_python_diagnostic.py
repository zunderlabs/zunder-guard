#!/usr/bin/env python3
"""Inert tests for public diagnostics; no runtime copy or network."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hosted_launch.bootstrap import python_failure_diagnostic as diagnostic, stdlib_alias_target


class Diagnostic(unittest.TestCase):
    def test_fixed_ubuntu_library_alias_is_the_only_external_exception(self):
        original = Path('/usr/lib/python3.12')
        member = 'config-3.12-x86_64-linux-gnu/libpython3.12.so'
        target = Path('/usr/lib/x86_64-linux-gnu/libpython3.12.so.1.0')
        self.assertEqual(stdlib_alias_target(member, target, original), str(target))
        for name, actual in [(member, Path('/tmp/libpython3.12.so.1.0')),
                             (member, Path('/usr/lib/x86_64-linux-gnu/libpython3.13.so.1.0')),
                             ('unexpected.so', target),
                             ('config-3.12-aarch64-linux-gnu/libpython3.12.so', target)]:
            with self.subTest(name=name, actual=actual), self.assertRaises(RuntimeError):
                stdlib_alias_target(name, actual, original)
        self.assertEqual(stdlib_alias_target('internal.py', original/'internal.py', original), 'internal.py')

    def test_fixed_reason_and_relative_public_member(self):
        result = diagnostic(('copy-member', 'sitecustomize.py'), RuntimeError('Unexpected site customization alias refused'))
        self.assertEqual(result['reason'], 'startup-alias-refused')
        self.assertEqual(result['member'], 'sitecustomize.py')
        self.assertEqual(result['errorType'], 'RuntimeError')
        self.assertEqual(set(result), {'operation', 'member', 'memberSha256', 'errorType', 'reason'})

    def test_arbitrary_exception_text_is_never_exported(self):
        result = diagnostic(('copy-interpreter', 'python3.12'), RuntimeError('fixture-private-value'))
        self.assertNotIn('fixture-private-value', str(result))
        self.assertEqual(result['reason'], 'operation-failed')
        self.assertEqual(result['member'], 'python3.12')

    def test_unexpected_member_grammar_exports_hash_only(self):
        for member in ('/private/value', '../value', 'a\nb', 'name with space'):
            result = diagnostic(('copy-member', member), FileNotFoundError('fixture-private-value'))
            self.assertIsNone(result['member'])
            self.assertEqual(len(result['memberSha256']), 64)
            self.assertNotIn('fixture-private-value', str(result))

    def test_operation_and_bound_are_closed(self):
        for context in [('unlisted', 'stdlib'), ('copy-member', 'x'*1025)]:
            with self.assertRaises(RuntimeError): diagnostic(context, RuntimeError('fixture'))
        self.assertIsNone(diagnostic(None, RuntimeError('fixture')))

    def test_other_error_classes_emit_no_message(self):
        result = diagnostic(('enumerate', 'stdlib'), ValueError('fixture-private-value'))
        self.assertEqual(result['errorType'], 'other')
        self.assertNotIn('fixture-private-value', str(result))


if __name__ == '__main__':
    unittest.main()
