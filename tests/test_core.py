import unittest
from patch_scope_guard import analyze, _git_files


class ScopeTests(unittest.TestCase):
    def test_rename_source_is_checked(self):
        report = analyze({'diff': 'diff --git a/secret.txt b/src/a.txt\nsimilarity index 100%\nrename from secret.txt\nrename to src/a.txt', 'allow': ['src/*']})
        self.assertFalse(report['within_scope'])
        self.assertIn({'path': 'secret.txt', 'reason': 'outside_allowlist'}, report['findings'])

    def test_additions_that_look_like_headers_count(self):
        report = analyze({'diff': 'diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n+++data'})
        self.assertEqual(report['changed_lines'], 1)

    def test_traversal(self):
        diff = 'diff --git a/../x b/../x\n--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n'
        self.assertIn({'path': '../x', 'reason': 'unsafe_path'}, analyze({'diff': diff})['findings'])

    def test_noncanonical_paths_cannot_bypass_canonical_policy(self):
        for path in ('src//secret.txt', './src/secret.txt', 'src/./secret.txt', 'src/secret.txt/', '.'):
            diff = f'diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n'
            with self.subTest(path=path):
                report = analyze({'diff': diff, 'deny': ['src/secret.txt']})
                self.assertFalse(report['within_scope'])
                self.assertIn({'path': path, 'reason': 'unsafe_path'}, report['findings'])
                self.assertEqual(report['files'][0]['old'], path)

    def test_empty(self):
        self.assertTrue(analyze({'diff': ''})['within_scope'])

    def test_no_newline_marker_between_removal_and_addition(self):
        diff = 'diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -1 +1 @@\n-a\n\\ No newline at end of file\n+b\n\\ No newline at end of file\n'
        self.assertEqual(analyze({'diff': diff})['changed_lines'], 2)

    def test_ambiguous_and_malformed_diffs_fail_closed(self):
        for diff in (
            'diff --cc x',
            'diff --git a/a b/a',
            'diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a',
            'diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b\n+extra',
            'diff --git a/name with spaces b/name with spaces\nnew file mode 100644',
            'diff --git "a/quoted\\tpath" "b/quoted\\tpath"\nnew file mode 100644',
            'diff --git a/a b/b\nrename from other\nrename to b',
            'diff --git a/a b/a\nGIT binary patch\nliteral 1\nopaque',
            'diff --git a/a b/a\nunknown extension',
        ):
            with self.subTest(diff=diff), self.assertRaises(ValueError):
                analyze({'diff': diff})

    def test_policy_validation_and_budget(self):
        for policy in ({'allow': '*'}, {'deny': [3]}, {'max_changed_lines': True}, {'max_changed_lines': -1}, {'alow': ['*']}):
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                analyze({'diff': '', **policy})
        report = analyze({'diff': 'diff --git a/a b/a\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-a\n+b', 'max_changed_lines': 1})
        self.assertEqual(report['findings'], [{'reason': 'line_budget_exceeded', 'actual': 2, 'budget': 1}])

    def test_raw_metadata_rejects_truncation_mismatch_and_bad_counts(self):
        oid = b'0' * 40
        raw = b':100644 100644 ' + oid + b' ' + oid + b' M\0x\0'
        for metadata, stats in ((raw[:-1], b''), (raw, b'1\t1\tx'), (raw, b'1\t1\ty\0'), (raw, b'-\t1\tx\0'), (raw, b''), (raw, b'1\t1\tx\0' * 2), (b':bad\0x\0', b'')):
            with self.subTest(metadata=metadata, stats=stats), self.assertRaises(ValueError):
                _git_files(metadata, stats)
