"""End-to-end contracts against actual Git object databases, not mocked output."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from patch_scope_guard import analyze, analyze_repo


@unittest.skipUnless(shutil.which('git'), 'Git is required')
class GitScopeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.repo = Path(self.temporary.name)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'commit.gpgSign', 'false')
        self.git('config', 'core.autocrlf', 'false')

    def git(self, *args):
        run = subprocess.run(['git', '-C', str(self.repo), *args], capture_output=True, check=True)
        return run.stdout.decode().strip()

    def write(self, name, content):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content if isinstance(content, bytes) else content.encode())

    def commit(self):
        self.git('add', '--all')
        self.git('commit', '-qm', 'test: add synthetic fixture')
        return self.git('rev-parse', 'HEAD')

    def test_rename_binary_deletion_names_and_budget(self):
        self.write('secret source.txt', 'keep\n' * 10)
        self.write('deleted.txt', 'gone\n')
        self.write('image.bin', b'\0old')
        self.write('src/tab\tname.txt', 'old\n')
        self.write('src/雪.txt', 'old\n')
        base = self.commit()
        self.git('mv', 'secret source.txt', 'renamed source.txt')
        (self.repo / 'deleted.txt').unlink()
        self.write('image.bin', b'\0new')
        self.write('src/tab\tname.txt', 'new\n')
        self.write('src/雪.txt', 'new\n')
        self.write('src/line\nbreak.txt', 'new\n')
        head = self.commit()
        report = analyze_repo(self.repo, base, head, {'allow': ['src/*', 'renamed source.txt'], 'deny': ['image.bin'], 'max_changed_lines': 5})
        files = {file['new']: file for file in report['files']}
        self.assertEqual(files['renamed source.txt']['old'], 'secret source.txt')
        self.assertEqual(files['renamed source.txt']['status'], 'R100')
        self.assertTrue(files['image.bin']['binary'])
        self.assertEqual(files['deleted.txt']['status'], 'D')
        self.assertEqual(files['deleted.txt']['deleted'], 1)
        self.assertEqual(files['src/雪.txt']['added'], 1)
        self.assertEqual(report['changed_lines'], 6)
        for path, reason in (('secret source.txt', 'outside_allowlist'), ('image.bin', 'denied_path'), ('image.bin', 'binary_requires_review'), ('src/tab\tname.txt', 'unsafe_path'), ('src/line\nbreak.txt', 'unsafe_path')):
            self.assertIn({'path': path, 'reason': reason}, report['findings'])
        self.assertEqual(report['comparison'], {'base': base, 'head': head})

    def test_empty_add_mode_change_and_symlink_are_accounted(self):
        self.write('run.sh', 'echo hi\n')
        base = self.commit()
        self.write('empty.txt', '')
        os.chmod(self.repo / 'run.sh', 0o755)
        os.symlink('run.sh', self.repo / 'link')
        self.commit()
        report = analyze_repo(self.repo, base)
        files = {file['new']: file for file in report['files']}
        self.assertEqual(files['empty.txt']['added'], 0)
        self.assertEqual(files['run.sh']['new_mode'], '100755')
        self.assertEqual(files['run.sh']['added'], 0)
        self.assertEqual(files['link']['new_mode'], '120000')
        self.assertEqual(report['changed_lines'], 1)

    def test_diff_drivers_and_textconv_never_execute(self):
        marker = self.repo / 'EXECUTED'
        script = self.repo / 'driver.py'
        script.write_text('from pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\nprint("converted")\n')
        self.write('.gitattributes', '*.txt diff=hostile\n')
        self.write('a.txt', 'one\n')
        base = self.commit()
        self.git('config', 'diff.hostile.command', sys.executable + ' ' + str(script))
        self.git('config', 'diff.hostile.textconv', sys.executable + ' ' + str(script))
        self.write('a.txt', 'two\n')
        self.commit()
        with patch.dict(os.environ, {'GIT_EXTERNAL_DIFF': sys.executable + ' ' + str(script), 'GIT_DIR': str(self.repo / 'nonexistent')}):
            report = analyze_repo(self.repo, base)
        self.assertFalse(marker.exists())
        self.assertEqual(report['changed_lines'], 2)

    def test_repo_subdirectory_uses_repo_relative_names(self):
        self.write('inside/a.txt', 'old\n')
        self.write('outside.txt', 'old\n')
        base = self.commit()
        self.write('outside.txt', 'new\n')
        self.commit()
        self.git('config', 'diff.relative', 'true')
        report = analyze_repo(self.repo / 'inside', base, policy={'allow': ['inside/*']})
        self.assertEqual(report['files'][0]['new'], 'outside.txt')
        self.assertFalse(report['within_scope'])

    def test_git_applicable_redundant_slashes_cannot_bypass_deny(self):
        self.write('src/secret.txt', 'old\n')
        self.commit()
        diff = 'diff --git a/src//secret.txt b/src//secret.txt\n--- a/src//secret.txt\n+++ b/src//secret.txt\n@@ -1 +1 @@\n-old\n+new\n'
        applicable = subprocess.run(
            ['git', '-C', str(self.repo), 'apply', '--check', '-'],
            input=diff, capture_output=True, text=True,
        )
        self.assertEqual(applicable.returncode, 0, applicable.stderr)
        report = analyze({'diff': diff, 'deny': ['src/secret.txt']})
        self.assertFalse(report['within_scope'])
        self.assertIn({'path': 'src//secret.txt', 'reason': 'unsafe_path'}, report['findings'])
        # --check and analysis must leave the canonical protected file untouched.
        self.assertEqual((self.repo / 'src/secret.txt').read_text(), 'old\n')

    def test_safe_revision_errors_and_identical_commits(self):
        self.write('x', 'data\n')
        base = self.commit()
        self.assertTrue(analyze_repo(self.repo, base, base)['within_scope'])
        for revision in ('--help', 'does-not-exist', 'HEAD\0bad', ''):
            with self.subTest(revision=revision), self.assertRaises(ValueError):
                analyze_repo(self.repo, revision)

    def test_non_utf8_paths_fail_closed(self):
        self.write('x', 'old\n')
        base = self.commit()
        # Build the tree directly: macOS filesystems may reject invalid UTF-8 names.
        blob = subprocess.run(['git', '-C', str(self.repo), 'hash-object', '-w', '--stdin'], input=b'data', capture_output=True, check=True).stdout.strip()
        tree = subprocess.run(['git', '-C', str(self.repo), 'mktree', '-z'], input=b'100644 blob ' + blob + b'\tbad-\xff\0', capture_output=True, check=True).stdout.strip()
        head = subprocess.run(['git', '-C', str(self.repo), 'commit-tree', tree.decode(), '-p', base, '-m', 'test: add non-UTF-8 path'], capture_output=True, check=True).stdout.decode().strip()
        with self.assertRaisesRegex(ValueError, 'non-UTF-8'):
            analyze_repo(self.repo, base, head)

    def test_submodule_change_requires_review(self):
        self.write('x', 'old\n')
        base = self.commit()
        self.git('update-index', '--add', '--cacheinfo', '160000,' + base + ',vendor/library')
        self.git('commit', '-qm', 'test: add synthetic gitlink')
        report = analyze_repo(self.repo, base)
        self.assertIn({'path': 'vendor/library', 'reason': 'submodule_requires_review'}, report['findings'])

    def test_existing_submodule_update_is_reviewed_in_text_and_native_modes(self):
        self.write('x', 'first target\n')
        target_one = self.commit()
        self.write('x', 'second target\n')
        target_two = self.commit()
        self.git('update-index', '--add', '--cacheinfo', '160000,' + target_one + ',vendor/library')
        self.git('commit', '-qm', 'test: add initial synthetic gitlink')
        base = self.git('rev-parse', 'HEAD')
        self.git('update-index', '--cacheinfo', '160000,' + target_two + ',vendor/library')
        self.git('commit', '-qm', 'test: update synthetic gitlink')
        diff = self.git('diff', '--no-ext-diff', '--no-textconv', '--submodule=short', base, 'HEAD')
        self.assertIn(' 160000\n', diff)
        for report in (analyze({'diff': diff}), analyze_repo(self.repo, base)):
            self.assertFalse(report['within_scope'])
            self.assertIn({'path': 'vendor/library', 'reason': 'submodule_requires_review'}, report['findings'])
            self.assertEqual(report['files'][0]['old_mode'], '160000')
            self.assertEqual(report['files'][0]['new_mode'], '160000')

    def test_cli_check_codes_and_policy(self):
        self.write('private.txt', 'old\n')
        base = self.commit()
        self.write('private.txt', 'new\n')
        head = self.commit()
        policy = self.repo / 'policy.json'
        policy.write_text(json.dumps({'deny': ['private.txt']}))
        command = [sys.executable, '-m', 'patch_scope_guard', '--repo', str(self.repo), '--base', base, '--head', head, '--policy', str(policy)]
        run = subprocess.run(command + ['--check'], capture_output=True, text=True)
        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertFalse(json.loads(run.stdout)['within_scope'])
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        allowed = subprocess.run(command[:-2] + ['--head', base, '--check'], capture_output=True, text=True)
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        invalid = subprocess.run(command + ['--base', '--help'], capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 2)
        self.assertNotIn('Traceback', invalid.stderr)
