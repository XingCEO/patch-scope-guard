import unittest
from patch_scope_guard import analyze

class ScopeTests(unittest.TestCase):
    def test_rename_source_is_checked(self):
        r=analyze({'diff':'diff --git a/secret.txt b/src/a.txt\nsimilarity index 100%\nrename from secret.txt\nrename to src/a.txt','allow':['src/*']})
        self.assertFalse(r['within_scope'])
    def test_additions_that_look_like_headers_count(self):
        r=analyze({'diff':'diff --git a/x b/x\n--- a/x\n+++ b/x\n@@ -0,0 +1 @@\n+++data'})
        self.assertEqual(r['changed_lines'],1)
    def test_traversal(self):
        self.assertFalse(analyze({'diff':'diff --git a/../x b/../x'})['within_scope'])
    def test_empty(self):
        self.assertTrue(analyze({'diff':''})['within_scope'])
    def test_merge_rejected(self):
        with self.assertRaises(ValueError): analyze({'diff':'diff --cc x'})
