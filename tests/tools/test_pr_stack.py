#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
"""Real Git fixtures for squash/restack, conflict detection and isolation."""
from pathlib import Path
import tempfile
import unittest

from verify_pr_stack import StackError, group_stacks, order_prs, run, verify


class StackTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repo = Path(temporary.name) / 'repository'
        run(['git', 'init', '-b', 'develop', str(self.repo)])
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        # Fixture commits are raw unpublished objects, independent of signing
        # hooks and configuration for the user's actual repository.
        (self.repo / 'file').write_text('base\n')
        self.commit()
        self.root = self.git('rev-parse', 'HEAD')

    def git(self, *args, **kwargs):
        return run(['git', '-C', str(self.repo), *args], **kwargs)

    def commit(self):
        self.git('add', '.')
        tree = self.git('write-tree')
        result = self.git('rev-parse', '--verify', 'HEAD') if (self.repo / '.git/refs/heads/develop').exists() else None
        parent = f'parent {result}\n' if result else ''
        text = (f'tree {tree}\n{parent}author Fixture <fixture@example.invalid> 0 +0000\n'
                'committer Fixture <fixture@example.invalid> 0 +0000\n\nFixture\n')
        sha = self.git('hash-object', '-t', 'commit', '-w', '--stdin', input=text)
        self.git('update-ref', 'HEAD', sha)
        return sha

    def pr(self, number, head, head_sha, base, base_sha):
        return {'number': number,
                'head': {'ref': head, 'sha': head_sha, 'repo': {'full_name': 'Cacti/spine'}},
                'base': {'ref': base, 'sha': base_sha, 'repo': {'full_name': 'Cacti/spine'}}}

    def stack(self):
        self.git('checkout', '-b', 'one')
        (self.repo / 'file').write_text('first\n')
        first = self.commit()
        self.git('checkout', '-b', 'two')
        (self.repo / 'file').write_text('second\n')
        second = self.commit()
        return [self.pr(1, 'one', first, 'develop', self.root),
                self.pr(2, 'two', second, 'one', first)]

    def test_squashed_parent_requires_restacking(self):
        prs = self.stack()
        refs = self.git('show-ref')
        status = self.git('status', '--porcelain')
        report = verify(self.repo, prs, 'Cacti/spine')
        self.assertEqual(report['dependency_order'], [1, 2])
        self.assertEqual(report['results'][-1]['restacked_tree'],
                         self.git('rev-parse', 'two^{tree}'))
        self.assertEqual(self.git('show-ref'), refs)
        self.assertEqual(self.git('status', '--porcelain'), status)

    def test_preserves_new_upstream_changes(self):
        prs = self.stack()
        self.git('checkout', 'develop')
        (self.repo / 'upstream').write_text('new upstream work\n')
        self.commit()
        prs[0]['base']['sha'] = self.git('rev-parse', 'HEAD')
        expected = self.git('rev-parse', 'HEAD:upstream')
        report = verify(self.repo, prs, 'Cacti/spine')
        self.assertTrue(report['all_clean'])
        # The final tree is synthesized only in the disposable repository.
        # Compute the expected tree from the two real files for comparison.
        (self.repo / 'file').write_text('second\n')
        self.git('add', 'file')
        self.assertEqual(report['results'][-1]['restacked_tree'], self.git('write-tree'))
        self.assertEqual(self.git('rev-parse', 'HEAD:upstream'), expected)

    def test_conflicting_upstream_is_rejected(self):
        prs = self.stack()
        self.git('checkout', 'develop')
        (self.repo / 'file').write_text('conflicting upstream\n')
        prs[0]['base']['sha'] = self.commit()
        with self.assertRaises(StackError):
            verify(self.repo, prs, 'Cacti/spine')

    def test_conflicting_siblings_are_rejected(self):
        prs = self.stack()
        prs[1]['base'] = prs[0]['base'].copy()
        with self.assertRaises(StackError):
            verify(self.repo, prs, 'Cacti/spine')

    def test_dependency_order_is_not_input_order(self):
        prs = self.stack()
        self.assertEqual([p['number'] for p in order_prs(prs[::-1], ('Cacti/spine', 'develop'))], [1, 2])

    def test_duplicate_disconnected_cycle_and_invalid_revision(self):
        prs = self.stack()
        for invalid in ([prs[0], prs[0]], [prs[1]]):
            with self.assertRaises(StackError):
                order_prs(invalid, ('Cacti/spine', 'develop'))
        prs[0]['base'] = prs[1]['head'].copy()
        with self.assertRaises(StackError):
            order_prs(prs, ('Cacti/spine', 'develop'))
        prs[0]['head']['sha'] = '--bad-option'
        with self.assertRaises(StackError):
            order_prs(prs, ('Cacti/spine', 'develop'))

    def test_independent_maintenance_stack_is_verified_separately(self):
        prs = self.stack()
        self.git('branch', '1.2.x', self.root)
        maintenance = self.pr(3, 'backport', self.root, '1.2.x', self.root)
        child = self.pr(4, 'backport-child', self.root, 'backport', self.root)
        groups = group_stacks([child, *prs, maintenance], 'Cacti/spine', ['develop', '1.2.x'])
        self.assertEqual([p['number'] for p in groups['develop']], [1, 2])
        self.assertEqual([p['number'] for p in groups['1.2.x']], [3, 4])
        self.assertTrue(verify(self.repo, groups['develop'], 'Cacti/spine')['all_clean'])
        self.assertTrue(verify(self.repo, groups['1.2.x'], 'Cacti/spine', '1.2.x')['all_clean'])
        with self.assertRaises(StackError):
            group_stacks([*prs, maintenance], 'Cacti/spine', ['develop'])

    def test_independent_maintenance_conflict_is_rejected(self):
        prs = self.stack()
        self.git('checkout', '-b', '1.2.x', self.root)
        self.git('checkout', '-b', 'backport')
        (self.repo / 'file').write_text('backport\n')
        head = self.commit()
        self.git('checkout', '1.2.x')
        (self.repo / 'file').write_text('maintenance upstream\n')
        base = self.commit()
        groups = group_stacks([*prs, self.pr(3, 'backport', head, '1.2.x', base)],
                              'Cacti/spine', ['develop', '1.2.x'])
        with self.assertRaises(StackError):
            verify(self.repo, groups['1.2.x'], 'Cacti/spine', '1.2.x')

    def test_shallow_source_preserves_the_history_boundary(self):
        old_root = self.root
        (self.repo / 'file').write_text('new base\n')
        self.root = self.commit()
        prs = self.stack()
        (self.repo / '.git' / 'shallow').write_text(self.root + '\n')
        (self.repo / '.git' / 'objects' / old_root[:2] / old_root[2:]).unlink()
        checkout = self.repo.parent / 'checkout'
        self.git('worktree', 'add', '--detach', str(checkout), 'two')
        self.assertTrue(verify(checkout, prs, 'Cacti/spine')['all_clean'])

    def test_empty_stack(self):
        self.assertEqual(verify(self.repo, [], 'Cacti/spine')['dependency_order'], [])


if __name__ == '__main__':
    unittest.main()
