#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify PR deltas under squash-and-restack without modifying source refs."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


class StackError(RuntimeError):
    pass


def run(command, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise StackError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def order_prs(prs, root, other_roots=()):
    numbers, heads = set(), set()
    for pr in prs:
        number = pr['number']
        head = (pr['head']['repo']['full_name'], pr['head']['ref'])
        if number in numbers or head in heads:
            raise StackError('Duplicate PR or head branch')
        numbers.add(number)
        heads.add(head)
        for side in ('head', 'base'):
            if not re.fullmatch(r'[0-9a-f]{40}', pr[side]['sha']):
                raise StackError('Invalid revision')
    pending, ordered, available = list(prs), [], {root, *other_roots}
    while pending:
        ready = [pr for pr in pending if
                 (pr['base']['repo']['full_name'], pr['base']['ref']) in available]
        if not ready:
            raise StackError('Disconnected or cyclic PR dependencies')
        for pr in sorted(ready, key=lambda pr: pr['number']):
            ordered.append(pr)
            available.add((pr['head']['repo']['full_name'], pr['head']['ref']))
            pending.remove(pr)
    return ordered


def group_stacks(prs, repository, branches):
    if not branches or len(set(branches)) != len(branches):
        raise StackError('Duplicate or missing root branch')
    roots = [(repository, branch) for branch in branches]
    ordered = order_prs(prs, roots[0], roots[1:])
    owners = {root: root[1] for root in roots}
    groups = {branch: [] for branch in branches}
    for pr in ordered:
        base = (pr['base']['repo']['full_name'], pr['base']['ref'])
        head = (pr['head']['repo']['full_name'], pr['head']['ref'])
        branch = owners[base]
        groups[branch].append(pr)
        owners[head] = branch
    return groups


def changed_paths(git, old, new):
    return set(git('diff-tree', '-r', '--name-only', '--no-renames', old, new).splitlines())


def blob_at(git, revision, path):
    try:
        return git('rev-parse', f'{revision}:{path}')
    except StackError:
        return None


def verify(source, prs, repository, root_branch='develop', fetch=False):
    ordered = order_prs(prs, (repository, root_branch))
    with tempfile.TemporaryDirectory(prefix='spine-stack-') as directory:
        git_dir = Path(directory) / 'simulation.git'
        run(['git', 'clone', '--bare', '--shared', str(source), str(git_dir)])
        # Cloning a shallow worktree locally omits the history boundary.
        # Preserve it instead of walking into parents the source never fetched.
        if run(['git', '-C', str(source), 'rev-parse', '--is-shallow-repository']) == 'true':
            shallow = Path(run(['git', '-C', str(source), 'rev-parse', '--git-path', 'shallow']))
            if not shallow.is_absolute():
                shallow = Path(source) / shallow
            shutil.copyfile(shallow, git_dir / 'shallow')


        def git(*arguments, **kwargs):
            return run(['git', '--git-dir=' + str(git_dir), *arguments], **kwargs)

        def synthetic(tree, parent, message):
            commit = (f'tree {tree}\nparent {parent}\n'
                      'author Stack Audit <audit@example.invalid> 0 +0000\n'
                      'committer Stack Audit <audit@example.invalid> 0 +0000\n\n'
                      f'{message}\n')
            return git('hash-object', '-t', 'commit', '-w', '--stdin', input=commit)

        root_ref = root_branch
        if fetch:
            url = 'https://github.com/' + repository + '.git'
            refs = [f'+refs/heads/{root_branch}:refs/audit/root']
            refs.extend(f'+refs/pull/{pr["number"]}/head:refs/audit/pr/{pr["number"]}'
                        for pr in ordered)
            refs.extend(f'+refs/heads/{pr["base"]["ref"]}:refs/audit/base/{pr["number"]}'
                        for pr in ordered)
            git('fetch', '--no-tags', url, *refs)
            root_ref = 'refs/audit/root'
            # The API reports the base tip as of the PR's last update, which is
            # stale as soon as the base branch moves. Only the head is a stable
            # identity; the base is whatever the branch is now.
            for pr in ordered:
                if git('rev-parse', f'refs/audit/pr/{pr["number"]}') != pr['head']['sha']:
                    raise StackError('PR moved during fetch; repeat the audit')
        current = original_root = git('rev-parse', root_ref)
        results = []
        for pr in ordered:
            head = pr['head']['sha']
            base = git('rev-parse', f'refs/audit/base/{pr["number"]}') if fetch else pr['base']['sha']
            # Check the existing PR independently, then replay its complete delta
            # on the simulated squashed parent. Ordinary merges retain ancestry;
            # squash merges require this explicit restacking step.
            direct_tree = git('merge-tree', '--write-tree', base, head).splitlines()[0]
            ancestor = git('merge-base', base, head)
            # Give the current result tree an ephemeral parent at the original
            # delta boundary, forcing that three-way base on Git 2.38+ without
            # requiring the newer merge-tree --merge-base option. This pivot
            # ancestry is never retained by the resulting squash commit.
            pivot = synthetic(git('rev-parse', current + '^{tree}'), ancestor,
                              f'Unpublished replay pivot for PR #{pr["number"]}')
            tree = git('merge-tree', '--write-tree', pivot, head).splitlines()[0]
            # A restack must carry every path the PR changes: a path in the
            # direct delta that the replay left alone must already match the
            # head, otherwise the delta was dropped without a textual conflict.
            direct_paths = changed_paths(git, ancestor, head)
            parent_tree = git('rev-parse', current + '^{tree}')
            restacked_paths = changed_paths(git, parent_tree, tree)
            for path in sorted(direct_paths - restacked_paths):
                if blob_at(git, tree, path) != blob_at(git, head, path):
                    raise StackError(f'Restack of PR #{pr["number"]} dropped its change to {path}')
            current = synthetic(tree, current,
                                f'Unpublished squash/restack simulation of PR #{pr["number"]}')
            results.append({'number': pr['number'], 'base_sha': base, 'head_sha': head,
                            'direct_tree': direct_tree, 'restacked_tree': tree,
                            'direct_paths': len(direct_paths),
                            'restacked_paths': len(restacked_paths),
                            'simulated_squash': current})
        return {'checked_at_utc': datetime.now(timezone.utc).isoformat(),
                'repository': repository, 'root_branch': root_branch,
                'root_sha': original_root, 'all_clean': True,
                'merge_policy': 'squash each PR delta and restack its dependents',
                'dependency_order': [pr['number'] for pr in ordered], 'results': results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default='Cacti/spine')
    parser.add_argument('--source', default='.')
    parser.add_argument('--root', default='develop')
    parser.add_argument('--other-root', action='append', default=[],
                        help='Additional independent target branch to verify')
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--fetch', action='store_true')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository):
        parser.error('Invalid repository')
    try:
        if args.inventory:
            prs = json.loads(args.inventory.read_text())
        else:
            pages = json.loads(run(['gh', 'api', '--paginate', '--slurp',
                                    f'repos/{args.repository}/pulls?state=open&per_page=100']))
            prs = [pr for page in pages for pr in page]
        groups = group_stacks(prs, args.repository, [args.root, *args.other_root])
        report = verify(args.source, groups[args.root], args.repository, args.root, args.fetch)
        if args.other_root:
            report['independent_stacks'] = [
                verify(args.source, groups[branch], args.repository, branch, args.fetch)
                for branch in args.other_root]

    except (StackError, KeyError, TypeError, ValueError) as error:
        args.output.write_text(json.dumps({'all_clean': False, 'error': str(error)}, indent=2) + '\n')
        raise SystemExit(str(error)) from error
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    for stack in [report, *report.get('independent_stacks', [])]:
        print('Squash/restack verified:', stack['root_branch'],
              ' -> '.join(str(n) for n in stack['dependency_order']))


if __name__ == '__main__':
    main()
