#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
"""Verify PR deltas under squash-and-restack without modifying source refs."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import tempfile


class StackError(RuntimeError):
    pass


def run(command, **kwargs):
    result = subprocess.run(command, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise StackError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def order_prs(prs, root):
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
    pending, ordered, available = list(prs), [], {root}
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


def verify(source, prs, repository, root_branch='develop', fetch=False):
    ordered = order_prs(prs, (repository, root_branch))
    with tempfile.TemporaryDirectory(prefix='spine-stack-') as directory:
        git_dir = Path(directory) / 'simulation.git'
        run(['git', 'clone', '--bare', '--shared', str(source), str(git_dir)])

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
            for pr in ordered:
                for side in ('head', 'base'):
                    ref = f'refs/audit/{"pr" if side == "head" else "base"}/{pr["number"]}'
                    if git('rev-parse', ref) != pr[side]['sha']:
                        raise StackError('PR moved during fetch; repeat the audit')
        current = original_root = git('rev-parse', root_ref)
        results = []
        for pr in ordered:
            base, head = pr['base']['sha'], pr['head']['sha']
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
            current = synthetic(tree, current,
                                f'Unpublished squash/restack simulation of PR #{pr["number"]}')
            results.append({'number': pr['number'], 'base_sha': base, 'head_sha': head,
                            'direct_tree': direct_tree, 'restacked_tree': tree,
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
        report = verify(args.source, prs, args.repository, args.root, args.fetch)
    except (StackError, KeyError, TypeError, ValueError) as error:
        args.output.write_text(json.dumps({'all_clean': False, 'error': str(error)}, indent=2) + '\n')
        raise SystemExit(str(error)) from error
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print('Squash/restack verified:', ' -> '.join(str(n) for n in report['dependency_order']))


if __name__ == '__main__':
    main()
