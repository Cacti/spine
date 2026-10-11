<!-- SPDX-FileCopyrightText: 2026 The Cacti Group -->
<!-- SPDX-License-Identifier: GPL-2.0-or-later -->

# Reviewing and merging the Spine PR stack

Cacti/spine permits squash merges and automatically deletes merged branches.
An ordinary merge simulation does not establish that untouched dependent
branches remain safe after a squash: their old parent commits retain different
identities. Merge one PR at a time and restack dependents before continuing.

The open stack audited on 2026-10-11 was:

`#641 → #644 → #654 → #646 → #648 → #649 → #650 → #651 → #655 → #656 → #658`

`tests/tools/verify_pr_stack.py` discovers current PRs through GitHub's API,
validates their dependency graph and exact revisions, and checks each existing
PR merge. In a temporary bare repository it replays each PR's complete delta
against the preceding simulated squash commit. Each synthetic commit has only
the squashed parent. The tool does not publish commits, change source refs or
edit the worktree. It checks complete PR deltas, not individual intermediate
commits in a developer's rebase. Conflicts or disconnected dependencies fail
the check and preserve a diagnostic instead of reporting a clean stack.

```sh
python3 tests/tools/verify_pr_stack.py --fetch --output pr-stack-audit.json
```

The workflow runs on PR updates and `develop` pushes. Its artifact records
exact revisions, dependency order and result trees. Repeat after restacking.

Before squash-merging a parent, record its old head and preserve a local ref.
After the merge, fetch `develop`, replay only the dependent PR's own commits
with `git rebase --onto NEW_PARENT OLD_PARENT CHILD_BRANCH`, and retarget that
PR to `develop` when its immediate parent has merged. Restack later descendants
using each recorded old-parent boundary. Compare the resulting diff with the
reviewed delta, run relevant tests, push with an exact expected-head lease and
wait for checks on the new head. Automatic branch deletion must not erase the
old-parent boundary. Human review remains required.

Cancelled runs are not test failures. Verify successful replacements at the
same head SHA and check identity; a pass on another revision is insufficient.
Rerun stale cancellations instead of deleting history or weakening checks.
