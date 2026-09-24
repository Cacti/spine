#!/usr/bin/env bash
# Verify that every commit in a revision range has a Signed-off-by trailer
# matching that commit's author. This enforces the Developer Certificate of
# Origin without granting a third-party action access to the repository.
set -euo pipefail

if [[ $# -ne 1 || -z $1 ]]; then
	echo "usage: $0 <git-revision-range>" >&2
	exit 2
fi

range=$1
failures=0

while IFS= read -r commit; do
	author=$(git show -s --format='%an <%ae>' "$commit")
	if ! git show -s --format='%B' "$commit" \
		| git interpret-trailers --parse \
		| grep -Fqi "Signed-off-by: $author"; then
		echo "${commit}: missing Signed-off-by: ${author}" >&2
		failures=$((failures + 1))
	fi
done < <(git rev-list --reverse "$range")

if ((failures > 0)); then
	echo "$failures commit(s) failed the DCO check." >&2
	exit 1
fi

echo "All commits in $range have matching Signed-off-by trailers."
