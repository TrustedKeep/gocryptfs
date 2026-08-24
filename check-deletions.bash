#!/bin/bash
#
# check-deletions.bash verifies that nothing listed in .merge-deletions has
# reappeared in the working tree.
#
# Run it after every upstream merge, including when the merge reports no conflicts.
# An upstream release that adds files underneath a subsystem this fork removed
# produces no conflict at all, so this is the only thing standing between us and
# silently re-importing code we deliberately deleted.
#
# This is deliberately the only script in the merge workflow; everything else is
# documented commands in Documentation/tk-upstream-merge.md. It stays a script
# because it checks 15+ manifest paths and returns an exit code, and because the
# thing it detects is invisible in merge output.
#
# Exits 0 if clean, 1 if any listed path exists, 2 on usage errors.

set -eu

cd "$(dirname "$0")"

MANIFEST=.merge-deletions

if [[ ! -f $MANIFEST ]]; then
	echo "check-deletions: $MANIFEST not found" >&2
	exit 2
fi

resurrected=()
entries=0

while read -r line; do
	# Strip comments, then trim leading and trailing whitespace only. Do NOT
	# squeeze all whitespace out: a path may legitimately contain a space, and
	# collapsing it would silently check the wrong path and pass.
	entry=${line%%#*}
	entry=${entry#"${entry%%[![:space:]]*}"}
	entry=${entry%"${entry##*[![:space:]]}"}
	[[ -z $entry ]] && continue
	entries=$((entries + 1))
	# -L as well as -e: -e is false for a dangling symlink, but a symlink
	# reappearing at a path we deleted still counts as the path coming back.
	if [[ -e "$entry" || -L "$entry" ]]; then
		resurrected+=("$entry")
	fi
done < "$MANIFEST"

if [[ $entries -eq 0 ]]; then
	echo "check-deletions: $MANIFEST lists no paths - refusing to pass vacuously" >&2
	exit 2
fi

if [[ ${#resurrected[@]} -eq 0 ]]; then
	echo "check-deletions: OK, all $entries intentionally-removed paths are still absent"
	exit 0
fi

cat >&2 <<'EOF'
check-deletions: FAILED

The paths below are listed in .merge-deletions as intentionally removed from
this fork, but they exist in the working tree. This almost always means an
upstream merge re-added them without conflicting.

Decide per path:
  - still unwanted -> git rm -rf <path>
  - now wanted     -> delete its line from .merge-deletions and say why

EOF

for p in "${resurrected[@]}"; do
	echo "  resurrected: $p" >&2
done

exit 1
