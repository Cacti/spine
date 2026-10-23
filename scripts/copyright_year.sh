#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2004-2026 The Cacti Group
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This code is designed, written, and maintained by the Cacti Group. See
# CONTRIBUTORS.md for developer information.
#
# Fork maintenance: Thomas Vincent.
# Project contributor history: CONTRIBUTORS.md.

update_copyright() {
	local original_file=$1
	local file=$original_file
	file=${file/$SCRIPT_BASE/}
	printf -v line "%60s" "$file"
	if [[ -z "$ERRORS_ONLY" ]]; then
		echo -n "$line"
		line=
	fi

	old_reg="20[0-9][0-9][ ]*-[ ]*20[0-9][0-9]"
	old_data=$(grep -c -e "$old_reg" "$original_file" 2>/dev/null)
	new_reg="2004-$YEAR"


	if [[ $old_data -eq 0 ]]; then
		old_reg="(Copyright.*) 20[0-9][0-9] "
		old_data=$(grep -c -e "$old_reg" "$original_file" 2>/dev/null)
		new_reg="\1 2004-$YEAR"

	fi

	if [[ $old_data -gt 0 ]]; then
		old_data=$(grep -e "$old_reg" "$original_file" 2>/dev/null)
		new_data=$(echo "$old_data" | sed -r s/"$old_reg"/"$new_reg"/g)
		if [[ "$old_data" == "$new_data" ]]; then
			if [[ -z "$ERRORS_ONLY" ]]; then
				echo "$line Skipping Copyright Data"
			fi
		else
			echo "$line Updating Copyright Data"
			printf '%60s %s\n' "==============================" "===================="
			printf '%60s %s\n' "$old_data" "=>"
			printf '%60s %s\n' "$new_data" ""
			sed -i -r s/"$old_reg"/"$new_reg"/g "$original_file"
			printf '%60s %s\n' "==============================" "===================="
		fi
	else
		echo "$line  Copyright not found!"

	fi
	return 0
}

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
SCRIPT_BASE=$(realpath "${SCRIPT_DIR}/")/

BAD_FOLDERS="\.git include/vendor \*\*/vendor include/fa cache include/js scripts"
SCRIPT_EXCLUSION=
for f in $BAD_FOLDERS; do
	SCRIPT_EXCLUSION="$SCRIPT_EXCLUSION -not -path ${SCRIPT_BASE}$f/\* "
done


YEAR=$(date +"%Y")
EXT="" # "sh sql php js md conf c h ac dist"
ERRORS_ONLY=1
while [[ -n "$1" ]]; do
	case $1 in
	"--help")
		echo "NOTE: Checks all Cacti pages for this years copyright"
		echo ""
		echo "usage: scripts/copyright_year.sh [-a]"
		echo ""
		;;
	"-E" | "-e")
		shift
		EXT="$1"
		;;
	"-A" | "-a")
		ERRORS_ONLY=
		echo "Searching..."
		;;
	*) ;;

	esac
	shift
done

# ----------------------------------------------
# PHP / JS / MD Files
# ----------------------------------------------
SCRIPT_INCLUSION=
SCRIPT_SEPARATOR=
for ext in $EXT; do
	if [[ -n "$SCRIPT_INCLUSION" ]]; then
		SCRIPT_SEPARATOR="-o "
	fi
	SCRIPT_INCLUSION="$SCRIPT_INCLUSION $SCRIPT_SEPARATOR-name \*.$ext"
done

if [[ -n "$SCRIPT_INCLUSION" ]]; then
	SCRIPT_INCLUSION="\( $SCRIPT_INCLUSION \)"
fi

SCRIPT_CMD="find ${SCRIPT_BASE} -type f $SCRIPT_INCLUSION $SCRIPT_EXCLUSION -print0"
bash -c "$SCRIPT_CMD" | while IFS= read -r -d '' file; do
	update_copyright "${file}"
done
