#!/usr/bin/env bash
set -euo pipefail
# +-------------------------------------------------------------------------+
# | Copyright (C) 2004-2026 The Cacti Group                                 |
# |                                                                         |
# | This program is free software; you can redistribute it and/or           |
# | modify it under the terms of the GNU General Public License             |
# | as published by the Free Software Foundation; either version 2          |
# | of the License, or (at your option) any later version.                  |
# |                                                                         |
# | This program is distributed in the hope that it will be useful,         |
# | but WITHOUT ANY WARRANTY; without even the implied warranty of          |
# | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           |
# | GNU General Public License for more details.                            |
# +-------------------------------------------------------------------------+
# | Cacti: The Complete RRDtool-based Graphing Solution                     |
# +-------------------------------------------------------------------------+
# | This code is designed, written, and maintained by the Cacti Group. See  |
# | about.php and/or the AUTHORS file for specific developer information.   |
# +-------------------------------------------------------------------------+
# | http://www.cacti.net/                                                   |
# +-------------------------------------------------------------------------+

# Variable Declaration
TMP_DIR="/tmp"

# Help Display function
display_help () {
  echo "----------------------------------------------------------------------------"
  echo " Spine Package Script"
  echo "   Attempts to package spine from a repository checkout directory of"
  echo "   spine. If all goes well a tar.gz file will be created."
  echo "----------------------------------------------------------------------------"
  echo " Syntax:"
  echo "  $0 <Version>"
  echo ""
  echo "    <Version> - Designated version for build (required)"
  echo ""
}

# Sanity checks
[ ! -e configure.ac ] && echo "ERROR: Your current working directory must be the SVN check out of Spine" && exit 1

if [[ ${1:-} == --help || ${1:-} == -h ]]; then
  display_help
  exit 0
fi

if [ -z "${1:-}" ]; then
  echo ""
  echo "ERROR: Invalid syntax, missing required argument"
  echo ""
  display_help
  exit 1
fi
VERSION=${1}
case "$VERSION" in
  *[!A-Za-z0-9.+-]* | .* | -*)
    echo "ERROR: Invalid version component" >&2
    exit 1
    ;;
esac

# Perform packaging
echo ""
echo "----------------------------------------------------------------------------"
echo "Spine package builder"
echo "  Version: ${VERSION}"
echo "----------------------------------------------------------------------------"

# Clean up previous builds
if [ -e "${TMP_DIR}/cacti-spine-${VERSION}" ]; then
  echo "INFO: Removing previous build ${TMP_DIR}/cacti-spine-${VERSION}..."
  if ! rm -Rf -- "${TMP_DIR}/cacti-spine-${VERSION}"; then
    echo "ERROR: Unable to remove directory: ${TMP_DIR}/cacti-spine-${VERSION}" >&2
    exit 1
  fi
fi
if [ -e "${TMP_DIR}/cacti-spine-${VERSION}.tar.gz" ]; then
  if ! rm -Rf -- "${TMP_DIR}/cacti-spine-${VERSION}.tar.gz"; then
    echo "ERROR: Unable to remove file: ${TMP_DIR}/cacti-spine-${VERSION}.tar.gz" >&2
    exit 1
  fi
fi

# Copy repository
mkdir -p "${TMP_DIR}/cacti-spine-${VERSION}"
if ! tar -cf - ./* | (
  cd "${TMP_DIR}/cacti-spine-${VERSION}" || exit 1
  tar -xf -
); then
  echo "ERROR: Unable to copy repository to ${TMP_DIR}/cacti-spine-${VERSION}" >&2
  exit 1
fi

# Native BSD tar has no GNU --exclude option. Prune obsolete metadata only
# from the staged copy, after copying with portable tar arguments.
find "${TMP_DIR}/cacti-spine-${VERSION}" \
  \( -name .svn -o -name .travis.yml \) -prune -exec rm -rf -- {} +

# Change working directory
pushd "${TMP_DIR}/cacti-spine-${VERSION}" > /dev/null || exit 1

# Get version from source files, warn if different than defined for build
SRC_VERSION=$(grep AC_INIT configure.ac | awk -F, '{print $2}' | sed 's/ //g')
if [ "${SRC_VERSION}" != "${VERSION}" ]; then
  echo "WARNING: Build version and source version are not the same";
  echo "WARNING:    Build Version: ${VERSION}"
  echo "WARNING:   Source Version: ${SRC_VERSION}"
fi

# Call bootstrap
echo "INFO: call bootstrap..."
./bootstrap

# Check working directory
cd "$TMP_DIR" || exit 1

# Package it
echo "INFO: Packaging..."
if ! tar -zcf "cacti-spine-${VERSION}.tar.gz" "cacti-spine-${VERSION}"; then
  echo "ERROR: Unable to package" >&2
  exit 1
fi

# Change working directory
popd > /dev/null || exit 1

# Clean up
echo "INFO: Cleaning up build directory..."
rm -rf -- "${TMP_DIR}/cacti-spine-${VERSION}"

# Display file locations
echo "INFO: Completed..."
echo ""
echo "Package file: ${TMP_DIR}/cacti-spine-${VERSION}.tar.gz"
echo ""

exit 0
