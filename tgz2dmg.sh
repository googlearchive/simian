#!/bin/bash
#
# Copyright 2011 Google.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# #

# Translate a tgz into an installable pkg inside a dmg.

set -i
set -e

if [[ $(uname) != "Darwin" ]]; then
  echo $0 must run on OS X
  exit 1
fi

TGZ="$1"
OUT="$2"
ORIGPWD="$PWD"
ID="com.google.code.simian"
VERSION="1"
PKGONLY=""
PKGBUILD=$(which pkgbuild)

if [[ "$#" -lt 2 ]]; then
  echo usage: $0 tgz_input_file dmg\|pkg_output_file [options...]
  echo
  echo options:
  echo -vep binary          add binary to directory which is prepended onto
  echo                      PATH during postflight virtualenv install.
  echo -pyver version       create python version hint e.g. \"2.5\"
  echo -pkgonly             do not create a dmg, just create a pkg
  echo -version version     set package version to version
  echo -id id               set package id, default $ID
  echo -s script_file       add script to package
  echo -r resource_file     add resource file to package resources
  echo -R resource_dir      add a file OR dir into package resources
  echo                      NOTE: IF YOU USE GLOBS PUT THE PATTERN IN QUOTES\!
  echo -c src dst           copy a file into the installation tree of package
  echo                      e.g. -c /tmp/foo.py Library/Foo/Bar/foo.py
  echo
  exit 1
fi

shift ; shift

if [[ -z "$PKGBUILD" ]]; then
  echo "cannot find executable Apple pkgbuild tool."
  exit 1
fi

TMPDIR=$(mktemp -d tgz2dmgXXXXXX)
echo "TMPDIR is ${TMPDIR}"
mkdir -p "${TMPDIR}/contents"
mkdir -p "${TMPDIR}/pkg"
mkdir -p "${TMPDIR}/resources"
mkdir -p "${TMPDIR}/resources/vep"
mkdir -p "${TMPDIR}/scripts"

trap "rm -rf \"${TMPDIR}\"" EXIT

if [[ "$TGZ" != "" ]]; then
  tar -zpxf "$TGZ" -C "${TMPDIR}/contents"
fi

# parse argv
next=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$next" = "" ]]; then
    if [[ "$1" = "-s" ]]; then
      next="script"
    elif [[ "$1" = "-r" ]]; then
      next="rsrc"
    elif [[ "$1" = "-c" ]]; then
      next="copy"
    elif [[ "$1" = "-R" ]]; then
      next="rsrcdir"
    elif [[ "$1" = "-id" ]]; then
      next="id"
    elif [[ "$1" = "-version" ]]; then
      next="version"
    elif [[ "$1" = "-pkgonly" ]]; then
      PKGONLY="1"
      next=""
    elif [[ "$1" = "-pyver" ]]; then
      next="pyver"
    elif [[ "$1" = "-vep" ]]; then
      next="vep"
    else
      echo Unknown argument "$1"
    fi
  else
    if [[ "$next" = "script" ]]; then
      if [[ $PKGBUILD == "" ]]; then
        cp "$1" "${TMPDIR}/scripts"
      else
        cp postinstall "${TMPDIR}/scripts"
        cp roots.pem "${TMPDIR}/scripts"
      fi
    elif [[ "$next" = "rsrc" ]]; then
      cp "$1" "${TMPDIR}/resources"
    elif [[ "$next" = "rsrcdir" ]]; then
      # try to helpfully warn the user if they supplied the arguments
      # as -R *.foo (which the shell has already expanded) versus
      # hiding the glob inside quotes as -R '*.foo'.
      defensive_next="$2"
      if [[ "$#" -gt 1 && "${defensive_next:0:1}" != "-" ]]; then
        echo "warning: did you mean -R '*.pattern' (quote glob patterns)"
      fi
      r="$1"
      declare -a rsrcdirs
      rsrcdirs=($1)
      for dirent in "${rsrcdirs[@]}"; do
        [[ -f "${dirent}" ]] && cp "${dirent}" "${TMPDIR}/resources"
        [[ -d "${dirent}" ]] && cp -R "${dirent}" "${TMPDIR}/resources"
      done
    elif [[ "$next" = "id" ]]; then
      ID="$1"
    elif [[ "$next" = "version" ]]; then
      VERSION="$1"
    elif [[ "$next" = "copy" ]]; then
      src="$1"
      shift
      dst="$1"
      cp "$src" "${TMPDIR}/contents/$dst"
    elif [[ "$next" = "pyver" ]]; then
      echo "$1" > "${TMPDIR}/resources/python_version"
    elif [[ "$next" = "vep" ]]; then
      cp "$1" "${TMPDIR}/resources/vep"
    else
      echo Unknown argument "$1"
    fi
    next=""
  fi
  shift
done

cd "${TMPDIR}/contents"
rm -f Distribution

# At this stage we can edit the pkg contents
# and write a preflight to handle other python deps.

cd "$ORIGPWD"

if [[ -z "$PKGONLY" ]]; then
  pkgout="${TMPDIR}/pkg/simian.pkg"
else
  pkgout="$OUT"
fi

echo "Using pkgbuild"
cp -R "${TMPDIR}/resources" "${TMPDIR}/scripts/Resources"
${PKGBUILD} --root "${TMPDIR}/contents" \
    --identifier "$ID" \
    --scripts "${TMPDIR}/scripts" \
    --version "${VERSION}" \
    "${pkgout}"

if [[ -z "$PKGONLY" ]]; then
  hdiutil create -srcfolder "${TMPDIR}/pkg" -layout NONE -volname Simian "$OUT"
fi

rm -rf "${TMPDIR}"
echo output at "$OUT"
