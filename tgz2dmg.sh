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

function find_packagemaker() {
  for path in \
    /Developer/usr/bin/packagemaker \
    /Applications/PackageMaker.app/Contents/MacOS/PackageMaker \
    /Applications/Xcode.app/Contents/Applications/PackageMaker.app/Contents/MacOS/PackageMaker \
    ; do
    if [[ -x "$path" ]]; then
      echo "$path"
      return
    fi
  done
}

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
PKGMAKER=$(find_packagemaker)

if [[ "$#" -lt 2 ]]; then
  echo usage: $0 tgz_input_file dmg\|pkg_output_file [options...]
  echo
  echo options:
  echo -pyver version       create python version hint e.g. \"2.5\"
  echo -pkgonly             do not create a dmg, just create a pkg
  echo -version version     set package version to version
  echo -id id               set package id, default $ID
  echo -s script_file       add script to package
  echo -r resource_file     add resource file to package
  echo -R resource_dir      add a file OR dir into resources
  echo -c src dst           copy a file into the installation tree of package
  echo                      e.g. -c /tmp/foo.py Library/Foo/Bar/foo.py
  echo
  exit 1
fi

shift ; shift

if [[ -z "$PKGMAKER" ]]; then
  echo cannot find executable Apple packagemaker tool.
  exit 1
fi

TMPDIR=$(mktemp -d tgz2dmgXXXXXX)
mkdir -p "$TMPDIR/contents"
mkdir -p "$TMPDIR/pkg"
mkdir -p "$TMPDIR/resources"
mkdir -p "$TMPDIR/scripts"

trap "rm -rf \"$TMPDIR\"" EXIT

if [[ "$TGZ" != "" ]]; then
  tar -zpxf "$TGZ" -C "$TMPDIR/contents"
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
    fi
  else
    if [[ "$next" = "script" ]]; then
      cp "$1" "$TMPDIR/scripts"
    elif [[ "$next" = "rsrc" ]]; then
      cp "$1" "$TMPDIR/resources"
    elif [[ "$next" = "rsrcdir" ]]; then
      [[ -f "$1" ]] && cp "$1" "$TMPDIR/resources"
      [[ -d "$1" ]] && cp -R "$1" "$TMPDIR/resources"
    elif [[ "$next" = "id" ]]; then
      ID="$1"
    elif [[ "$next" = "version" ]]; then
      VERSION="$1"
    elif [[ "$next" = "copy" ]]; then
      src="$1"
      shift
      dst="$1"
      cp "$src" "$TMPDIR/contents/$dst"
    elif [[ "$next" = "pyver" ]]; then
      echo "$1" > "$TMPDIR/resources/python_version"
    fi
    next=""
  fi
  shift
done

cd "$TMPDIR/contents"

# At this stage we can edit the pkg contents
# and write a preflight to handle other python deps.

cd "$ORIGPWD"

if [[ -z "$PKGONLY" ]]; then
  pkgout="$TMPDIR/pkg/simian.pkg"
else
  pkgout="$OUT"
fi

${PKGMAKER} \
--root "$TMPDIR/contents" \
--id "$ID" \
--out "$pkgout" \
--resources "$TMPDIR/resources" \
--scripts "$TMPDIR/scripts" \
--version "$VERSION"

if [[ -z "$PKGONLY" ]]; then
  hdiutil create -srcfolder "$TMPDIR/pkg" -layout NONE -volname Simian "$OUT"
fi

rm -rf "$TMPDIR"
echo output at "$OUT"
