#!/bin/bash
#
# Copyright 2011 Google.  All Rights Reserved.
# Author: jrand@google.com
#
# Translate a tgz into an installable pkg inside a dmg.

set -i
set -e

if [[ $(uname) != "Darwin" ]]; then
  echo $0 must run on OS X
  exit 1
fi

TGZ="$1"
DMG="$2"
ORIGPWD="$PWD"

if [[ "$#" -lt 2 ]]; then
  echo usage: $0 tgz_input_file dmg_output_file [options...]
  echo
  echo options:
  echo -s script_file     add script to package
  echo -r resource_file   add resource file to package
  echo -R resource_dir    add an entire dir into resources
  echo -c src dst         copy a file into the installation tree of package
  echo                    e.g. -c /tmp/foo.py Library/Foo/Bar/foo.py
  echo
  exit 1
fi

shift ; shift

TMPDIR=$(mktemp -d tgz2dmgXXXXXX)
mkdir -p "$TMPDIR/contents"
mkdir -p "$TMPDIR/pkg"
mkdir -p "$TMPDIR/resources"
mkdir -p "$TMPDIR/scripts"

trap "rm -rf \"$TMPDIR\"" EXIT

if [[ "$TGZ" != "" ]]; then
  tar -zxf "$TGZ" -C "$TMPDIR/contents"
fi

# copy optional resources and scripts...
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
    fi
  else
    if [[ "$next" = "script" ]]; then
      cp "$1" "$TMPDIR/scripts"
    elif [[ "$next" = "rsrc" ]]; then
      cp "$1" "$TMPDIR/resources"
    elif [[ "$next" = "rsrcdir" ]]; then
      cp -R "$1" "$TMPDIR/resources"
    elif [[ "$next" = "copy" ]]; then
      src="$1"
      shift
      dst="$1"
      cp "$src" "$TMPDIR/contents/$dst"
    fi
    next=""
  fi
  shift
done

cd "$TMPDIR/contents"

# At this stage we can edit the pkg contents
# and write a preflight to handle other python deps.

cd "$ORIGPWD"

/Developer/usr/bin/packagemaker \
--root "$TMPDIR/contents" \
--id com.google.code.simian \
--out "$TMPDIR/pkg/simian.pkg" \
--resources "$TMPDIR/resources" \
--scripts "$TMPDIR/scripts"

hdiutil create -srcfolder "$TMPDIR/pkg" -layout NONE -volname Simian "$DMG"

rm -rf "$TMPDIR"

echo DMG at "$DMG"
