#!/bin/bash
#
# Copyright 2011 Google Inc. All Rights Reserved.

GAE_BUNDLE=gae_bundle/


function find_module() {
  python <<EOF
import imp
try:
 print imp.find_module('$1')[1]
except ImportError:
 pass
EOF
}


function link_module() {
  local module="$1"
  local path=`find_module $module`
  if [ ! -z "$path" ]; then
    rm -f "$GAE_BUNDLE/$module"
    ln -s "$path" "$GAE_BUNDLE/$module"
  else
    echo ERROR: path not found for $module. symlink creation failure.
  fi
}

link_module $1
