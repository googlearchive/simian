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

function find_egg() {
  egg=$(find ${module}-*.egg -type f 2>/dev/null)
  if [[ ! -z "${egg}" ]]; then
    echo "${egg}"
  fi
}

function link_module() {
  local module="$1"
  
  local egg=$(find_egg ${module})
  if [[ ! -z "${egg}" ]]; then
    unzip -o "${egg}" -d "${GAE_BUNDLE}" > /dev/null
    rm -rf "${GAE_BUNDLE}/EGG-INFO"
    return
  fi
  
  local path=$(find_module ${module})
  if [[ ! -z "${path}" ]]; then
    rm -f "${GAE_BUNDLE}/${module}"
    ln -s "${path}" "${GAE_BUNDLE}/${module}"
    return
  fi

  echo "ERROR: path not found for ${module}. symlink creation failure."
}

link_module "$1"
