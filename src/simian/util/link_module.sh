#!/bin/bash
#
# Copyright 2011 Google Inc. All Rights Reserved.

set -e

GAE_BUNDLE=gae_bundle/

function find_module() {
  VE/bin/python <<EOF
import imp
try:
 print imp.find_module('$1')[1]
except ImportError:
 pass
EOF
}

function find_egg_file() {
  egg=$(find .eggs -type f -maxdepth 1 -name ${module}-*.egg 2>/dev/null)
  if [[ ! -z "${egg}" ]]; then
    echo "${egg}"
  fi
}

function find_egg_dir() {
  egg=$(find .eggs -type d -name ${module}-*.egg 2>/dev/null)
  if [[ ! -z "${egg}" ]]; then
    find "${egg}" -type d -maxdepth 1 -mindepth 1 \! -name EGG-INFO
  fi
}

function link_module() {
  local module="$1"

  local egg=$(find_egg_file ${module})
  if [[ ! -z "${egg}" ]]; then
    unzip -o "${egg}" -d "${GAE_BUNDLE}" > /dev/null
    rm -rf "${GAE_BUNDLE}/EGG-INFO"
    return
  fi

  local egg=$(find_egg_dir ${module})
  if [[ ! -z "${egg}" ]]; then
    cp -fR "${egg}" "${GAE_BUNDLE}"
    return
  fi

  local path=$(find_module ${module})
  if [[ ! -z "${path}" ]]; then
    rm -f "${GAE_BUNDLE}/${module}"
    ln -s "${path}" "${GAE_BUNDLE}/${module}"
    return
  fi

  echo "ERROR: path not found for ${module}. symlink creation failure."
  exit 1
}

link_module "$1"
