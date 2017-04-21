#!/bin/bash
#
# Copyright 2010 Google Inc.  All Rights Reserved.
#
# Creates a Google App Engine deployable bundle of Simian code.

set -e

SIMIAN_ROOT=$1
BUNDLE_ROOT=$SIMIAN_ROOT/gae_bundle/
SIMIAN_REL_PATH=../src/simian/

# Create Google App Engine bundle directory.
rm -rf $BUNDLE_ROOT
mkdir -p $BUNDLE_ROOT/simian
touch $BUNDLE_ROOT/__init__.py
touch $BUNDLE_ROOT/simian/__init__.py

# Symlink simian namespace.
ln -s ../$SIMIAN_REL_PATH/auth $BUNDLE_ROOT/simian/auth
ln -s ../$SIMIAN_REL_PATH/mac $BUNDLE_ROOT/simian/mac
ln -s ../$SIMIAN_REL_PATH/settings.py $BUNDLE_ROOT/simian/settings.py

# Symlink gae_resources.
ln -s $SIMIAN_ROOT/gae_resources/client_resources $BUNDLE_ROOT/client_resources

# Symlink necessary files at the root of the bundle.
ln -s $SIMIAN_REL_PATH/mac/app.yaml $BUNDLE_ROOT/app.yaml
ln -s $SIMIAN_REL_PATH/mac/index.yaml $BUNDLE_ROOT/index.yaml
ln -s $SIMIAN_REL_PATH/mac/queue.yaml $BUNDLE_ROOT/queue.yaml
ln -s $SIMIAN_REL_PATH/mac/cron.yaml $BUNDLE_ROOT/cron.yaml
