#!/usr/bin/env python
"""Common constants/etc for Simian project."""

import re


# Track name constants.
STABLE = 'stable'
TESTING = 'testing'
UNSTABLE = 'unstable'
TRACKS = [STABLE, TESTING, UNSTABLE]
DEFAULT_TRACK = STABLE


# Install type constants.
MANAGED_INSTALLS = 'managed_installs'
MANAGED_UNINSTALLS = 'managed_uninstalls'
MANAGED_UPDATES = 'managed_updates'
OPTIONAL_INSTALLS = 'optional_installs'
INSTALL_TYPES = [
    MANAGED_INSTALLS, MANAGED_UNINSTALLS, MANAGED_UPDATES, OPTIONAL_INSTALLS]
DEFAULT_INSTALL_TYPE = MANAGED_INSTALLS

# Manifest Modification Group Names
MANIFEST_MOD_ADMIN_GROUP = 'admin'
MANIFEST_MOD_SUPPORT_GROUP = 'support'
MANIFEST_MOD_SECURITY_GROUP = 'security'
MANIFEST_MOD_GROUPS = [
    MANIFEST_MOD_SUPPORT_GROUP,
    MANIFEST_MOD_SECURITY_GROUP
]

# Munki plist name allowed characters.
PLIST_NAME_ALLOWED_CHAR_REGEX = r'[^\w\-\.]'


def IsValidPlistName(name):
  """Verifies if a given plist name is valid.

  Args:
    name: str plist name.
  Returns:
    Boolean. True if the plist name is valid, False otherwise.
  """
  if not name or re.search(PLIST_NAME_ALLOWED_CHAR_REGEX, name):
    return False
  return True


def SanitizeUUID(uuid):
  """Sanitizes a UUID by lowercasing and removing any prepended "CN=" string.

  Args:
    uuid: str uuid.
  Returns:
    str uuid.
  """
  uuid = uuid.lower()
  if uuid.startswith('cn='):
    uuid = uuid[3:]
  return uuid
