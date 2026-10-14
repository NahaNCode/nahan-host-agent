#!/bin/sh
set -eu
blocked=$(git ls-files | awk '/(^|\/)(agent|core)\.key$|(^|\/)\.env$|(^|\/)runtime\/|^deploy\/private-control\/(apache|nginx)\.conf$|^deploy\/control\//')
if [ -n "$blocked" ]; then
  printf '%s\n' 'Public repository contains operational files:' "$blocked" >&2
  exit 1
fi
