#!/usr/bin/env bash
# Build release notes from the commits in a release range.
#
# `gh release create --generate-notes` derives its body from merged pull requests, so
# in a repository where changes land as direct commits to main it describes almost
# nothing: the real work is invisible and only Dependabot's PRs show up. This script
# reads the commit subjects between two refs instead, grouped by Conventional Commit
# type, so the notes match what the tag actually contains.
#
# Usage: release-notes.sh [<from> <to>]
#   without arguments it uses the previous tag and HEAD.

set -euo pipefail

if [ "$#" -ge 2 ]; then
  from="$1"
  to="$2"
else
  to="${1:-HEAD}"
  from="$(git describe --tags --abbrev=0 "$to" 2>/dev/null || true)"
fi

if [ -z "$from" ]; then
  range=("$to")
  from_label=""
else
  range=("$from".."$to")
  from_label="$from"
fi

# Only non-merge commits: a merge subject says nothing about the change. The release
# job's own version bump is dropped too, since it echoes the tag being announced.
mapfile -t all < <(git log --no-merges --reverse --format='%s%x09%h' "${range[@]}")
subjects=()
for line in "${all[@]}"; do
  case "${line%%$'\t'*}" in
    "chore: bump version to "*) continue;;
  esac
  subjects+=("$line")
done

if [ "${#subjects[@]}" -eq 0 ]; then
  echo "No commits in the release range." >&2
  exit 1
fi

section() {
  local title="$1"
  shift
  local printed=0
  for line in "${subjects[@]}"; do
    local subject="${line%%$'\t'*}"
    local sha="${line##*$'\t'}"
    for prefix in "$@"; do
      case "$subject" in
        "$prefix"*)
          [ "$printed" -eq 0 ] && printf '\n## %s\n\n' "$title"
          printed=1
          # Drop the conventional-commit prefix; the section header already says it.
          desc="${subject#"$prefix"}"
          desc="${desc#:}"
          desc="${desc# }"
          printf -- '- %s (%s)\n' "$desc" "$sha"
          ;;
      esac
    done
  done
}

# Breaking changes first: the "!" marker goes on the type, so match it before the
# plain types below and exclude it from them.
breaking=()
for line in "${subjects[@]}"; do
  s="${line%%$'\t'*}"
  case "$s" in *'!:'*) breaking+=("$s");; esac
done

if [ "${#breaking[@]}" -gt 0 ]; then
  printf '\n## Breaking changes\n\n'
  for line in "${subjects[@]}"; do
    subject="${line%%$'\t'*}"
    sha="${line##*$'\t'}"
    case "$subject" in
      *'!:'*) printf -- '- %s (%s)\n' "${subject#*:}" "$sha";;
    esac
  done
fi

section "Fixed" "fix:"
section "Added" "feat:"
section "Changed" "refactor:"
section "Tests" "test:"
section "CI and tooling" "ci:" "chore:" "build:"
section "Documentation" "docs:"

repo="${GITHUB_REPOSITORY:-}"
if [ -z "$repo" ]; then
  # Fall back to the origin remote, which may be https, ssh:// or scp-style, with or
  # without a trailing slash and .git suffix. Each step needs its own command: bash
  # ends a command substitution's command at a newline, so a pipeline cannot start on
  # the following line.
  url=$(git remote get-url origin 2>/dev/null || true)
  repo=$(printf '%s' "$url" | sed -E -e 's#^(https?://|ssh://|git@)##' -e 's#\.git/?$##' -e 's#/$##' -e 's#^[^/:]*[:/]##')
fi
target="${TARGET_REF:-$(git rev-parse HEAD)}"
if [ -n "$from_label" ]; then
  printf '\n**Full changelog:** https://github.com/%s/compare/%s...%s\n' \
    "$repo" "$from_label" "${RELEASE_TAG:-$target}"
fi
