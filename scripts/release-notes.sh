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

# Group by Conventional Commit type. Several types share one section ("ci", "build",
# "chore" and "perf" all land in CI and tooling), and a subject that does not parse as
# "type(scope)!: description" still gets reported under Other changes - silently
# dropping commits is how a changelog starts lying.

declare -A bucket=()
declare -a order=("Breaking changes" "Fixed" "Added" "Changed" "Performance" "Tests" "CI and tooling" "Documentation" "Other changes")

type_to_section() {
  case "$1" in
    breaking)        echo "Breaking changes" ;;
    fix)             echo "Fixed" ;;
    feat)            echo "Added" ;;
    refactor|revert) echo "Changed" ;;
    perf)            echo "Performance" ;;
    test)            echo "Tests" ;;
    ci|build|chore)  echo "CI and tooling" ;;
    docs)            echo "Documentation" ;;
    *)               echo "Other changes" ;;
  esac
}

# classify <subject> -> "<section>$TAB<description>"
classify() {
  local subject="$1" type desc
  # The pattern lives in a variable: inside [[ =~ ]] an inline regex with parentheses is
  # parsed by the shell rather than the regex engine.
  local pattern='^([a-zA-Z]+)(\(([^)]*)\))?(!)?:[[:space:]]*(.*)$'
  if [[ "$subject" =~ $pattern ]]; then
    type="$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
    desc="${BASH_REMATCH[5]}"
    [ -n "${BASH_REMATCH[3]}" ] && desc="**${BASH_REMATCH[3]}**: ${desc}"
    [ -n "${BASH_REMATCH[4]}" ] && type="breaking"
  else
    type="other"
    desc="$subject"
  fi
  printf '%s\t%s' "$(type_to_section "$type")" "$desc"
}

listed=0
for line in "${subjects[@]}"; do
  subject="${line%%$'\t'*}"
  sha="${line##*$'\t'}"
  classified="$(classify "$subject")"
  section="${classified%%$'\t'*}"
  desc="${classified#*$'\t'}"
  bucket["$section"]+="- ${desc} (${sha})"$'\n'
  listed=$((listed + 1))
done

for section in "${order[@]}"; do
  if [ -n "${bucket[$section]:-}" ]; then
    printf '\n## %s\n\n%s' "$section" "${bucket[$section]}"
  fi
done

# Self-check: every commit in the range must have landed in a section.
if [ "$listed" -ne "${#subjects[@]}" ]; then
  printf 'release-notes: %d of %d commits were not classified\n'     "$(( ${#subjects[@]} - listed ))" "${#subjects[@]}" >&2
  exit 1
fi

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
