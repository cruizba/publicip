#!/usr/bin/env bash
# Release description, and the check that it matches what shipped.
#
# CHANGELOG.md is the source of truth for what a release means to its users. Commit
# subjects are written for the person making the change, so turning them into release
# notes produces entries like "docs: bring AGENTS.md in line" in a patch release that a
# user reads looking for "do I have to do anything?". Both descriptions of one release
# is also how they start disagreeing.
#
# This script therefore has three modes:
#
#   section <version>          print the release body, from CHANGELOG.md
#   verify <version> [<from> <to>]
#                              drift check between the commits in a range and the
#                              changelog section for that version
#   commits [<from> <to>]      the old behaviour: a listing derived from commit
#                              subjects. Debug aid and emergency fallback, not what a
#                              release should publish.
#
#   without arguments: verify HEAD's version against the previous tag.
#
# In CI, `verify-pr <base>` runs the checks that make sense before a version exists.
#
# ABSOLUTE_LINKS=0 prints the section with repository-relative links untouched, which
# is what a reader outside a repository context (or a test) wants.

set -euo pipefail

CHANGELOG="${CHANGELOG_FILE:-CHANGELOG.md}"

die() { printf 'release-notes: %s\n' "$*" >&2; exit 1; }

[ -f "$CHANGELOG" ] || die "$CHANGELOG not found (set CHANGELOG_FILE to override)"

# normalise_version accepts 2.0.0 and v2.0.0 so headings can be written either way.
normalise_version() { printf '%s' "$1" | sed -E 's/^v//'; }

# section_start prints the line number of a version's heading, or nothing.
section_start() {
  local v
  v="$(normalise_version "$1")"
  grep -n -E "^## +\[v?${v//./\\.}\]" "$CHANGELOG" | head -1 | cut -d: -f1 || true
}

# extract_section prints a version's changelog section, heading excluded.
extract_section() {
  local start v
  start="$(section_start "$1")"
  [ -n "$start" ] || return 1
  v="$(normalise_version "$1")"
  awk -v start="$start" '
    NR < start { next }
    NR == start { next }
    /^## \[/ || /^## \[v?[0-9]/ { exit }
    { print }
  ' "$CHANGELOG" | sed -E 's/[[:space:]]+$//' | awk '
    BEGIN { blank = 0; out = 0 }
    /^$/ { blank++; next }
    {
      if (out && blank > 1) printf "\n"; else if (out && blank == 1) printf "\n"
      blank = 0; out = 1
      print          # indentation preserved: nested lists and code blocks matter
    }
  '
}

# absolute_links rewrites repository-relative links, which resolve fine inside the
# repo but not in a GitHub release body, where the page is not in the tree.
absolute_links() {
  local repo ref
  # `|| true`: without it a repository with no origin remote aborts here under
  # set -e / pipefail, inside a command substitution, with no message to read.
  local from_remote=""
  if [ -z "${GITHUB_REPOSITORY:-}" ]; then
    from_remote="$(git remote get-url origin 2>/dev/null |
      sed -E -e 's#^(https?://|ssh://|git@)##' -e 's#\.git/?$##' -e 's#/$##' -e 's#^[^/:]*[:/]##' || true)"
  fi
  repo="${GITHUB_REPOSITORY:-$from_remote}"
  ref="${RELEASE_REF:-$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo HEAD)}"
  [ -n "$repo" ] || die "cannot work out owner/repo for link rewriting; set GITHUB_REPOSITORY"

  awk -v base="$repo" -v ref="$ref" '
    {
      out = ""
      rest = $0
      while ((i = index(rest, "](")) > 0) {
        out = out substr(rest, 1, i + 1)
        rest = substr(rest, i + 2)
        j = index(rest, ")")
        if (j == 0) { out = out rest; rest = ""; break }
        target = substr(rest, 1, j - 1)
        if (target !~ /^https?:\/\// && substr(target, 1, 1) != "/" && substr(target, 1, 1) != "#") {
          target = "https://github.com/" base "/blob/" ref "/" target
        }
        out = out target
        rest = substr(rest, j)
      }
      print out rest
    }
  '
}

# commit_subjects prints "<subject>\t<sha>" for the range, oldest first, without merges
# and without this job's own version bump.
commit_subjects() {
  local from="$1" to="$2"
  git log --no-merges --reverse --format='%s%x09%h' "${from}..${to}" |
    while IFS=$'\t' read -r subject sha; do
      case "$subject" in
        "chore: bump version to "*) continue ;;
      esac
      printf '%s\t%s\n' "$subject" "$sha"
    done
}

type_of() {
  local subject="$1"
  case "$subject" in
    fix*!*)   echo "breaking" ;;
    feat*!*)  echo "breaking" ;;
    chore*!*) echo "breaking" ;;
    refactor*!*) echo "breaking" ;;
    docs*)    echo "docs" ;;
    fix*)     echo "fix" ;;
    feat*)    echo "feat" ;;
    test*)    echo "test" ;;
    ci*)      echo "ci" ;;
    build*)   echo "build" ;;
    chore*)   echo "chore" ;;
    perf*)    echo "perf" ;;
    revert*)  echo "revert" ;;
    refactor*) echo "refactor" ;;
    *)        echo "other" ;;
  esac
}

# type_heading maps a commit type to the CHANGELOG section it must appear under.
type_heading() {
  case "$1" in
    breaking) echo "Removed" ;;      # also satisfied by Changed / Breaking changes
    fix)      echo "Fixed" ;;
    feat)     echo "Added" ;;
    perf)     echo "Performance" ;;
    test)     echo "Tests" ;;
    ci|build|chore) echo "CI and tooling" ;;
    docs)     echo "Documentation" ;;
    refactor) echo "Changed" ;;
    revert)   echo "Changed" ;;
    other)    echo "Other changes" ;;
  esac
}

have_heading() {
  local body="$1" heading="$2"
  printf '%s\n' "$body" | grep -qE "^### +${heading}( |$)" && return 0
  case "$heading" in
    Removed) printf '%s\n' "$body" | grep -qE "^### +(Breaking changes|Changed|Removed)( |$)" ;;
    *) return 1 ;;
  esac
}

usage() {
  sed -n '3,28p' "$0" | sed 's/^# \{0,1\}//'
}

mode="${1:-}"
case "$mode" in
  section)
    [ $# -ge 2 ] || usage >&2; shift
    body="$(extract_section "$1")" || die "no '## [$1]' section in $CHANGELOG"
    [ -n "$body" ] || die "'## [$1]' section is empty in $CHANGELOG"
    if [ "${ABSOLUTE_LINKS:-1}" = "1" ]; then
      printf '%s\n' "$body" | absolute_links
    else
      printf '%s\n' "$body"
    fi
    ;;

  commits)
    shift || true
    from="${1:-}"; to="${2:-HEAD}"
    if [ -z "$from" ]; then
      from="$(git describe --tags --abbrev=0 "$to" 2>/dev/null || true)"
    fi
    if [ -n "$from" ]; then
      rows="$(commit_subjects "$from" "$to")"
    else
      rows="$(git log --no-merges --reverse --format='%s%x09%h' "$to")"
    fi
    [ -n "$rows" ] || die "no commits in the release range"
    printf '%s\n' "$rows" | while IFS=$'\t' read -r subject sha; do
      printf -- '- %s (%s)\n' "$subject" "$sha"
    done
    ;;

  verify)
    shift || true
    [ $# -ge 1 ] || usage >&2
    version="$1"
    from="${2:-$(git describe --tags --abbrev=0 "v$(normalise_version "$version")^" 2>/dev/null ||
                 git describe --tags --abbrev=0 HEAD^ 2>/dev/null || true)}"
    to="${3:-HEAD}"
    [ -n "$from" ] || die "cannot find a previous tag to verify against"

    body="$(extract_section "$version")" || die "$CHANGELOG has no section for $version"
    [ -n "$body" ] || die "$CHANGELOG section for $version is empty"

    status=0
    declare -A seen_types=()
    while IFS=$'\t' read -r subject sha; do
      t="$(type_of "$subject")"
      if [ "$t" = other ]; then
        printf 'release-notes: commit %s (%s) has no recognised type prefix; it would be dropped from every description\n' "$sha" "$subject" >&2
        status=1
      fi
      seen_types["$t"]=1
      # A cited sha must exist in the range: catches a changelog edited for another
      # branch or a commit that got rebased away.
      case "$body" in
        *"($sha)"*) : ;;
      esac
    done < <(commit_subjects "$from" "$to")

    # Only the types a user is affected by need a heading. Requiring one for ci:,
    # chore: and test: would be exactly the maintainer noise this script exists to
    # keep out of a release.
    for t in "${!seen_types[@]}"; do
      case "$t" in fix|feat|breaking|perf) ;; *) continue ;; esac
      heading="$(type_heading "$t")"
      if ! have_heading "$body" "$heading"; then
        printf 'release-notes: the range has %s commits but the %s section has no "### %s" heading\n' \
          "$t" "$version" "$heading" >&2
        status=1
      fi
    done

    # Shas the changelog cites must belong to this range.
    for cited in $(printf '%s\n' "$body" | grep -oE '\((0|[a-f0-9]){7,40}\)' | tr -d '()' | sort -u); do
      if ! git rev-parse --verify -q "${cited}^{commit}" >/dev/null; then
        printf 'release-notes: %s cites %s, which is not a commit in this repository\n' "$version" "$cited" >&2
        status=1
        continue
      fi
      if ! git merge-base --is-ancestor "$cited" "$to" 2>/dev/null ||
         git merge-base --is-ancestor "$cited" "$from" 2>/dev/null; then
        printf 'release-notes: %s cites %s, which is outside %s..%s\n' "$version" "$cited" "$from" "$to" >&2
        status=1
      fi
    done

    if [ "$status" -eq 0 ]; then
      printf 'release-notes: %s matches %s..%s (%s commit types verified)\n' \
        "$version" "$from" "$to" "${#seen_types[@]}" >&2
    fi
    exit $status
    ;;

  verify-pr)
    shift || true
    base="${1:-origin/main}"
    status=0
    breaking=0
    while IFS=$'\t' read -r subject _sha; do
      t="$(type_of "$subject")"
      [ "$t" = breaking ] && breaking=1
      if [ "$t" = other ]; then
        printf 'release-notes: commit subject "%s" has no recognised type prefix\n' "$subject" >&2
        status=1
      fi
    done < <(git log --no-merges --format='%s%x09%h' "${base}..HEAD")

    if [ "$breaking" -eq 1 ] &&
       ! git diff --name-only "${base}...HEAD" -- "$CHANGELOG" | grep -q .; then
      printf 'release-notes: this change breaks the API but does not touch %s\n' "$CHANGELOG" >&2
      status=1
    fi

    [ "$status" -eq 0 ] && printf 'release-notes: changelog looks consistent with the commits\n' >&2
    exit $status
    ;;

  ""|-h|--help|help)
    usage
    ;;

  *)
    die "unknown mode '$mode'"
    ;;
esac
