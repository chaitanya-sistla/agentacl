#!/usr/bin/env bash
# Every commit in AgentACL is authored by Chaitanya Sistla, with no co-author
# or tool-attribution trailers. Used by CI, the release workflow and the
# local commit-msg hook.
#
#   scripts/check-authorship.sh <rev-range>   # e.g. origin/main..HEAD
#   scripts/check-authorship.sh --all         # whole history
#   scripts/check-authorship.sh --message F   # a commit message file (hook)
set -euo pipefail

AUTHOR_NAME="Chaitanya Sistla"
# Addresses the author commits from (GitHub's noreply form included).
ALLOWED_EMAILS=("sistlachaitanya2@gmail.com" "chaitanya@openobserve.ai")
ALLOWED_EMAIL_RE='^[0-9]+\+chaitanya-sistla@users\.noreply\.github\.com$'

fail=0
bad_message() {
  # $1: message text, $2: label for errors
  local msg_lc
  msg_lc=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  if printf '%s' "$msg_lc" | grep -qiE '(^|[[:space:]])co-authored-by:'; then
    echo "::error::$2: has a Co-authored-by trailer (commits are authored by $AUTHOR_NAME only)"
    return 0
  fi
  if printf '%s' "$msg_lc" | grep -qiE 'generated with \[?claude|noreply@anthropic\.com|🤖 generated'; then
    echo "::error::$2: has a tool-attribution line; remove it"
    return 0
  fi
  if printf '%s' "$msg_lc" | grep -iE '^signed-off-by:' | grep -qviE "^signed-off-by: $AUTHOR_NAME"; then
    echo "::error::$2: Signed-off-by someone other than $AUTHOR_NAME"
    return 0
  fi
  return 1
}

email_ok() {
  local e="$1" a
  for a in "${ALLOWED_EMAILS[@]}"; do [[ "$e" == "$a" ]] && return 0; done
  [[ "$e" =~ $ALLOWED_EMAIL_RE ]]
}

if [[ "${1:-}" == "--message" ]]; then
  if bad_message "$(grep -v '^#' "$2")" "commit message"; then exit 1; fi
  exit 0
fi

if [[ "${1:-}" == "--all" ]]; then
  range=(HEAD)
elif [[ -n "${1:-}" ]]; then
  range=("$1")
else
  echo "usage: $0 <rev-range> | --all | --message <file>" >&2
  exit 2
fi

count=0
for sha in $(git rev-list "${range[@]}"); do
  count=$((count + 1))
  short=${sha:0:9}
  an=$(git log -1 --format=%an "$sha")
  ae=$(git log -1 --format=%ae "$sha")
  cn=$(git log -1 --format=%cn "$sha")
  ce=$(git log -1 --format=%ce "$sha")
  body=$(git log -1 --format=%B "$sha")
  if [[ "$an" != "$AUTHOR_NAME" ]] || ! email_ok "$ae"; then
    echo "::error::$short: author is '$an <$ae>'; only $AUTHOR_NAME may author commits"
    fail=1
  fi
  # Merges made on github.com are committed by GitHub itself; anything else must be the author.
  if [[ "$cn" != "$AUTHOR_NAME" && "$ce" != "noreply@github.com" ]]; then
    echo "::error::$short: committer is '$cn <$ce>'"
    fail=1
  fi
  if bad_message "$body" "$short"; then fail=1; fi
done

if [[ $fail -ne 0 ]]; then
  echo "Authorship check failed. Fix with: git rebase -i <base> and 'git commit --amend --reset-author' (set user.name/user.email first)." >&2
  exit 1
fi
echo "Authorship OK: $count commit(s), all by $AUTHOR_NAME, no co-author or tool-attribution trailers."
