#!/usr/bin/env bash
# Authorship rules for AgentACL.
#
# Contributor mode (default; CI and release preflight): any human may author a
# commit, but nothing may credit an AI tool or a bot: no bot or AI-tool
# authors, no AI Co-authored-by trailers, no "Generated with ..." lines.
#
# Maintainer mode (--maintainer; the local git hooks): additionally, the
# author must be Chaitanya Sistla and there are no co-author trailers at all.
#
#   scripts/check-authorship.sh [--maintainer] <rev-range>   # e.g. origin/main..HEAD
#   scripts/check-authorship.sh [--maintainer] --all         # whole history
#   scripts/check-authorship.sh [--maintainer] --message F   # a commit message file (hook)
set -euo pipefail

MAINTAINER_NAME="Chaitanya Sistla"
# Addresses the maintainer commits from (GitHub's noreply form included).
MAINTAINER_EMAILS=("sistlachaitanya2@gmail.com" "chaitanya@openobserve.ai")
MAINTAINER_EMAIL_RE='^[0-9]+\+chaitanya-sistla@users\.noreply\.github\.com$'

# Author/committer identities of bots and AI coding tools (matched against
# the email, so a person named e.g. Claude is fine).
BOT_AUTHOR_RE='\[bot\]|noreply@anthropic\.com|noreply@openai\.com|copilot@github\.com|@cursor\.(com|sh)|devin-ai-integration|noreply@aider|@codeium\.com'
# Co-author trailers that credit an AI tool or a bot (names and emails).
AI_RE='\[bot\]|noreply@anthropic\.com|claude|anthropic|copilot|openai|chatgpt|gpt-[0-9]|codex|gemini|cursor(agent)?@|devin|aider|codeium|windsurf|tabnine|amazon ?q|sweep|jules'
# Lines that credit a tool for the change.
GENERATED_RE='generated (with|by) \[?(claude|chatgpt|copilot|cursor|codex|gemini|aider|devin|windsurf|codeium|an? ai)|🤖'

mode=contributor
if [[ "${1:-}" == "--maintainer" ]]; then
  mode=maintainer
  shift
fi

fail=0
# $1: message text, $2: label for errors. Returns 0 if the message is bad.
bad_message() {
  local msg="$1" label="$2" co
  if printf '%s' "$msg" | grep -qiE "$GENERATED_RE"; then
    echo "::error::$label: has a tool-attribution line (e.g. 'Generated with ...'); remove it"
    return 0
  fi
  co=$(printf '%s\n' "$msg" | grep -iE '^[[:space:]]*co-authored-by:' || true)
  if [[ -n "$co" ]]; then
    if [[ $mode == maintainer ]]; then
      echo "::error::$label: has a Co-authored-by trailer (the maintainer's commits have one author)"
      return 0
    fi
    if printf '%s' "$co" | grep -qiE "$AI_RE"; then
      echo "::error::$label: credits an AI tool or bot as co-author; remove that trailer"
      return 0
    fi
  fi
  if [[ $mode == maintainer ]] && printf '%s\n' "$msg" | grep -iE '^signed-off-by:' | grep -qviE "^signed-off-by: $MAINTAINER_NAME"; then
    echo "::error::$label: Signed-off-by someone other than $MAINTAINER_NAME"
    return 0
  fi
  return 1
}

maintainer_email() {
  local e="$1" a
  for a in "${MAINTAINER_EMAILS[@]}"; do [[ "$e" == "$a" ]] && return 0; done
  [[ "$e" =~ $MAINTAINER_EMAIL_RE ]]
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
  echo "usage: $0 [--maintainer] <rev-range> | --all | --message <file>" >&2
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
  if printf '%s <%s>' "$an" "$ae" | grep -qiE "$BOT_AUTHOR_RE"; then
    echo "::error::$short: authored by a bot or AI tool ('$an <$ae>'); commits must be authored by a person"
    fail=1
  fi
  # GitHub commits merges made on github.com itself (noreply@github.com).
  if [[ "$ce" != "noreply@github.com" ]] && printf '%s <%s>' "$cn" "$ce" | grep -qiE "$BOT_AUTHOR_RE"; then
    echo "::error::$short: committed by a bot or AI tool ('$cn <$ce>')"
    fail=1
  fi
  if [[ $mode == maintainer ]]; then
    if [[ "$an" != "$MAINTAINER_NAME" ]] || ! maintainer_email "$ae"; then
      echo "::error::$short: author is '$an <$ae>'; the maintainer's commits are authored by $MAINTAINER_NAME"
      fail=1
    fi
  fi
  if bad_message "$body" "$short"; then fail=1; fi
done

if [[ $fail -ne 0 ]]; then
  echo "Authorship check failed. Remove the flagged trailers/lines, or re-author with: git rebase -i <base> and 'git commit --amend --reset-author'." >&2
  exit 1
fi
if [[ $mode == maintainer ]]; then
  echo "Authorship OK: $count commit(s), all by $MAINTAINER_NAME, no co-author or tool-attribution trailers."
else
  echo "Authorship OK: $count commit(s), all by people, no AI or bot attribution."
fi
