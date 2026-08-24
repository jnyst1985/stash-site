#!/usr/bin/env bash
#
# verify-shares.sh - contract check for the /api/* shares routes in worker.js.
#
# There is no JS test infrastructure in this repo by decision (spec §8), so this
# script IS the route table's test: every status it asserts is pinned in
# link-saver docs/superpowers/specs/2026-08-24-stash-short-share-links-design.md §4.
# It is also the release checklist's verify step.
#
# Usage:
#   npx wrangler dev --persist-to /tmp/stash-kv     # terminal 1, simulated KV
#   scripts/verify-shares.sh http://localhost:8787
#
# --persist-to is not optional in practice: `assets.directory` is "." (the repo
# root), so wrangler's own writes under ./.wrangler land inside the directory it
# watches and it reloads itself several times a second, forever. Pointing its
# state anywhere outside the repo stops that dead. Pre-existing, and unrelated to
# the Worker script: an assets-only config on this layout loops the same way.
#
# Kill switch (503) needs the Worker started with the switch on, so it is a
# separate run against a separate dev server:
#   npx wrangler dev --var SHARES_DISABLED:1 --port 8788 --persist-to /tmp/stash-kill
#   STASH_EXPECT_DISABLED=1 scripts/verify-shares.sh http://localhost:8788
#
# Wrangler must be new enough for this repo's compatibility_date - 4.100 ships a
# workerd that refuses it ("newest date supported by this server binary is
# ..."). `npx wrangler@latest dev` is the fix.
# In that mode the script asserts ONLY that a well-formed create returns 503.
#
# Against production the same commands work with BASE_URL=https://getstash.link,
# but note that a real run stores real shares (7-day TTL) and burns two of the
# per-IP creates-per-hour budget.

set -uo pipefail

BASE="${1:-}"
if [ -z "$BASE" ]; then
  echo "usage: $0 <BASE_URL>   e.g. $0 http://localhost:8787" >&2
  exit 2
fi
BASE="${BASE%/}"

WORK="${TMPDIR:-/tmp}/stash-verify-$$"
mkdir -p "$WORK"
cleanup() {
  # House rule: never rm. trash if it exists, otherwise leave the scratch files
  # and say where they are.
  if command -v trash >/dev/null 2>&1; then
    trash "$WORK" >/dev/null 2>&1 || echo "note: scratch files left in $WORK"
  else
    echo "note: scratch files left in $WORK"
  fi
}
trap cleanup EXIT

PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$1"; }

expect() { # expect <label> <expected> <actual>
  if [ "$2" = "$3" ]; then ok "$1 -> $3"; else bad "$1 -> expected $2, got $3"; fi
}

new_id() { LC_ALL=C head -c 16 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n'; }

create() { # create <id> <payload-file> [extra curl args...]
  local id="$1" payload="$2"
  shift 2
  curl -s -o "$WORK/create.json" -w '%{http_code}' \
    -X POST "$BASE/api/share" \
    -H "Content-Type: application/vnd.stash-share.v1" \
    -H "X-Stash-Share-Id: $id" \
    --data-binary "@$payload" "$@"
}

echo "shares API contract check against $BASE"

# --- kill switch mode: one assertion, nothing else ---------------------------
if [ "${STASH_EXPECT_DISABLED:-0}" = "1" ]; then
  echo
  echo "kill switch (SHARES_DISABLED=1)"
  LC_ALL=C head -c 256 /dev/urandom > "$WORK/kill.bin"
  expect "create while disabled" 503 "$(create "$(new_id)" "$WORK/kill.bin")"
  echo
  echo "passed: $PASS   failed: $FAIL"
  [ "$FAIL" -eq 0 ] || exit 1
  exit 0
fi

ID="$(new_id)"
LC_ALL=C head -c 512 /dev/urandom > "$WORK/payload.bin"

# --- create ------------------------------------------------------------------
echo
echo "create"
expect "POST /api/share" 201 "$(create "$ID" "$WORK/payload.bin")"

TOKEN="$(sed -n 's/.*"deletionToken":"\([^"]*\)".*/\1/p' "$WORK/create.json")"
if printf '%s' "$TOKEN" | grep -Eq '^[A-Za-z0-9_-]{22}$'; then
  ok "deletionToken is 22 base64url chars"
else
  bad "deletionToken shape: got '${TOKEN}'"
fi

# --- read back ---------------------------------------------------------------
echo
echo "read"
STATUS="$(curl -s -D "$WORK/read.h" -o "$WORK/readback.bin" -w '%{http_code}' "$BASE/api/share/$ID")"
expect "GET /api/share/<id>" 200 "$STATUS"

if cmp -s "$WORK/payload.bin" "$WORK/readback.bin"; then
  ok "bytes round-trip identical"
else
  bad "bytes differ between upload and read-back"
fi

if grep -qi '^content-type: application/octet-stream' "$WORK/read.h"; then
  ok "Content-Type: application/octet-stream"
else
  bad "Content-Type is not application/octet-stream"
fi

if grep -qi '^cache-control: no-store' "$WORK/read.h"; then
  ok "Cache-Control: no-store"
else
  bad "Cache-Control is not no-store"
fi

# --- rejected creates --------------------------------------------------------
echo
echo "rejected creates"
expect "bad id shape (21 chars)" 400 "$(create "tooshortnotavalididxx" "$WORK/payload.bin")"
expect "bad id shape (illegal char)" 400 "$(create 'AAAAAAAAAAAAAAAAAAAA!!' "$WORK/payload.bin")"

expect "wrong Content-Type" 400 "$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/api/share" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Stash-Share-Id: $(new_id)" \
  --data-binary "@$WORK/payload.bin")"

expect "empty body" 400 "$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/api/share" \
  -H "Content-Type: application/vnd.stash-share.v1" \
  -H "X-Stash-Share-Id: $(new_id)" \
  --data-binary '')"

# 65,536 is the cap and must be accepted; one byte more must not.
LC_ALL=C head -c 65536 /dev/urandom > "$WORK/at-cap.bin"
LC_ALL=C head -c 65537 /dev/urandom > "$WORK/over-cap.bin"
expect "body exactly at the 65,536 cap" 201 "$(create "$(new_id)" "$WORK/at-cap.bin")"
expect "body one byte over the cap" 413 "$(create "$(new_id)" "$WORK/over-cap.bin")"

# Same oversize body without a Content-Length: the bounded read has to catch it.
expect "oversize as chunked (no Content-Length)" 413 \
  "$(create "$(new_id)" "$WORK/over-cap.bin" -H 'Transfer-Encoding: chunked')"

# Different bytes on purpose: a 409 that still overwrote the stored envelope
# would let anyone who learns an id replace what the recipient opens.
LC_ALL=C head -c 512 /dev/urandom > "$WORK/impostor.bin"
expect "duplicate id" 409 "$(create "$ID" "$WORK/impostor.bin")"

curl -s -o "$WORK/after-dup.bin" "$BASE/api/share/$ID"
if cmp -s "$WORK/payload.bin" "$WORK/after-dup.bin"; then
  ok "rejected duplicate left the stored envelope untouched"
else
  bad "a duplicate create overwrote the stored envelope"
fi

# --- delete ------------------------------------------------------------------
echo
echo "delete"
expect "wrong deletion token" 403 "$(curl -s -o /dev/null -w '%{http_code}' \
  -X DELETE "$BASE/api/share/$ID" -H "X-Stash-Delete-Token: $(new_id)")"

expect "missing deletion token" 403 "$(curl -s -o /dev/null -w '%{http_code}' \
  -X DELETE "$BASE/api/share/$ID")"

expect "unknown id" 403 "$(curl -s -o /dev/null -w '%{http_code}' \
  -X DELETE "$BASE/api/share/$(new_id)" -H "X-Stash-Delete-Token: $TOKEN")"

expect "right deletion token" 204 "$(curl -s -o /dev/null -w '%{http_code}' \
  -X DELETE "$BASE/api/share/$ID" -H "X-Stash-Delete-Token: $TOKEN")"

expect "read after delete" 404 "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/share/$ID")"
expect "read of an id that never existed" 404 \
  "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/share/$(new_id)")"

# --- report ------------------------------------------------------------------
echo
echo "report (202 whatever happens - never an existence oracle)"
expect "report with note" 202 "$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/api/report" -H 'Content-Type: application/json' \
  -d "{\"id\":\"$ID\",\"note\":\"verify-shares.sh\"}")"

expect "report for an unknown id" 202 "$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/api/report" -H 'Content-Type: application/json' \
  -d "{\"id\":\"$(new_id)\"}")"

expect "report with malformed JSON" 202 "$(curl -s -o /dev/null -w '%{http_code}' \
  -X POST "$BASE/api/report" -H 'Content-Type: application/json' -d 'not json')"

# --- the site itself still serves --------------------------------------------
echo
echo "assets passthrough"
expect "GET /" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/")"
expect "GET /privacy/" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/privacy/")"
# -L on purpose: /s 307s to /s/ (the asset router's trailing-slash handling,
# unchanged by the Worker). Browsers carry the fragment across that redirect,
# which is why legacy /s#<fragment> links still open.
expect "GET /s (legacy fragment viewer)" 200 "$(curl -sL -o /dev/null -w '%{http_code}' "$BASE/s")"
expect "GET /s/<id> (short-link viewer document)" 200 \
  "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/s/$(new_id)")"

echo
echo "passed: $PASS   failed: $FAIL"
if [ "$FAIL" -ne 0 ]; then
  echo
  echo "note: a 429 on a create means the per-IP hourly cap (30) or the global"
  echo "daily cap (500) was reached. Locally the counters live in wrangler's"
  echo "persist directory as ip:<addr>:<YYYY-MM-DDTHH> and day:<YYYY-MM-DD>;"
  echo "\`wrangler kv key delete --local --binding SHARES <key>\` resets one."
  exit 1
fi
