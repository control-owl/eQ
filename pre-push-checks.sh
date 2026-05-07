#!/usr/bin/env bash
# authors = ["Control Owl <eq[at]r-o0-t[dot]wtf>"]
# license = "CC-BY-NC-ND-4.0  [2023-2026]  Control Owl"

# -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..
clear

set -o errexit
set -o nounset
set -o pipefail

RED=$'\e[31m'
GREEN=$'\e[32m'
BOLD=$'\e[1m'
RESET=$'\e[0m'

SEP='-.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..'
LABEL_WIDTH=16
STATUS_WIDTH=6

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

# -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

color_ok() { printf '%b%s%b' "$BOLD$GREEN" "OK" "$RESET"; }
color_err() { printf '%b%s%b' "$BOLD$RED" "ERROR" "$RESET"; }

center_header() {
  local header="$1"
  local sep="$SEP"
  local sep_len=${#sep}
  local hdr_len=${#header}
  if [ "$hdr_len" -ge "$sep_len" ]; then
    printf '%s\n' "$header"
    return
  fi
  local left_pad=$(( (sep_len - hdr_len) / 2 ))
  local right_pad=$(( sep_len - hdr_len - left_pad ))
  printf '%*s%s%*s\n' "$left_pad" '' "$header" "$right_pad" ''
}

# -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

printf '\n%b%s%b\n\n' "$BOLD$GREEN" "Starting pre-push..." "$RESET";
printf '%s\n\n' "$SEP"

if [ $# -ge 1 ] && [ -d "$1" ]; then
  REPO_ROOT="$1"
  shift
else
  REPO_ROOT="."
fi

SHAS=("$@")

if ! command -v cargo >/dev/null 2>&1; then
  printf '%b\n' "$BOLD$RED""ERROR: cargo not found in PATH""$RESET" >&2
  exit 3
fi

if ! pushd "$REPO_ROOT" >/dev/null 2>&1; then
  printf '%b\n' "$BOLD$RED""ERROR: cannot change directory to $REPO_ROOT""$RESET" >&2
  exit 2
fi
trap 'popd >/dev/null 2>&1 || true; rm -rf "$TMPDIR"' EXIT

FMT_OUT="$TMPDIR/fmt.out"
CLIPPY_OUT="$TMPDIR/clippy.out"
TEST_OUT="$TMPDIR/test.out"

# -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

center_header "cargo fmt"
printf '\n'
if cargo fmt --all -- --check >"$FMT_OUT" 2>&1; then
  printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_ok)" "cargo fmt no errors"
else
  sed 's/^/    /' "$FMT_OUT" >&2
  printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_err)" "cargo fmt reported formatting issues"
  exit 1
fi

printf '\n%s\n\n' "$SEP"

# -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

center_header "cargo clippy"
printf '\n'
if cargo clippy --all-targets --all-features -- -D warnings >"$CLIPPY_OUT" 2>&1; then
  if [ -s "$CLIPPY_OUT" ]; then
    sed 's/^/    /' "$CLIPPY_OUT"
  fi
  printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_ok)" "cargo clippy no errors"
else
  sed 's/^/    /' "$CLIPPY_OUT" >&2
  printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_err)" "cargo clippy reported warnings or lint failures"
  exit 1
fi

printf '\n%s\n\n' "$SEP"

# -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

center_header "cargo test"
printf '\n'
if cargo test --all-targets --all-features -- >"$TEST_OUT" 2>&1; then
  if [ -s "$TEST_OUT" ]; then
    sed 's/^/    /' "$TEST_OUT"
  fi
  printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_ok)" "cargo test no errors"
else
  sed 's/^/    /' "$TEST_OUT" >&2
  printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_err)" "cargo test reported warnings"
  exit 1
fi

printf '\n%s\n\n' "$SEP"

# -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

center_header "PGP check"
printf '\n'

if [ "${#SHAS[@]}" -eq 0 ]; then
  if git rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
    SHAS=( "$(git rev-parse --verify --quiet HEAD)" )
  else
    printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_err)" "no commits available to verify"
    exit 6
  fi
fi

declare -A seen
normalized=()
for s in "${SHAS[@]}"; do
  [ -z "$s" ] && continue
  if full="$(git rev-parse --verify --quiet "${s}^{commit}" 2>/dev/null)"; then
    if [ -n "$full" ] && [ -z "${seen[$full]:-}" ]; then
      normalized+=("$full")
      seen[$full]=1
    fi
  else
    printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_err)" "commit ${s} not found locally"
    exit 7
  fi
done

if [ "${#normalized[@]}" -eq 0 ]; then
  printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_err)" "no valid local commits to verify"
  exit 8
fi

for sha in "${normalized[@]}"; do
  sig_status="$(git show --no-patch --pretty=format:%G? "$sha" 2>/dev/null || true)"
  if [ "$sig_status" != "G" ]; then
    sig_key="$(git show --no-patch --pretty=format:%GK "$sha" 2>/dev/null || true)"
    sig_user="$(git show --no-patch --pretty=format:%GS "$sha" 2>/dev/null || true)"
    printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_err)" "commit ${sha} signature status: ${sig_status}"
    [ -n "$sig_key" ] && printf '    %s\n' "Signature key: ${sig_key}" >&2
    [ -n "$sig_user" ] && printf '    %s\n' "Signer: ${sig_user}" >&2
    exit 9
  fi
  printf "%-${LABEL_WIDTH}s %-${STATUS_WIDTH}s %s\n" "$(color_ok)" "commit ${sha} has a valid PGP signature (G)"
done

# -.-. --- .--. -.-- .-. .. --. .... - / -.-. --- -. - .-. --- .-.. / --- .-- .-..

printf '\n%s\n\n' "$SEP"
printf '%b%s%b\n' "$BOLD$GREEN" "ALL CHECK DONE" "$RESET";

printf '\n%b%s%b\n' "$BOLD$GREEN" "Ready for push to remote..." "$RESET";
printf '\n%s\n' "$SEP"

exit 0
