#!/usr/bin/env bash
# Run one task through setup, start, finish and removal with the macOS system Git.
# Usage: smoke-macos.sh /absolute/path/to/work
# The scratch directory is new under TMPDIR and is kept for inspection.
set -euo pipefail

fail() {
  echo "smoke-macos: $*" >&2
  exit 1
}

[ "$#" -eq 1 ] || fail "usage: smoke-macos.sh /absolute/path/to/work"
work_bin=$1
case "$work_bin" in /*) ;; *) fail "the work path must be absolute" ;; esac
[ -x "$work_bin" ] || fail "not executable: $work_bin"

scratch=$(mktemp -d "${TMPDIR:-/tmp}/work-smoke-macos.XXXXXX")
scratch=$(cd "$scratch" && pwd -P)
home=$scratch/home
repo=$scratch/repo
mkdir "$home" "$repo"
echo "smoke-macos: scratch $scratch"

git() {
  env -i HOME="$home" PATH=/usr/bin:/bin GIT_CONFIG_NOSYSTEM=1 \
    /usr/bin/git -c user.name=Smoke -c user.email=smoke@example.invalid "$@"
}

work() {
  local out
  if ! out=$(cd "$scratch" && env -i HOME="$home" PATH=/usr/bin:/bin \
    XDG_CONFIG_HOME="$home/.config" "$work_bin" "$@" 2>"$scratch/stderr"); then
    cat "$scratch/stderr" >&2
    fail "work $* exited nonzero"
  fi
  printf '%s' "$out"
}

field() {
  printf '%s' "$1" | /usr/bin/plutil -extract "$2" raw -o - - 2>/dev/null ||
    fail "no $2 in: $1"
}

expect() {
  local got
  got=$(field "$1" "$2")
  [ "$got" = "$3" ] || fail "$2 is '$got', expected '$3' in: $1"
}

git -C "$repo" init -q -b main
git -C "$repo" commit -q --allow-empty -m initial

work setup --actor smoke --repository "$repo" --skills none --yes >/dev/null

started=$(work start --task smoke --base main)
checkout=$(field "$started" destination)
[ "$checkout" = "$home/worktrees/smoke" ] || fail "unexpected checkout: $checkout"

echo change >"$checkout/change.txt"
git -C "$checkout" add change.txt
git -C "$checkout" commit -q -m change

expect "$(work finish smoke)" task_finished true

preview=$(work remove smoke)
expect "$preview" outcome preview
expect "$preview" charge_retained true
[ -d "$checkout" ] || fail "the preview removed the checkout"

removed=$(work remove smoke --confirm-stopped)
expect "$removed" outcome removed
expect "$removed" charge_retained false
[ ! -e "$checkout" ] || fail "the checkout is still present after removal"

status=$(work status)
printf '%s\n' "$status" | grep -qx 'charged: 0' || fail "unexpected status: $status"

echo "smoke-macos: passed"
