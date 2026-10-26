#!/usr/bin/env bash
# Disposable qualification; mounts only this checkout and its dependency cache.
set -euo pipefail
work_cli_root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$work_cli_root/target/container-cargo" "$work_cli_root/target/container"
work_cli_network=none
if [[ ${1:-} == fetch ]]; then
  work_cli_network=bridge
fi
work_cli_command=(cargo "$@")
if [[ ${1:-} == -- ]]; then
  shift
  work_cli_command=("$@")
fi
# Keep procfs on one mount for the historical no-mount-crossing supervisor tests.
# The container remains unprivileged with no capabilities or host runtime mounts.
exec docker run --rm --init --cpus=4 --memory=6g \
  --network "$work_cli_network" --cap-drop=ALL --security-opt=no-new-privileges \
  --security-opt=systempaths=unconfined \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$work_cli_root,dst=/workspace" \
  --env CARGO_HOME=/workspace/target/container-cargo \
  --env CARGO_TARGET_DIR=/workspace/target/container \
  --env CARGO_BUILD_JOBS=4 \
  work-cli-qualification:rust-1.98.1-git-2.55.0 "${work_cli_command[@]}"
