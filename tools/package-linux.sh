#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || {
  echo 'Packaging is qualified for Linux x86_64.' >&2
  exit 1
}
work_cli_expected=$(python3 tools/release_version.py)
cargo build --release --locked -p work-cli
work_cli_target=${CARGO_TARGET_DIR:-target}
work_cli_version=$("$work_cli_target/release/work" --version)
work_cli_version=${work_cli_version#work }
[[ "$work_cli_version" == "$work_cli_expected" ]] || { echo 'Binary version disagrees with workspace.' >&2; exit 1; }
work_cli_name="work-cli-$work_cli_version-linux-x86_64"
work_cli_stage=$(mktemp -d)
trap 'rm -rf "$work_cli_stage"' EXIT
mkdir -p "$work_cli_stage/$work_cli_name/bin" "$work_cli_stage/$work_cli_name/examples" "$work_cli_stage/$work_cli_name/tools" "$work_cli_stage/$work_cli_name/docs" target/dist
install -m 755 "$work_cli_target/release/work" "$work_cli_stage/$work_cli_name/bin/work"
cp README.md LICENSE AGENTS.md "$work_cli_stage/$work_cli_name/"
cp examples/work.toml "$work_cli_stage/$work_cli_name/examples/"
cp tools/work_install.py "$work_cli_stage/$work_cli_name/tools/"
chmod 755 "$work_cli_stage/$work_cli_name/tools/work_install.py"
cp docs/distribution.md "$work_cli_stage/$work_cli_name/docs/"
cp -R skills "$work_cli_stage/$work_cli_name/"
tar -C "$work_cli_stage" -czf "target/dist/$work_cli_name.tar.gz" "$work_cli_name"
(cd target/dist && sha256sum "$work_cli_name.tar.gz" > "$work_cli_name.tar.gz.sha256")
