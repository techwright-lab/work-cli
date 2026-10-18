# work-cli

Linux-first command-line tool (`work`) for managed Git worktree lifecycle:
admission, checkout ownership, execution groups, and retirement.

This is a public Apache-2.0 project. Configuration lives on the host; the
binary has no baked-in organization paths, identities, quotas, or notification
channels.

## Status

Early construction. The executable provides read-only `work --help`, `work status`
and `work doctor`. Status reports an honest uninitialized store. Other lifecycle
commands are not implemented and will not silently succeed.

## Read-only inventory

```sh
work doctor --json --repository /absolute/repo --managed-root /absolute/checkouts \
  --store-dir /absolute/private/store --trusted-registry /absolute/private/registry
```

Repeat `--repository` and `--managed-root` for multiple scopes. Repository inputs
may be the primary checkout or a linked checkout; canonical Git common directories
deduplicate aliases. No repository discovery outside these inputs occurs. Roots
must be existing canonical absolute directories, not symlinks, nested roots,
duplicate roots or `/`. No host-specific defaults are supplied. Omit the store
options to report unknown accounting rather than initialize anything.

Alternatively set `WORK_CONFIG` to a TOML file (or use
`$XDG_CONFIG_HOME/work/config.toml`):

```toml
repositories = ["/absolute/repo"]
roots = ["/absolute/checkouts"]
store_dir = "/absolute/private/store"
trusted_registry = "/absolute/private/registry"
```

Known fields require strings/string arrays of absolute canonical directory paths;
store/registry paths may be missing or inaccessible so unresolved evidence can be
reported unknown (never treated as canonical identity proof).
Explicit CLI lists replace their respective config lists. Empty scope is an error.
`--json` emits the version-1 report; without it the same report is pretty printed.
Unknown evidence is a successful report, not a healthy empty inventory.

Inventory includes Git-registered worktrees and at most 1,000 immediate children
per managed root. Unregistered child subtrees are reported as unmanaged/unknown,
not exhaustively searched for nested checkouts. Missing or malformed private Git
metadata is unknown/partial/recreated, never evidence of safe retirement. Valid
registered checkouts are **legacy/unmanaged candidates**, not proof of absence
from managed accounting: the current database lacks checkout filesystem paths.
`managed_filesystem_count` therefore remains null; doctor never guesses a match
from a basename, actor or task. Owner/state accounting includes every non-retired
charge independently of filesystem classification.

Headroom is `statvfs` available bytes, not a quota guarantee. Logical size estimates
use metadata only, at most 10,000 entries and depth 32 per path, without following
symlinks or crossing devices; incomplete estimates are null. They are neither
allocated nor reclaimed Btrfs bytes. Reports are observations, not atomic snapshots;
concurrent same-UID replacement remains a reconciliation concern.

Doctor never calls store initialization/migration, repairs evidence, runs hooks,
creates notifications or contacts remotes. SQLite is opened read-only with existing
initialization/authority evidence. WAL databases require **both pre-existing WAL and
SHM files**; a closed WAL database without sidecars is conservatively unknown rather
than recreating sidecars or using `immutable=1` (which ignores active WAL). Existing
SHM lock bookkeeping may change: read-only does not promise byte immutability.
No new files/directories or lifecycle/outbox writes are intended. Missing, corrupt,
inaccessible or partial authority/store evidence is unknown, not zero charges.

## Requirements

- Rust 1.98.1
- Linux is the qualified platform. Other operating systems are unsupported.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
