# work-cli

Linux-first command-line tool (`work`) for managed Git worktree lifecycle:
admission, checkout ownership, execution groups, and retirement.

This is a public Apache-2.0 project. Configuration lives on the host; the
binary has no baked-in organization paths, identities, quotas, or notification
channels.

## Status

Early construction. The executable currently provides read-only `work --help`
and `work status`. Status reports an honest uninitialized store and does not
create files. Later commands are not implemented and will not silently succeed.

## Requirements

- Rust 1.98.1
- Linux is the qualified platform. Other operating systems are unsupported.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
