# Modified Moby seccomp policy

`seccomp.json` is derived from [Moby profiles](https://github.com/moby/profiles/blob/6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef/seccomp/default.json) at commit `6fe7deb1b9fb7c0397a4593480d7d22b9ee8caef` (Apache-2.0). The repository's [LICENSE](../LICENSE) and [NOTICE](../NOTICE) accompany this modified copy.

The default profile prevents native Codex's unprivileged Bubblewrap sandbox from creating a nested user namespace. Only these additional rules are appended:

- `clone` requires `CLONE_NEWUSER` (`0x10000000`) on non-s390 architectures. The existing architecture-specific default rules are retained.
- `unshare` accepts only namespace bits: flags outside the namespace mask are rejected by the added allow rule (`value=2180907007`, masked comparison against zero). The default denial remains for other inputs.
- `mount`, `umount2`, `pivot_root` and `sethostname` are permitted at the syscall filter layer for namespace setup. Kernel capability/namespace checks still apply; the outer container has **all capabilities dropped**, an unprivileged UID, and `no-new-privileges`.

The baseline `clone3` ENOSYS behavior is preserved. This is not an unconfined profile and grants no Host capability, Docker socket or network route. Docker recursively locks the source bind read-only; native sandbox tests verify source writes/remount and immutable image writes fail while engine artifacts remain writable.

Support is currently tested on Docker Desktop's Linux kernel. Namespace/syscall availability on other kernels or LSM profiles can fail closed. Do not "fix" such failures with privileged containers, `CAP_SYS_ADMIN`, unconfined seccomp, a writable source bind or automatic kernel policy changes.
