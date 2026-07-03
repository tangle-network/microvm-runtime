# microvm-runtime

[![crates.io](https://img.shields.io/crates/v/microvm-runtime.svg)](https://crates.io/crates/microvm-runtime)
[![docs.rs](https://docs.rs/microvm-runtime/badge.svg)](https://docs.rs/microvm-runtime)

Firecracker microVM driver for decentralized Tangle operators.

A pure-Rust primitive. No HTTP server, no auth layer, no sessions, no business
logic — just the driver that speaks the Firecracker API over its unix socket
and exposes a small lifecycle trait. Tangle blueprints (the operator binaries)
consume it directly as a Cargo dependency — operators **are** the hosts, so
there is no second process to deploy.

## Why this exists

Every Tangle blueprint that wants microVM isolation (sandbox blueprint,
microvm blueprint, future cloud-style blueprints) needs the same driver. This
crate is that driver, extracted into a single primitive with a narrow surface
so it can be hardened in one place.

## Status

`0.1.0-alpha.1` — extracted from `microvm-blueprint`. Lifecycle works
(create / start / stop / snapshot / destroy). Production hardening is the
next several releases:

- [ ] Network configuration (TAP / bridge / iptables NAT)
- [ ] Vsock device for guest↔host RPC
- [ ] Snapshot restore (`PUT /snapshot/load`)
- [ ] Console log ring buffer for post-mortem
- [ ] Graceful shutdown (SIGTERM → wait → SIGKILL)
- [ ] Jailer wrapper (chroot / cgroup v2 / seccomp / UID-GID mapping)
- [ ] Rate limiters on drives and NICs
- [ ] Egress firewall per session
- [ ] Metrics polling (`GET /vm` for CPU / memory / network)
- [ ] VM rename for warm-pool handoff

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the per-phase plan.

## Usage

```rust
use microvm_runtime::{adapters::firecracker::{FirecrackerConfig, FirecrackerVmProvider}, VmProvider, VmQuery};

let provider = FirecrackerVmProvider::from_env();
provider.create_vm("vm-1")?;
provider.start_vm("vm-1")?;
provider.snapshot_vm("vm-1", "snap-a")?;
provider.stop_vm("vm-1")?;
provider.destroy_vm("vm-1")?;
```

## Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `MICROVM_FIRECRACKER_BIN` | `/usr/local/bin/firecracker` | Firecracker binary path |
| `MICROVM_FIRECRACKER_KERNEL` | `/var/lib/firecracker/vmlinux` | Linux kernel image |
| `MICROVM_FIRECRACKER_ROOTFS` | `/var/lib/firecracker/rootfs/default.ext4` | Rootfs image |
| `MICROVM_FIRECRACKER_SOCKET_DIR` | `/var/run/microvm/sockets` | Per-VM API socket parent dir |
| `MICROVM_FIRECRACKER_STATE_DIR` | `/var/lib/microvm/state` | Per-VM state dir |
| `MICROVM_FIRECRACKER_VCPU` | `1` | Default vCPU count |
| `MICROVM_FIRECRACKER_MEM_MIB` | `256` | Default memory size |
| `MICROVM_MEM_BACKEND` | `file` | Snapshot-restore memory backend: `file` (FC reads the whole mem file before resume) or `uffd` (userfaultfd handler pages memory in on demand) |

## License

[Unlicense](LICENSE) — public domain.
