# Roadmap

This crate ships in alpha-cadence releases until the production hardening list
is complete. Each phase below is a release boundary.

## 0.1.x — Extraction (current)

Lifecycle: create / start / stop / snapshot (create only) / destroy. Direct
unix-socket HTTP to the Firecracker API. No SDK dep. Process management with
kill-on-error rollback. In-memory test adapter for downstream blueprint tests.

What works for an operator today: provision a VM, boot it, capture a snapshot
of its memory, tear it down. Not yet useful for sandboxing — the VM has no
network and no guest↔host channel.

## 0.2.x — Make it useful

The minimum for any operator to actually run workloads inside a VM.

- **Network setup**: TAP device creation, bridge attachment, IP allocation,
  `PUT /network-interfaces`, host iptables NAT.
- **Vsock**: CID allocation, `PUT /vsock`, parent dir mkdir before
  `/snapshot/load` (FC v1.6 race fix).
- **Snapshot restore**: `PUT /snapshot/load` + UFFD handler coordination.
  Pairs with 0.1 snapshot-create for fast warm boot.
- **Console capture**: stderr ring buffer (200-line tail per VM) so kernel
  panics and init failures are debuggable post-mortem instead of `Stdio::null`.
- **Graceful shutdown**: SIGTERM → poll → SIGKILL on timeout.
- **Per-VM config override**: kernel, rootfs, vCPU, memory, boot args — today
  these are workspace-level, which prevents sizing VMs to workload.

## 0.3.x — Production hardening

Required before a security-conscious operator should run this in production.

- **Jailer wrapper**: chroot + cgroup v2 + seccomp + UID-GID mapping.
- **Rate limiters**: bandwidth + ops quota on drives + NICs, plumbed to the FC
  API rather than the current hardcoded `None`.
- **Egress firewall**: per-session iptables FORWARD chain with cleanup on
  destroy. Operator can scope what each VM can reach.
- **Metrics polling**: periodic `GET /vm` for CPU, memory, network counters.
- **VM rename**: FC 1.10+ identifier swap for warm-pool handoff without
  re-snapshotting.

## 0.4.x — Optional surfaces

Per use case, not blocking either consumer.

- MMDS (instance metadata service).
- Balloon device (pre-snapshot memory reclaim).
- CPU templates (cross-host migration compatibility).
- Multi-drive support: workspace, sidecar, nix store as separate drives with
  separate rate limits.
- Metrics fifo for in-VM observability tools.
