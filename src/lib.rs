//! enxerto — pleme-io mesh sidecar-injector.
//!
//! Sprint **M2.2** of `theory/MESH-EXECUTION-PLAN.md`.
//!
//! A Kubernetes MutatingAdmissionWebhook that grafts the
//! [`aresta`](https://github.com/pleme-io/aresta) proxy + an
//! iptables init-container onto Pods labeled for mesh injection.
//!
//! # Selection
//!
//! A pod is injected iff:
//!   - it has label `mesh.pleme.io/inject=true` (per-pod opt-in), OR
//!   - its namespace has label `mesh.pleme.io/inject=true` (per-ns opt-in)
//!
//! AND it does NOT carry the annotation
//! `mesh.pleme.io/injected=true` (idempotency — re-admission is a
//! no-op).
//!
//! # Mutation
//!
//! - Adds `aresta` as a sidecar container, sharing the SPIFFE Workload
//!   API socket via a `csi.spiffe.io` CSI volume.
//! - Adds an init-container that runs `iptables` to redirect inbound
//!   pod-network traffic on TCP/* to `127.0.0.1:15001` (so the
//!   workload still binds on its native port, but bytes arrive via
//!   `aresta`'s mTLS termination).
//! - Adds an annotation `mesh.pleme.io/injected=true` so re-admission
//!   is a no-op.
//!
//! # Naming
//!
//! `enxerto` (Brazilian-Portuguese) = "graft". Semantically the
//! injector grafts mesh containers onto a pod's spec.

#![warn(clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]

pub mod admission;
pub mod patch;
pub mod tls;

pub use admission::{InjectorConfig, decide};
