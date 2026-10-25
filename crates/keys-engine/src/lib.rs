//! Niyantrak keys engine: one SSH key per connection, rotated by a 7-step contract that never locks you out.
//!
//! * `model`     — the `ssh_rotation` block (control plane or local `connections.json`)
//! * `plan`      — read-only report: age, due, reachability, drift on the target's authorized_keys
//! * `rotate`    — the 7 steps, against any `Transport` (system ssh or the in-memory fake)
//! * `audit`     — JSONL per step (fingerprints only) + niyantrak 6W events (who, whom, what, where, why, which + when)
//! * `identity`  — who is acting, from the OS
//! * `enrol`     — node card + pinned-TLS join to a Niyantrak control plane
//! * `features`  — module flags delivered by the control plane

pub mod audit;
pub mod canon;
pub mod client;
pub mod enrol;
pub mod features;
pub mod identity;
pub mod layout;
pub mod model;
pub mod plan;
pub mod pubkey;
pub mod rotate;
pub mod sshconfig;
pub mod timeutil;
pub mod transport;

#[cfg(test)]
mod rotate_tests;

pub use model::{Connection, Policy, RotationConfig, TargetOs};
pub use rotate::{Outcome, RotationReport, Rotator, StepEvent, StepResult};
pub use transport::{FakeTransport, SystemTransport, Transport};
