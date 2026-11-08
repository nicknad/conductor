//! Durable job definitions and the single-process scheduler dispatcher.
//!
//! The scheduler is a control-plane component: it sequences work but never
//! executes it directly. Dispatch goes through [`dispatch::ExecutionDispatcher`],
//! which exposes only a pinned `ExecutionService::execute` call.

pub mod dispatch;
pub mod job;
pub mod service;
pub mod store;

pub use job::{
    ClaimedRun, JobDefinition, JobFailureCode, JobRun, JobRunState, NewJob, RunCompletion, Trigger,
    TriggerKind,
};
pub use service::{SchedulerConfig, SchedulerError, SchedulerService, SchedulerState};
pub use store::{EnableResult, JobStore, JobStoreError, JobStoreLimits, RecoveryReport};
