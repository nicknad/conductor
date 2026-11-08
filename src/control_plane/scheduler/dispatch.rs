//! Narrow execution boundary for the scheduler.
//!
//! This wrapper is the only scheduler dependency on the execution service.
//! It deliberately exposes no activation, registry, artifact, staging, or
//! worker-spawn surface, and every call pins the job's registered version.

use std::sync::Arc;
use std::time::Duration;

use crate::control_plane::execute_module::{ExecutionError, ExecutionReceipt, ExecutionService};

/// Pinned execution adapter used by the scheduler.
#[derive(Clone, Debug)]
pub struct ExecutionDispatcher {
    service: Arc<ExecutionService>,
}

impl ExecutionDispatcher {
    #[must_use]
    pub fn new(service: Arc<ExecutionService>) -> Self {
        Self { service }
    }

    /// Host ceiling for a scheduled execution.
    #[must_use]
    pub fn max_deadline(&self) -> Duration {
        self.service.max_deadline()
    }

    /// Executes one function of the job's pinned registered version. The
    /// version is mandatory and is always passed as an explicit pin, so the
    /// scheduler cannot follow or mutate the active pointer.
    pub async fn execute(
        &self,
        module_id: &str,
        version: &str,
        function: &str,
        configuration: serde_json::Value,
        deadline: Duration,
    ) -> Result<ExecutionReceipt, ExecutionError> {
        self.service
            .execute(module_id, Some(version), function, configuration, deadline)
            .await
    }
}
