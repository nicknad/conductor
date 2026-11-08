//! Durable job definition and manual-trigger HTTP surface.
//!
//! Every route is bearer-authenticated by the router. Handlers validate
//! identities, triggers, and payload bounds before the store sees them; the
//! scheduler remains a dispatcher and every run is executed through the
//! existing pinned execution service.

use std::time::SystemTime;

use axum::extract::rejection::{JsonRejection, PathRejection, QueryRejection};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::api::errors::ApiError;
use crate::api::uploads::{request_id, AppState};
use crate::control_plane::scheduler::job::{
    next_interval_at, next_job_id, validate_payload, JobDefinition, JobFailureCode, JobRun, NewJob,
    Trigger, MAX_INTERVAL_SECS, MAX_JOB_ID_BYTES, MIN_INTERVAL_SECS,
};
use crate::control_plane::scheduler::service::SchedulerError;
use crate::control_plane::scheduler::store::JobStoreError;
use crate::modules::identity::{is_safe_identity, validate_identity};
use crate::storage::database::to_millis;

const DEFAULT_LIST_LIMIT: u64 = 50;
const MAX_LIST_LIMIT: u64 = 200;
const MAX_LIST_OFFSET: u64 = 1_000_000;

/// Request body for creating a job.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateJobRequest {
    pub module_id: String,
    pub version: String,
    pub function: String,
    pub trigger: TriggerRequest,
    #[serde(default)]
    pub payload: Option<serde_json::Value>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_enabled() -> bool {
    true
}

/// Trigger shape accepted on create.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TriggerRequest {
    Manual,
    Interval { interval_secs: u64 },
    Cron { expression: String },
}

/// Job view. Payload is deliberately absent.
#[derive(Debug, Serialize)]
pub struct JobResponse {
    pub job_id: String,
    pub module_id: String,
    pub version: String,
    pub function: String,
    pub trigger: TriggerView,
    pub enabled: bool,
    pub next_run_at_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TriggerView {
    Manual,
    Interval { interval_secs: u64 },
    Cron { expression: String },
}

#[derive(Debug, Serialize)]
pub struct ListJobsResponse {
    pub jobs: Vec<JobResponse>,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Serialize)]
pub struct TriggerRunResponse {
    pub job_id: String,
    pub run_id: String,
    pub state: &'static str,
}

#[derive(Debug, Serialize)]
pub struct RunResponse {
    pub run_id: String,
    pub job_id: String,
    pub attempt: u32,
    pub trigger: &'static str,
    pub state: &'static str,
    pub scheduled_for_ms: i64,
    pub created_at_ms: i64,
    pub started_at_ms: Option<i64>,
    pub finished_at_ms: Option<i64>,
    pub execution_id: Option<String>,
    pub outcome: Option<String>,
    pub failure_code: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct ListRunsResponse {
    pub runs: Vec<RunResponse>,
    pub limit: usize,
    pub offset: usize,
}

#[derive(Debug, Deserialize)]
pub struct PaginationQuery {
    pub limit: Option<u64>,
    pub offset: Option<u64>,
}

/// Creates a durable job.
#[tracing::instrument(name = "create_job", skip(state, headers, payload))]
pub async fn post_job(
    State(state): State<AppState>,
    headers: HeaderMap,
    payload: Result<Json<CreateJobRequest>, JsonRejection>,
) -> Response {
    let id = request_id(&headers);
    let request = match payload {
        Ok(Json(request)) => request,
        Err(rejection) => return refuse(&id, json_rejection(rejection)),
    };
    if let Err(api) = validate_create(&request) {
        return refuse(&id, api);
    }
    let trigger: Trigger = request.trigger.into();
    let now = SystemTime::now();
    let next_run_at = match &trigger {
        Trigger::Interval { interval_secs } if request.enabled => {
            next_interval_at(now, *interval_secs)
        }
        Trigger::Manual | Trigger::Interval { .. } | Trigger::Cron { .. } => None,
    };
    let new = NewJob {
        job_id: next_job_id(),
        module_id: request.module_id,
        version: request.version,
        function: request.function,
        trigger,
        payload: request.payload.unwrap_or(serde_json::Value::Null),
        enabled: request.enabled,
        next_run_at,
        created_at: now,
    };
    match state.scheduler.create_job(new).await {
        Ok(job) => (StatusCode::CREATED, Json(JobResponse::from(job))).into_response(),
        Err(error) => refuse(&id, scheduler_error(error)),
    }
}

/// Lists jobs newest first.
#[tracing::instrument(name = "list_jobs", skip(state))]
pub async fn get_jobs(
    State(state): State<AppState>,
    query: Result<Query<PaginationQuery>, QueryRejection>,
) -> Response {
    let (limit, offset) = match pagination(query) {
        Ok(pagination) => pagination,
        Err(api) => return api.into_response(),
    };
    match state.scheduler.list_jobs(limit, offset).await {
        Ok(jobs) => Json(ListJobsResponse {
            jobs: jobs.into_iter().map(JobResponse::from).collect(),
            limit,
            offset,
        })
        .into_response(),
        Err(error) => scheduler_error(error).into_response(),
    }
}

/// Enables a job. Manual jobs have no next run time.
#[tracing::instrument(name = "enable_job", skip(state, headers))]
pub async fn post_enable(
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    let id = request_id(&headers);
    let job_id = match job_id_path(path) {
        Ok(job_id) => job_id,
        Err(api) => return refuse(&id, api),
    };
    let job = match state.scheduler.get_job(&job_id).await {
        Ok(Some(job)) => job,
        Ok(None) => return refuse(&id, job_not_found()),
        Err(error) => return refuse(&id, scheduler_error(error)),
    };
    let next_run_at = match &job.trigger {
        Trigger::Interval { interval_secs } => next_interval_at(SystemTime::now(), *interval_secs),
        Trigger::Manual | Trigger::Cron { .. } => None,
    };
    match state
        .scheduler
        .set_enabled(&job_id, true, next_run_at)
        .await
    {
        Ok(Some(result)) => Json(JobResponse::from(result.job)).into_response(),
        Ok(None) => refuse(&id, job_not_found()),
        Err(error) => refuse(&id, scheduler_error(error)),
    }
}

/// Disables a job and terminalizes its queued runs.
#[tracing::instrument(name = "disable_job", skip(state, headers))]
pub async fn post_disable(
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    let id = request_id(&headers);
    let job_id = match job_id_path(path) {
        Ok(job_id) => job_id,
        Err(api) => return refuse(&id, api),
    };
    match state.scheduler.set_enabled(&job_id, false, None).await {
        Ok(Some(result)) => Json(JobResponse::from(result.job)).into_response(),
        Ok(None) => refuse(&id, job_not_found()),
        Err(error) => refuse(&id, scheduler_error(error)),
    }
}

/// Enqueues one manual run and returns its durable id.
#[tracing::instrument(name = "trigger_job", skip(state, headers))]
pub async fn post_trigger(
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    headers: HeaderMap,
) -> Response {
    let id = request_id(&headers);
    let job_id = match job_id_path(path) {
        Ok(job_id) => job_id,
        Err(api) => return refuse(&id, api),
    };
    match state.scheduler.trigger_manual(&job_id).await {
        Ok(run) => (
            StatusCode::ACCEPTED,
            Json(TriggerRunResponse {
                job_id: run.job_id,
                run_id: run.run_id,
                state: run.state.as_str(),
            }),
        )
            .into_response(),
        Err(error) => refuse(&id, scheduler_error(error)),
    }
}

/// Lists runs for one job newest first.
#[tracing::instrument(name = "list_job_runs", skip(state))]
pub async fn get_job_runs(
    State(state): State<AppState>,
    path: Result<Path<String>, PathRejection>,
    query: Result<Query<PaginationQuery>, QueryRejection>,
) -> Response {
    let job_id = match job_id_path(path) {
        Ok(job_id) => job_id,
        Err(api) => return api.into_response(),
    };
    let (limit, offset) = match pagination(query) {
        Ok(pagination) => pagination,
        Err(api) => return api.into_response(),
    };
    match state.scheduler.get_job(&job_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return job_not_found().into_response(),
        Err(error) => return scheduler_error(error).into_response(),
    }
    match state.scheduler.list_runs(&job_id, limit, offset).await {
        Ok(runs) => Json(ListRunsResponse {
            runs: runs.into_iter().map(RunResponse::from).collect(),
            limit,
            offset,
        })
        .into_response(),
        Err(error) => scheduler_error(error).into_response(),
    }
}

fn validate_create(request: &CreateJobRequest) -> Result<(), ApiError> {
    validate_identity_field("module_id", &request.module_id)?;
    validate_identity_field("version", &request.version)?;
    validate_identity_field("function", &request.function)?;
    if let Some(payload) = &request.payload {
        validate_payload(payload)
            .map_err(|error| ApiError::BadRequest("invalid_payload", error.to_string()))?;
    }
    match &request.trigger {
        TriggerRequest::Manual => Ok(()),
        TriggerRequest::Interval { interval_secs } => {
            if !(MIN_INTERVAL_SECS..=MAX_INTERVAL_SECS).contains(interval_secs) {
                return Err(ApiError::BadRequest(
                    "invalid_trigger",
                    format!(
                        "interval_secs must be between {MIN_INTERVAL_SECS} and {MAX_INTERVAL_SECS}"
                    ),
                ));
            }
            Ok(())
        }
        TriggerRequest::Cron { .. } => Err(ApiError::BadRequest(
            "invalid_trigger",
            "interval triggers are supported; cron triggers are not".to_owned(),
        )),
    }
}

fn validate_identity_field(field: &'static str, value: &str) -> Result<(), ApiError> {
    validate_identity(value)
        .map_err(|error| ApiError::BadRequest("invalid_identity", format!("{field} {error}")))
}

fn job_id_path(path: Result<Path<String>, PathRejection>) -> Result<String, ApiError> {
    let Path(job_id) = path.map_err(|_| invalid_job_id())?;
    if !is_safe_identity(&job_id) || job_id.len() > MAX_JOB_ID_BYTES {
        return Err(invalid_job_id());
    }
    Ok(job_id)
}

fn invalid_job_id() -> ApiError {
    ApiError::BadRequest("invalid_job_id", "job id is not valid".to_owned())
}

fn job_not_found() -> ApiError {
    ApiError::NotFound("job_not_found", "job was not found".to_owned())
}

fn pagination(
    query: Result<Query<PaginationQuery>, QueryRejection>,
) -> Result<(usize, usize), ApiError> {
    let Ok(Query(query)) = query else {
        return Err(invalid_pagination());
    };
    let limit = query.limit.unwrap_or(DEFAULT_LIST_LIMIT);
    let offset = query.offset.unwrap_or(0);
    if limit == 0 || limit > MAX_LIST_LIMIT || offset > MAX_LIST_OFFSET {
        return Err(invalid_pagination());
    }
    Ok((limit as usize, offset as usize))
}

fn invalid_pagination() -> ApiError {
    ApiError::BadRequest(
        "invalid_pagination",
        "pagination parameters are invalid".to_owned(),
    )
}

fn json_rejection(rejection: JsonRejection) -> ApiError {
    if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
        ApiError::PayloadTooLarge("request body exceeds the allowed size".to_owned())
    } else {
        ApiError::BadRequest(
            "invalid_request_body",
            "request body must be valid JSON matching the documented schema".to_owned(),
        )
    }
}

fn scheduler_error(error: SchedulerError) -> ApiError {
    match error {
        SchedulerError::Store(JobStoreError::JobNotFound) => job_not_found(),
        SchedulerError::Store(JobStoreError::JobDisabled) => {
            ApiError::Conflict("job_disabled", "job is disabled".to_owned())
        }
        SchedulerError::Store(JobStoreError::QueueFull | JobStoreError::JobLimitReached) => {
            ApiError::Overloaded("server is at its job bound; retry later".to_owned())
        }
        SchedulerError::Store(JobStoreError::InvalidJob(_) | JobStoreError::InvalidRun(_)) => {
            ApiError::BadRequest(
                "invalid_request_body",
                "job definition is not usable".to_owned(),
            )
        }
        SchedulerError::NotRunning => ApiError::Unavailable(
            "scheduler_unavailable",
            "scheduler is not available".to_owned(),
        ),
        SchedulerError::Store(JobStoreError::Storage(_)) | SchedulerError::Task(_) => {
            ApiError::Internal("scheduler host failure".to_owned())
        }
        SchedulerError::AlreadyStarted => {
            ApiError::Internal("scheduler lifecycle failure".to_owned())
        }
    }
}

fn refuse(request_id: &Option<String>, api: ApiError) -> Response {
    let (_, body) = api.status_and_body();
    tracing::warn!(
        request_id = request_id.as_deref().unwrap_or(""),
        code = body.code,
        "job request refused"
    );
    api.into_response()
}

impl From<JobDefinition> for JobResponse {
    fn from(job: JobDefinition) -> Self {
        Self {
            job_id: job.job_id,
            module_id: job.module_id,
            version: job.version,
            function: job.function,
            trigger: TriggerView::from(job.trigger),
            enabled: job.enabled,
            next_run_at_ms: job.next_run_at.map(to_millis),
            created_at_ms: to_millis(job.created_at),
            updated_at_ms: to_millis(job.updated_at),
        }
    }
}

impl From<TriggerRequest> for Trigger {
    fn from(trigger: TriggerRequest) -> Self {
        match trigger {
            TriggerRequest::Manual => Self::Manual,
            TriggerRequest::Interval { interval_secs } => Self::Interval { interval_secs },
            TriggerRequest::Cron { expression } => Self::Cron { expression },
        }
    }
}

impl From<Trigger> for TriggerView {
    fn from(trigger: Trigger) -> Self {
        match trigger {
            Trigger::Manual => Self::Manual,
            Trigger::Interval { interval_secs } => Self::Interval { interval_secs },
            Trigger::Cron { expression } => Self::Cron { expression },
        }
    }
}

impl From<JobRun> for RunResponse {
    fn from(run: JobRun) -> Self {
        Self {
            run_id: run.run_id,
            job_id: run.job_id,
            attempt: run.attempt_no,
            trigger: run.trigger.as_str(),
            state: run.state.as_str(),
            scheduled_for_ms: to_millis(run.scheduled_for),
            created_at_ms: to_millis(run.created_at),
            started_at_ms: run.started_at.map(to_millis),
            finished_at_ms: run.finished_at.map(to_millis),
            execution_id: run.execution_id,
            outcome: run.outcome,
            failure_code: run.failure_code.map(JobFailureCode::as_str),
        }
    }
}
