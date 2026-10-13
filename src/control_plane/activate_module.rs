//! Activates a registered module after policy checks. Never executes
//! untrusted code to revalidate.
//!
//! Activation consumes registry state plus an [`ActivationPolicy`]: it
//! never re-opens the archive, never re-parses the manifest, and never
//! runs package bytes. The returned [`ActivatedModule`] carries the
//! registered digest and authorizing signer so the executor can verify
//! bytes at spawn time — the Rust type is not the authorization, it is the
//! receipt of one.
//!
//! Who may ask for activation (operator authorization) is the caller's
//! responsibility, exactly like the upload bearer token. This layer
//! decides only whether a *registered* module version is permitted to run:
//! registration exists and its declared runtime is allowlisted.

use thiserror::Error;

use crate::modules::registry::{ModuleRegistry, RegistryError};
use crate::packages::artifact::ArtifactDigest;

/// What activation is permitted to run. Built once at startup, held
/// immutably; an empty allowlist is a startup error, never a runtime
/// ambiguity.
#[derive(Debug, Clone)]
pub struct ActivationPolicy {
    pub allowed_runtimes: Vec<String>,
}

impl ActivationPolicy {
    pub fn new(allowed_runtimes: Vec<String>) -> Result<Self, ActivationError> {
        if allowed_runtimes.is_empty() {
            return Err(ActivationError::EmptyRuntimeAllowlist);
        }
        Ok(Self { allowed_runtimes })
    }
}

/// A module version cleared to be executed by the host runtime. Carries
/// identity, digest, and provenance; carries no code and no path — the
/// executor resolves bytes from the digest and verifies them at use time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivatedModule {
    pub module_id: String,
    pub version: String,
    pub digest: ArtifactDigest,
    pub signer_key_id: String,
}

/// Activation rejections. All variants are policy or state failures; none
/// execute or parse package bytes.
#[derive(Debug, Error)]
pub enum ActivationError {
    #[error("activation policy has an empty runtime allowlist")]
    EmptyRuntimeAllowlist,
    #[error("module version is not registered: {module_id} {version}")]
    NotRegistered { module_id: String, version: String },
    #[error("module runtime is not allowed to activate: {runtime} ({module_id} {version})")]
    RuntimeNotAllowed {
        module_id: String,
        version: String,
        runtime: String,
    },
    #[error("registry lookup failed: {0}")]
    Storage(#[from] RegistryError),
}

/// Activates a registered module version under policy.
pub fn activate(
    registry: &ModuleRegistry,
    module_id: &str,
    version: &str,
    policy: &ActivationPolicy,
) -> Result<ActivatedModule, ActivationError> {
    let record =
        registry
            .get(module_id, version)?
            .ok_or_else(|| ActivationError::NotRegistered {
                module_id: module_id.to_owned(),
                version: version.to_owned(),
            })?;
    if !policy
        .allowed_runtimes
        .iter()
        .any(|allowed| allowed == &record.runtime)
    {
        return Err(ActivationError::RuntimeNotAllowed {
            module_id: record.module_id,
            version: record.version,
            runtime: record.runtime,
        });
    }
    Ok(ActivatedModule {
        module_id: record.module_id,
        version: record.version,
        digest: record.digest,
        signer_key_id: record.signer_key_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::registry::{IntegrityState, ModuleRecord};
    use std::time::SystemTime;

    fn record(module: &str, version: &str, runtime: &str) -> ModuleRecord {
        ModuleRecord {
            module_id: module.to_owned(),
            version: version.to_owned(),
            digest: ArtifactDigest::new([7u8; 32]),
            signer_key_id: "k1".to_owned(),
            runtime: runtime.to_owned(),
            manifest_version: 1,
            manifest_json: "{}".to_owned(),
            artifact_relpath: format!("{module}/{version}/pkg.zip"),
            artifact_size: 0,
            integrity_state: IntegrityState::Ok,
            registered_at: SystemTime::now(),
        }
    }

    #[test]
    fn empty_runtime_allowlist_rejected_at_construction() {
        assert!(matches!(
            ActivationPolicy::new(vec![]),
            Err(ActivationError::EmptyRuntimeAllowlist)
        ));
    }

    #[test]
    fn registered_module_activates_with_identity() {
        let registry = ModuleRegistry::new();
        registry
            .record(record("reporting", "1.2.0", "rust"))
            .expect("record");
        let policy = ActivationPolicy::new(vec!["rust".to_owned()]).expect("policy");
        let activated = activate(&registry, "reporting", "1.2.0", &policy).expect("activate");
        assert_eq!(activated.module_id, "reporting");
        assert_eq!(activated.version, "1.2.0");
        assert_eq!(activated.digest, ArtifactDigest::new([7u8; 32]));
        assert_eq!(activated.signer_key_id, "k1");
    }

    #[test]
    fn unregistered_version_never_activates() {
        let registry = ModuleRegistry::new();
        let policy = ActivationPolicy::new(vec!["rust".to_owned()]).expect("policy");
        let err = activate(&registry, "reporting", "1.2.0", &policy).unwrap_err();
        assert!(matches!(err, ActivationError::NotRegistered { .. }));
    }

    #[test]
    fn runtime_outside_allowlist_rejected() {
        let registry = ModuleRegistry::new();
        registry
            .record(record("reporting", "1.2.0", "python"))
            .expect("record");
        let policy = ActivationPolicy::new(vec!["rust".to_owned()]).expect("policy");
        let err = activate(&registry, "reporting", "1.2.0", &policy).unwrap_err();
        assert!(matches!(err, ActivationError::RuntimeNotAllowed { .. }));
    }
}
