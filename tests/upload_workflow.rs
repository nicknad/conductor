//! Scaffold: upload workflow is not implemented yet.

use conductor::config::Config;

#[test]
fn upload_workflow_has_loopback_default() {
    assert!(Config::default().http_bind.starts_with("127.0.0.1:"));
}
