use std::{fs, path::PathBuf, process::Command};

use serde_json::{Value, json};
use tempfile::tempdir;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name)
}

fn command(arguments: &[String]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_wisp"))
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("Wisp CLI should execute: {error}"))
}

fn json_output(output: &std::process::Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("CLI stdout should be JSON: {error}"))
}

#[test]
fn validate_accepts_a_valid_candidate() {
    let output =
        command(&["artifact".to_owned(), "validate".to_owned(), fixture("spec-valid.json").display().to_string()]);
    assert!(output.status.success());
    assert_eq!(json_output(&output), json!({"artifact_type":"spec@1", "id":"SPEC-001", "status":"validated"}));
}

#[test]
fn validate_rejects_schema_failures_as_json_errors() {
    for fixture_name in ["spec-unknown-property.json", "spec-missing-required.json"] {
        let output =
            command(&["artifact".to_owned(), "validate".to_owned(), fixture(fixture_name).display().to_string()]);
        assert!(!output.status.success());
        assert_eq!(json_output(&output), json!({"code":"schema_violation", "status":"error"}));
    }
}

#[test]
fn validate_rejects_malformed_json_as_a_json_error() {
    let output =
        command(&["artifact".to_owned(), "validate".to_owned(), fixture("spec-malformed.json").display().to_string()]);
    assert!(!output.status.success());
    assert_eq!(json_output(&output), json!({"code":"invalid_json", "status":"error"}));
}

#[test]
fn persist_get_and_status_use_the_canonical_path() {
    let workspace = tempdir().unwrap_or_else(|error| panic!("temp workspace: {error}"));
    let workspace = workspace.path().display().to_string();
    let persist = command(&[
        "artifact".to_owned(),
        "persist".to_owned(),
        fixture("spec-valid.json").display().to_string(),
        "--workspace".to_owned(),
        workspace.clone(),
    ]);
    assert!(persist.status.success());
    assert_eq!(json_output(&persist)["path"], "docs/specs/SPEC-001.json");

    let get = command(&[
        "artifact".to_owned(),
        "get".to_owned(),
        "SPEC-001".to_owned(),
        "--workspace".to_owned(),
        workspace.clone(),
    ]);
    assert!(get.status.success());
    assert_eq!(json_output(&get)["artifact"]["spec_file_path"], "docs/specs/SPEC-001.json");

    let status = command(&[
        "artifact".to_owned(),
        "status".to_owned(),
        "SPEC-001".to_owned(),
        "--workspace".to_owned(),
        workspace,
    ]);
    assert!(status.status.success());
    assert_eq!(json_output(&status)["status"], "uncommitted");
}

#[test]
fn status_reports_an_absent_artifact_without_failure() {
    let workspace = tempdir().unwrap_or_else(|error| panic!("temp workspace: {error}"));
    let output = command(&[
        "artifact".to_owned(),
        "status".to_owned(),
        "SPEC-404".to_owned(),
        "--workspace".to_owned(),
        workspace.path().display().to_string(),
    ]);
    assert!(output.status.success());
    assert_eq!(
        json_output(&output),
        json!({"artifact_type":"spec@1", "id":"SPEC-404", "path":"docs/specs/SPEC-404.json", "status":"absent"})
    );
}

#[test]
fn status_reports_clean_after_the_canonical_file_is_committed() {
    let workspace = tempdir().unwrap_or_else(|error| panic!("temp workspace: {error}"));
    let workspace_path = workspace.path();
    let workspace = workspace_path.display().to_string();
    let persist = command(&[
        "artifact".to_owned(),
        "persist".to_owned(),
        fixture("spec-valid.json").display().to_string(),
        "--workspace".to_owned(),
        workspace.clone(),
    ]);
    assert!(persist.status.success());

    let init = Command::new("git")
        .args(["init", "--quiet"])
        .current_dir(workspace_path)
        .status()
        .unwrap_or_else(|error| panic!("git should initialize fixture workspace: {error}"));
    assert!(init.success());
    let add = Command::new("git")
        .args(["add", "docs/specs/SPEC-001.json"])
        .current_dir(workspace_path)
        .status()
        .unwrap_or_else(|error| panic!("git should stage fixture artifact: {error}"));
    assert!(add.success());
    let commit = Command::new("git")
        .args([
            "-c",
            "user.name=Wisp Test",
            "-c",
            "user.email=wisp@example.test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ])
        .current_dir(workspace_path)
        .status()
        .unwrap_or_else(|error| panic!("git should commit fixture artifact: {error}"));
    assert!(commit.success());

    let status = command(&[
        "artifact".to_owned(),
        "status".to_owned(),
        "SPEC-001".to_owned(),
        "--workspace".to_owned(),
        workspace,
    ]);
    assert!(status.status.success());
    assert_eq!(json_output(&status)["status"], "clean");
}

fn handoff_workspace() -> tempfile::TempDir {
    let workspace = tempdir().unwrap_or_else(|error| panic!("temp workspace: {error}"));
    let root = workspace.path();
    fs::create_dir_all(root.join("docs/projects")).unwrap_or_else(|error| panic!("plan directory: {error}"));
    fs::create_dir_all(root.join("docs/specs")).unwrap_or_else(|error| panic!("spec directory: {error}"));
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    fs::copy(repo.join("docs/specs/WISP-004.json"), root.join("docs/specs/WISP-004.json"))
        .unwrap_or_else(|error| panic!("copy handoff spec: {error}"));
    fs::copy(repo.join("docs/projects/WISP-004.json"), root.join("docs/projects/WISP-004.json"))
        .unwrap_or_else(|error| panic!("copy handoff plan: {error}"));
    workspace
}

#[test]
fn implementation_brief_returns_one_schema_valid_success_document() {
    let workspace = handoff_workspace();
    let output = command(&[
        "brief".to_owned(),
        "implement".to_owned(),
        "--workspace".to_owned(),
        workspace.path().display().to_string(),
        "--plan".to_owned(),
        "docs/projects/WISP-004.json".to_owned(),
        "--task".to_owned(),
        "T1".to_owned(),
    ]);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert_eq!(output.stderr, Vec::<u8>::new());
    assert!(output.stdout.ends_with(b"\n"));
    assert!(!output.stdout[..output.stdout.len() - 1].contains(&b'\n'));
    let value = json_output(&output);
    assert_eq!(value["contract_id"], "implementation-context@1");
    assert_eq!(value["selection"]["task_ids"], json!(["T1"]));
    assert_eq!(value["status"], "ok");
    assert!(wisp_schema::validate_implementation_context(&value).is_ok());
}

#[test]
fn implementation_brief_returns_typed_errors_for_bad_selection_and_arguments() {
    let workspace = handoff_workspace();
    let common = [
        "brief".to_owned(),
        "implement".to_owned(),
        "--workspace".to_owned(),
        workspace.path().display().to_string(),
        "--plan".to_owned(),
        "docs/projects/WISP-004.json".to_owned(),
    ];
    for (selection, expected) in [
        (vec!["--task".to_owned(), "NOT-A-TASK".to_owned()], "invalid_selection"),
        (vec!["--batch".to_owned(), "B0".to_owned(), "--task".to_owned(), "T1".to_owned()], "invalid_input"),
        (vec!["--task".to_owned(), "T1".to_owned(), "--task".to_owned(), "T2".to_owned()], "invalid_input"),
        (vec!["--task".to_owned(), "T1".to_owned(), "--max-bytes".to_owned(), "255".to_owned()], "invalid_input"),
        (vec!["--task".to_owned(), "T1".to_owned(), "--max-bytes".to_owned(), "256".to_owned()], "budget_exceeded"),
        (vec![], "invalid_input"),
    ] {
        let mut args = common.to_vec();
        args.extend(selection);
        let output = command(&args);
        assert!(!output.status.success());
        assert_eq!(output.stderr, Vec::<u8>::new());
        let value = json_output(&output);
        assert_eq!(value["contract_id"], "implementation-context@1");
        assert_eq!(value["status"], "error");
        assert_eq!(value["error"]["code"], expected);
        assert!(wisp_schema::validate_implementation_context(&value).is_ok());
    }
}
