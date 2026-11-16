//! Canonical artifact path, persistence, and retrieval operations.

mod implementation_context;

pub use implementation_context::{ImplementationSelection, assemble_implementation_context};

use std::{fs, io::Write, process::Command};

use camino::{Utf8Path, Utf8PathBuf};
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use wisp_model::{ArtifactId, ArtifactRecord, ArtifactType, LocalArtifactState, PersistenceReceipt};
use wisp_schema::{
    Contract, SPEC_V1_SCHEMA_ID, SpecValidationError, validate_contract, validate_spec_json, validate_spec_value,
};

/// The first artifact operation is introduced in WISP-001 task T3.
pub const IMPLEMENTATION_STAGE: &str = "T3";

/// A revalidated canonical artifact discovered without modifying its workspace.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveredArtifact {
    /// Pinned contract used for validation.
    pub contract: Contract,
    /// Workspace-relative source path.
    pub path: Utf8PathBuf,
    /// Artifact identity, taken from `id` or the canonical filename stem.
    pub key: String,
    /// Revalidated JSON source.
    pub document: serde_json::Value,
}

/// A declared relationship between two canonical artifacts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactLink {
    /// Source artifact path.
    pub from: Utf8PathBuf,
    /// JSON field declaring the relationship.
    pub field: &'static str,
    /// Contract expected at the target.
    pub target_contract: Contract,
    /// Target artifact identity.
    pub target_key: String,
}

/// A graph validation finding; discovery continues after findings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphIssue {
    /// Artifact containing the invalid declaration.
    pub path: Utf8PathBuf,
    /// Relationship field when applicable.
    pub field: &'static str,
    /// Human-readable explanation.
    pub message: String,
}

/// Read-only canonical artifact graph and its non-fatal findings.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactGraph {
    /// Revalidated discovered nodes.
    pub artifacts: Vec<DiscoveredArtifact>,
    /// Resolved relationship declarations.
    pub links: Vec<ArtifactLink>,
    /// Invalid JSON/schema and missing-target findings.
    pub issues: Vec<GraphIssue>,
}

/// A deterministic, source-backed package for a requested artifact.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextPackage {
    /// Requested canonical artifact.
    pub root: DiscoveredArtifact,
    /// Root plus directly linked canonical artifacts, sorted by path.
    pub artifacts: Vec<DiscoveredArtifact>,
    /// Declared direct links from the root.
    pub links: Vec<ArtifactLink>,
    /// Discovery and link findings relevant to the package.
    pub issues: Vec<GraphIssue>,
    /// Bounded local Git evidence; unavailable rather than guessed outside Git.
    pub git: GitEvidence,
}

/// Read-only Git freshness evidence for a context package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GitEvidence {
    /// Git metadata was available.
    Available {
        /// Checked-out commit, if resolvable.
        head: String,
        /// Whether the worktree has local changes.
        dirty: bool,
    },
    /// The workspace is not a usable Git worktree or Git is unavailable.
    Unavailable {
        /// Stable reason code.
        reason: String,
    },
}

/// Errors from canonical artifact path, persistence, or retrieval operations.
#[derive(Debug, Error)]
pub enum ArtifactError {
    /// The candidate or stored artifact failed schema validation.
    #[error("spec validation failed: {source}")]
    Validation {
        /// The schema-layer cause.
        #[source]
        source: SpecValidationError,
    },
    /// A required filesystem operation failed.
    #[error("filesystem operation failed at {path}: {source}")]
    Filesystem {
        /// The relevant local path.
        path: Utf8PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// A candidate could not be deterministically serialized.
    #[error("could not serialize canonical spec JSON: {source}")]
    Serialization {
        /// The serialization cause.
        #[source]
        source: serde_json::Error,
    },
    /// No canonical artifact exists at the requested path.
    #[error("canonical artifact does not exist at {path}")]
    Absent {
        /// The canonical path that was not found.
        path: Utf8PathBuf,
    },
}

/// Discover and revalidate canonical workflow artifacts, then check their links.
///
/// This operation never writes to the workspace. Invalid documents and dangling
/// links become findings so one bad artifact does not hide independent evidence.
///
/// # Errors
///
/// Returns an error only when a required directory read fails unexpectedly.
#[allow(clippy::too_many_lines, reason = "discovery keeps filesystem traversal and graph-link validation together")]
pub fn discover_graph(workspace: &Utf8Path) -> Result<ArtifactGraph, ArtifactError> {
    let contracts = [
        Contract::RequirementV1,
        Contract::ResearchReportV1,
        Contract::SpecV1,
        Contract::PlanV1,
        Contract::ArchModelV2,
    ];
    let mut graph = ArtifactGraph { artifacts: Vec::new(), links: Vec::new(), issues: Vec::new() };
    for contract in contracts {
        let directory = workspace.join(contract.canonical_directory());
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(ArtifactError::Filesystem { path: directory, source });
            }
        };
        for entry in entries {
            let entry = entry.map_err(|source| ArtifactError::Filesystem { path: directory.clone(), source })?;
            let path = Utf8PathBuf::from_path_buf(entry.path()).map_err(|_| ArtifactError::Filesystem {
                path: directory.clone(),
                source: std::io::Error::other("non-UTF-8 artifact path"),
            })?;
            if path.extension() != Some("json") {
                continue;
            }
            let relative = path.strip_prefix(workspace).unwrap_or(&path).to_owned();
            let bytes = fs::read(&path).map_err(|source| ArtifactError::Filesystem { path: path.clone(), source })?;
            let document: serde_json::Value = match serde_json::from_slice(&bytes) {
                Ok(value) => value,
                Err(error) => {
                    graph.issues.push(GraphIssue { path: relative, field: "document", message: error.to_string() });
                    continue;
                }
            };
            if let Err(error) = validate_contract(contract, &document) {
                graph.issues.push(GraphIssue { path: relative, field: "document", message: error.to_string() });
                continue;
            }
            let key = document
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map_or_else(|| path.file_stem().unwrap_or_default().to_owned(), ToOwned::to_owned);
            graph.artifacts.push(DiscoveredArtifact { contract, path: relative, key, document });
        }
    }
    for artifact in &graph.artifacts {
        for (field, target_contract) in link_fields(artifact.contract) {
            if let Some(target_key) = artifact.document.get(field).and_then(serde_json::Value::as_str) {
                let link = ArtifactLink {
                    from: artifact.path.clone(),
                    field,
                    target_contract: *target_contract,
                    target_key: target_key.to_owned(),
                };
                if !graph.artifacts.iter().any(|target| target.contract == *target_contract && target.key == target_key)
                {
                    graph.issues.push(GraphIssue {
                        path: artifact.path.clone(),
                        field,
                        message: format!("missing {} target {target_key}", target_contract.id()),
                    });
                }
                graph.links.push(link);
            }
        }
    }
    Ok(graph)
}

/// Assemble a deterministic one-hop context package without modifying sources.
///
/// # Errors
///
/// Returns [`ArtifactError::Absent`] when the requested artifact is not in the
/// discovered canonical graph, or filesystem errors from discovery.
pub fn assemble_context(workspace: &Utf8Path, contract: Contract, key: &str) -> Result<ContextPackage, ArtifactError> {
    let graph = discover_graph(workspace)?;
    let root = graph
        .artifacts
        .iter()
        .find(|artifact| artifact.contract == contract && artifact.key == key)
        .cloned()
        .ok_or_else(|| ArtifactError::Absent {
            path: Utf8PathBuf::from(contract.canonical_directory()).join(format!("{key}.json")),
        })?;
    let links: Vec<_> = graph.links.iter().filter(|link| link.from == root.path).cloned().collect();
    let mut artifacts = vec![root.clone()];
    for link in &links {
        if let Some(target) = graph
            .artifacts
            .iter()
            .find(|artifact| artifact.contract == link.target_contract && artifact.key == link.target_key)
        {
            artifacts.push(target.clone());
        }
    }
    artifacts.sort_by(|left, right| left.path.cmp(&right.path));
    let issues = graph
        .issues
        .into_iter()
        .filter(|issue| issue.path == root.path || artifacts.iter().any(|artifact| artifact.path == issue.path))
        .collect();
    Ok(ContextPackage { root, artifacts, links, issues, git: git_evidence(workspace) })
}

fn git_evidence(workspace: &Utf8Path) -> GitEvidence {
    let head = Command::new("git").arg("-C").arg(workspace).args(["rev-parse", "HEAD"]).output();
    let Ok(head) = head else {
        return GitEvidence::Unavailable { reason: "git_unavailable".to_owned() };
    };
    if !head.status.success() {
        return GitEvidence::Unavailable { reason: "not_a_git_worktree".to_owned() };
    }
    let status = Command::new("git").arg("-C").arg(workspace).args(["status", "--porcelain=v1"]).output();
    let Ok(status) = status else {
        return GitEvidence::Unavailable { reason: "git_status_unavailable".to_owned() };
    };
    if !status.status.success() {
        return GitEvidence::Unavailable { reason: "git_status_unavailable".to_owned() };
    }
    GitEvidence::Available {
        head: String::from_utf8_lossy(&head.stdout).trim().to_owned(),
        dirty: !status.stdout.is_empty(),
    }
}

fn link_fields(contract: Contract) -> &'static [(&'static str, Contract)] {
    match contract {
        Contract::ResearchReportV1 => &[("linked_requirement", Contract::RequirementV1)],
        Contract::SpecV1 => {
            &[("linked_requirement", Contract::RequirementV1), ("linked_research", Contract::ResearchReportV1)]
        }
        Contract::PlanV1 => &[("linked_spec", Contract::SpecV1), ("linked_requirement", Contract::RequirementV1)],
        _ => &[],
    }
}

/// Resolve an ID to its only valid `spec@1` workspace-relative destination.
#[must_use]
pub fn spec_relative_path(id: &ArtifactId) -> Utf8PathBuf {
    Utf8PathBuf::from("docs").join("specs").join(format!("{}.json", id.as_str()))
}

/// Validate a candidate, atomically write its canonical JSON, and report final bytes.
///
/// # Errors
///
/// Returns an error without writing a canonical target when validation fails. Write
/// failures leave the old canonical target intact because the final rename occurs
/// only after a complete same-directory temporary file has been written.
pub fn persist_spec(workspace: &Utf8Path, candidate: &[u8]) -> Result<PersistenceReceipt, ArtifactError> {
    let mut validated = validate_spec_json(candidate).map_err(|source| ArtifactError::Validation { source })?;
    let relative_path = spec_relative_path(&validated.id);
    let target = workspace.join(&relative_path);

    let object = validated.value.as_object_mut().ok_or_else(|| ArtifactError::Validation {
        source: SpecValidationError::SchemaViolation {
            contract_id: SPEC_V1_SCHEMA_ID,
            message: "spec@1 accepted a non-object document".to_owned(),
        },
    })?;
    object.insert("spec_file_path".to_owned(), serde_json::Value::String(relative_path.to_string()));
    validated = validate_spec_value(validated.value).map_err(|source| ArtifactError::Validation { source })?;

    let parent = target.parent().ok_or_else(|| ArtifactError::Absent { path: target.clone() })?;
    fs::create_dir_all(parent).map_err(|source| ArtifactError::Filesystem { path: parent.to_owned(), source })?;

    let mut bytes =
        serde_json::to_vec_pretty(&validated.value).map_err(|source| ArtifactError::Serialization { source })?;
    bytes.push(b'\n');
    let mut temporary = NamedTempFile::new_in(parent)
        .map_err(|source| ArtifactError::Filesystem { path: parent.to_owned(), source })?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.flush())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|source| ArtifactError::Filesystem { path: target.clone(), source })?;
    temporary
        .persist(&target)
        .map_err(|error| ArtifactError::Filesystem { path: target.clone(), source: error.error })?;

    let final_bytes = fs::read(&target).map_err(|source| ArtifactError::Filesystem { path: target, source })?;
    Ok(PersistenceReceipt {
        id: validated.id,
        artifact_type: ArtifactType::SpecV1,
        path: relative_path.clone(),
        content_hash: sha256(&final_bytes),
        state: local_state(workspace, &relative_path),
    })
}

/// Load, revalidate, and describe a canonical `spec@1` artifact.
///
/// # Errors
///
/// Returns [`ArtifactError::Absent`] when no canonical file exists, or another
/// error when reading or revalidating an existing canonical file fails.
pub fn get_spec(workspace: &Utf8Path, id: &ArtifactId) -> Result<ArtifactRecord, ArtifactError> {
    let relative_path = spec_relative_path(id);
    let target = workspace.join(&relative_path);
    let bytes = match fs::read(&target) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            return Err(ArtifactError::Absent { path: relative_path });
        }
        Err(source) => {
            return Err(ArtifactError::Filesystem { path: target, source });
        }
    };
    let validated = validate_spec_json(&bytes).map_err(|source| ArtifactError::Validation { source })?;
    if &validated.id != id {
        return Err(ArtifactError::Validation {
            source: SpecValidationError::SchemaViolation {
                contract_id: SPEC_V1_SCHEMA_ID,
                message: "the canonical file ID does not match its requested path".to_owned(),
            },
        });
    }

    Ok(ArtifactRecord {
        id: validated.id,
        artifact_type: ArtifactType::SpecV1,
        path: relative_path.clone(),
        content_hash: sha256(&bytes),
        state: local_state(workspace, &relative_path),
        artifact: validated.value,
    })
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn local_state(workspace: &Utf8Path, relative_path: &Utf8Path) -> LocalArtifactState {
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(["status", "--porcelain=v1", "--untracked-files=all", "--"])
        .arg(relative_path)
        .output();
    match output {
        Ok(output) if output.status.success() && output.stdout.is_empty() => LocalArtifactState::Clean,
        _ => LocalArtifactState::Uncommitted,
    }
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use camino::Utf8Path;
    use serde_json::json;
    use tempfile::tempdir;
    use wisp_model::{ArtifactId, LocalArtifactState};
    use wisp_schema::Contract;

    use super::{ArtifactError, discover_graph, get_spec, persist_spec, spec_relative_path};

    fn candidate(id: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "id": id,
            "purpose": "Persist a portable test spec.",
            "scope": "The artifact crate tests.",
            "non_goals": ["Git commits."],
            "acceptance_criteria": [{
                "id": "AC-001",
                "criterion": "The test artifact persists."
            }]
        }))
        .unwrap_or_else(|error| panic!("test candidate must serialize: {error}"))
    }

    fn temp_workspace() -> tempfile::TempDir {
        tempdir().unwrap_or_else(|error| panic!("temp workspace: {error}"))
    }

    fn workspace_path(workspace: &tempfile::TempDir) -> &Utf8Path {
        Utf8Path::from_path(workspace.path()).unwrap_or_else(|| panic!("temp path must be UTF-8"))
    }

    fn git_status(workspace: &Utf8Path) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(workspace)
            .args(["status", "--porcelain=v1", "--untracked-files=all"])
            .output()
            .unwrap_or_else(|error| panic!("git status should run: {error}"));
        assert!(output.status.success(), "git status should succeed");
        String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("git status output is UTF-8: {error}"))
    }

    #[test]
    fn resolves_only_the_canonical_spec_path() {
        let id = ArtifactId::new("SPEC-001");
        assert!(matches!(id, Ok(id) if spec_relative_path(&id) == Utf8Path::new("docs/specs/SPEC-001.json")));
    }

    #[test]
    fn persists_and_retrieves_a_valid_spec_as_uncommitted() {
        let workspace = temp_workspace();
        let workspace = Utf8Path::from_path(workspace.path()).unwrap_or_else(|| panic!("temp path must be UTF-8"));

        let receipt = persist_spec(workspace, &candidate("SPEC-001"));
        assert!(
            matches!(receipt, Ok(receipt) if receipt.path == Utf8Path::new("docs/specs/SPEC-001.json") && receipt.content_hash.starts_with("sha256:"))
        );
        let id = ArtifactId::new("SPEC-001").unwrap_or_else(|error| panic!("valid ID: {error}"));
        let record = get_spec(workspace, &id);
        assert!(
            matches!(record, Ok(record) if record.state == LocalArtifactState::Uncommitted && record.artifact["spec_file_path"] == "docs/specs/SPEC-001.json")
        );
    }

    #[test]
    fn absent_lookup_reports_the_canonical_path() {
        let workspace = temp_workspace();
        let workspace = Utf8Path::from_path(workspace.path()).unwrap_or_else(|| panic!("temp path must be UTF-8"));
        let id = ArtifactId::new("SPEC-404").unwrap_or_else(|error| panic!("valid ID: {error}"));

        let result = get_spec(workspace, &id);
        assert!(
            matches!(result, Err(ArtifactError::Absent { path }) if path == Utf8Path::new("docs/specs/SPEC-404.json"))
        );
    }

    #[test]
    fn invalid_input_creates_no_canonical_target() {
        let workspace = temp_workspace();
        let workspace = Utf8Path::from_path(workspace.path()).unwrap_or_else(|| panic!("temp path must be UTF-8"));

        let result = persist_spec(workspace, br#"{"id":"SPEC-001""#);
        assert!(matches!(result, Err(ArtifactError::Validation { .. })));
        assert!(!workspace.join("docs/specs/SPEC-001.json").exists());
    }

    #[test]
    fn write_failure_creates_no_partial_canonical_target() {
        let workspace = temp_workspace();
        let workspace = Utf8Path::from_path(workspace.path()).unwrap_or_else(|| panic!("temp path must be UTF-8"));
        std::fs::write(workspace.join("docs"), "not a directory")
            .unwrap_or_else(|error| panic!("test setup should write: {error}"));

        let result = persist_spec(workspace, &candidate("SPEC-001"));
        assert!(matches!(result, Err(ArtifactError::Filesystem { .. })));
        assert!(!workspace.join("docs/specs/SPEC-001.json").exists());
    }

    #[test]
    fn discovers_legacy_architecture_model_once_with_v2_without_writing() {
        let workspace = temp_workspace();
        let workspace = workspace_path(&workspace);
        let directory = workspace.join("docs/architecture");
        std::fs::create_dir_all(&directory)
            .unwrap_or_else(|error| panic!("architecture directory should be created: {error}"));
        let model_path = directory.join("model.json");
        let model_bytes = include_bytes!("../../../docs/architecture/model.json");
        std::fs::write(&model_path, model_bytes)
            .unwrap_or_else(|error| panic!("legacy model fixture should be written: {error}"));
        let init = Command::new("git")
            .args(["init", "--quiet"])
            .current_dir(workspace)
            .status()
            .unwrap_or_else(|error| panic!("git should initialize fixture workspace: {error}"));
        assert!(init.success(), "git init should succeed");
        let status_before = git_status(workspace);

        let graph = discover_graph(workspace).unwrap_or_else(|error| panic!("graph discovery should succeed: {error}"));
        assert_eq!(graph.artifacts.len(), 1);
        assert_eq!(graph.artifacts[0].contract, Contract::ArchModelV2);
        assert_eq!(graph.artifacts[0].path, Utf8Path::new("docs/architecture/model.json"));
        assert_eq!(
            std::fs::read(&model_path).unwrap_or_else(|error| panic!("model should remain readable: {error}")),
            model_bytes
        );
        assert_eq!(git_status(workspace), status_before);
    }

    #[test]
    fn discovers_architecture_model_with_decision_reference_once() {
        let workspace = temp_workspace();
        let workspace = workspace_path(&workspace);
        let directory = workspace.join("docs/architecture");
        std::fs::create_dir_all(&directory)
            .unwrap_or_else(|error| panic!("architecture directory should be created: {error}"));
        let mut model: serde_json::Value = serde_json::from_str(include_str!("../../../docs/architecture/model.json"))
            .unwrap_or_else(|error| panic!("architecture model fixture is valid JSON: {error}"));
        model["invariants"][0]["decision_ref"] = json!("docs/adr/example.md");
        std::fs::write(
            directory.join("model.json"),
            serde_json::to_vec(&model).unwrap_or_else(|error| panic!("updated fixture should serialize: {error}")),
        )
        .unwrap_or_else(|error| panic!("architecture model should be written: {error}"));

        let graph = discover_graph(workspace).unwrap_or_else(|error| panic!("graph discovery should succeed: {error}"));
        assert_eq!(graph.artifacts.len(), 1);
        assert_eq!(graph.artifacts[0].contract, Contract::ArchModelV2);
    }

    #[test]
    fn invalid_architecture_model_is_reported_without_hiding_other_artifacts() {
        let workspace = temp_workspace();
        let workspace = workspace_path(&workspace);
        let architecture = workspace.join("docs/architecture");
        let requirements = workspace.join("docs/requirements");
        std::fs::create_dir_all(&architecture)
            .unwrap_or_else(|error| panic!("architecture directory should be created: {error}"));
        std::fs::create_dir_all(&requirements)
            .unwrap_or_else(|error| panic!("requirements directory should be created: {error}"));
        std::fs::write(architecture.join("model.json"), br#"{"id":"broken"}"#)
            .unwrap_or_else(|error| panic!("invalid model fixture should be written: {error}"));
        std::fs::write(
            requirements.join("REQ-WISP-002.json"),
            include_bytes!("../../../docs/requirements/REQ-WISP-002.json"),
        )
        .unwrap_or_else(|error| panic!("requirement fixture should be written: {error}"));

        let graph =
            discover_graph(workspace).unwrap_or_else(|error| panic!("graph discovery should continue: {error}"));
        assert_eq!(graph.artifacts.len(), 1);
        assert_eq!(graph.artifacts[0].contract, Contract::RequirementV1);
        assert_eq!(graph.issues.len(), 1);
        assert_eq!(graph.issues[0].path, Utf8Path::new("docs/architecture/model.json"));
        assert_eq!(graph.issues[0].field, "document");
    }

    #[test]
    fn malformed_architecture_model_is_reported_as_a_document_issue() {
        let workspace = temp_workspace();
        let workspace = workspace_path(&workspace);
        let architecture = workspace.join("docs/architecture");
        std::fs::create_dir_all(&architecture)
            .unwrap_or_else(|error| panic!("architecture directory should be created: {error}"));
        std::fs::write(architecture.join("model.json"), b"{")
            .unwrap_or_else(|error| panic!("malformed model fixture should be written: {error}"));

        let graph =
            discover_graph(workspace).unwrap_or_else(|error| panic!("graph discovery should continue: {error}"));
        assert_eq!(graph.artifacts, Vec::<crate::DiscoveredArtifact>::new());
        assert_eq!(graph.issues.len(), 1);
        assert_eq!(graph.issues[0].path, Utf8Path::new("docs/architecture/model.json"));
        assert_eq!(graph.issues[0].field, "document");
    }
}
