//! Stable domain contracts shared by Wisp layers.

use camino::Utf8PathBuf;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A safe, portable identifier used to derive an artifact's canonical path.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ArtifactId(String);

impl ArtifactId {
    /// Creates an identifier after rejecting empty and path-like values.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactIdError`] when `value` is empty or could alter the
    /// canonical artifact path.
    pub fn new(value: impl Into<String>) -> Result<Self, ArtifactIdError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ArtifactIdError::Empty);
        }
        if value.contains('/') || value.contains('\\') || value == "." || value == ".." {
            return Err(ArtifactIdError::Unsafe { value });
        }
        Ok(Self(value))
    }

    /// Returns the identifier as an immutable string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Failure returned when a value cannot safely become an [`ArtifactId`].
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum ArtifactIdError {
    /// The caller supplied no identifier.
    #[error("artifact identifier must not be empty")]
    Empty,
    /// The caller supplied a value that could escape a canonical artifact path.
    #[error("artifact identifier is not path-safe: {value}")]
    Unsafe {
        /// The rejected value.
        value: String,
    },
}

/// The artifact type implemented by WISP-001.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum ArtifactType {
    /// A version-one implementation specification.
    #[serde(rename = "spec@1")]
    SpecV1,
}

/// Local durability state of a canonical artifact file.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalArtifactState {
    /// No canonical artifact exists at the resolved path.
    Absent,
    /// The canonical artifact differs from the local Git index.
    Uncommitted,
    /// The canonical artifact exists and is clean in the local Git worktree.
    Clean,
}

/// Canonical metadata returned after artifact persistence or retrieval.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArtifactRecord {
    /// Artifact identity used for canonical path resolution.
    pub id: ArtifactId,
    /// Implemented artifact contract.
    pub artifact_type: ArtifactType,
    /// Workspace-relative canonical artifact path.
    pub path: Utf8PathBuf,
    /// SHA-256 over the canonical file's final raw bytes.
    pub content_hash: String,
    /// Local durability state.
    pub state: LocalArtifactState,
    /// Parsed, revalidated canonical JSON when the artifact is present.
    pub artifact: serde_json::Value,
}

/// Evidence that a canonical artifact was durably written to the local worktree.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PersistenceReceipt {
    /// Artifact identity used for canonical path resolution.
    pub id: ArtifactId,
    /// Implemented artifact contract.
    pub artifact_type: ArtifactType,
    /// Workspace-relative canonical artifact path.
    pub path: Utf8PathBuf,
    /// SHA-256 over the final raw bytes at `path`.
    pub content_hash: String,
    /// The file is written but intentionally not committed by Wisp.
    pub state: LocalArtifactState,
}

/// Successful, artifact-only context assembled for one explicit plan selection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImplementationContext {
    /// Stable wire-contract identity.
    pub contract_id: String,
    /// Success discriminator.
    pub status: ContextSuccessStatus,
    /// Exact caller selection and resolved IDs.
    pub selection: ContextSelection,
    /// Raw-byte identities of the governing artifacts.
    pub sources: ContextSources,
    /// Relevant top-level plan context.
    pub plan_context: PlanContext,
    /// Relevant governing spec context.
    pub spec_context: SpecContext,
    /// Selected tasks in plan order.
    pub tasks: Vec<ImplementationTask>,
    /// Referenced acceptance criteria in spec order.
    pub criteria: Vec<ContextCriterion>,
    /// Successful mechanical checks.
    pub checks: Vec<ContextCheck>,
    /// Known gaps; declarations do not imply completion or code coverage.
    pub gaps: Vec<ContextGap>,
    /// Evidence boundary for this result.
    pub evidence_scope: String,
    /// Maximum serialized success response size, including its newline.
    pub output_limit_bytes: usize,
}

/// Typed, versioned failure returned instead of a partial context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImplementationContextFailure {
    /// Stable wire-contract identity.
    pub contract_id: String,
    /// Failure discriminator.
    pub status: ContextFailureStatus,
    /// Machine-readable failure details.
    pub error: ContextError,
}

/// Rust-native failure from assembling an implementation context.
///
/// Transport adapters map this error to their wire contract so library callers
/// do not receive a transport envelope.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{message}")]
pub struct ImplementationContextError {
    /// Stable failure category used when adapting this error to the wire contract.
    pub code: ContextErrorCode,
    /// Check that failed.
    pub check: String,
    /// Workspace-relative source path when known.
    pub path: Option<Utf8PathBuf>,
    /// Concise diagnostic without copied source contents.
    pub message: String,
}

/// The only valid success discriminator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ContextSuccessStatus {
    /// The selected context is complete and fits the requested output limit.
    #[serde(rename = "ok")]
    Ok,
}

/// The only valid failure discriminator.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ContextFailureStatus {
    /// A required check failed; no partial context is included.
    #[serde(rename = "error")]
    Error,
}

/// Failure code and source location for implementation-context assembly.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextError {
    /// Stable failure category.
    pub code: ContextErrorCode,
    /// Check that failed.
    pub check: String,
    /// Workspace-relative source path when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Utf8PathBuf>,
    /// Concise diagnostic without copied source contents.
    pub message: String,
}

/// Stable machine-readable implementation-context failure categories.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextErrorCode {
    /// Required arguments or selection values are invalid.
    InvalidInput,
    /// A path is absolute, traverses upward, or escapes the workspace.
    UnsafePath,
    /// A required plan or spec source is absent.
    MissingSource,
    /// A required artifact is not valid JSON.
    InvalidJson,
    /// A source does not satisfy its pinned schema.
    SchemaViolation,
    /// Plan/spec identities or paths disagree.
    LinkMismatch,
    /// The current spec bytes differ from the plan's recorded hash.
    SpecDrift,
    /// A selected task, batch, dependency, or criterion reference is invalid.
    InvalidSelection,
    /// Input bytes changed during assembly.
    InputsChanged,
    /// A required source or successful result exceeds its byte limit.
    BudgetExceeded,
    /// A required filesystem operation failed.
    FilesystemError,
}

/// The explicit selection requested by a caller.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextSelection {
    /// Whether the caller selected a declared batch or one task.
    pub mode: ContextSelectionMode,
    /// Exact batch or task identifier supplied by the caller.
    pub id: String,
    /// Resolved task identifiers in plan order.
    pub task_ids: Vec<String>,
    /// Resolved criterion identifiers in spec order.
    pub criterion_ids: Vec<String>,
}

/// Selector kind accepted by the implementation-context operation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextSelectionMode {
    /// Select all tasks declared in one plan batch.
    Batch,
    /// Select one declared task.
    Task,
}

/// Raw-byte source identity for a pinned plan or spec.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextSource {
    /// Workspace-relative path.
    pub path: Utf8PathBuf,
    /// Pinned schema identity.
    pub schema_id: String,
    /// SHA-256 digest over source bytes.
    pub sha256: String,
}

/// Plan and governing-spec source identities.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextSources {
    /// Selected plan source.
    pub plan: ContextSource,
    /// Governing spec source.
    pub spec: ContextSource,
}

/// Small plan-level context retained with the selected tasks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PlanContext {
    /// Plan goal.
    pub goal: String,
    /// Declared implementation architecture.
    pub architecture: String,
}

/// Governing spec fields needed to interpret selected criteria.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpecContext {
    /// Spec identifier.
    pub id: String,
    /// Purpose statement.
    pub purpose: String,
    /// Scope statement.
    pub scope: String,
    /// Explicit non-goals.
    pub non_goals: Vec<String>,
    /// Declared public API surface, when present in the source spec.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_surface: Option<Vec<SpecApiEntry>>,
}

/// One declared API entry from a spec.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SpecApiEntry {
    /// API name.
    pub name: String,
    /// Declared signature.
    pub signature: String,
    /// API purpose and behavior.
    pub description: String,
    /// Known failure conditions, when declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_conditions: Option<Vec<String>>,
}

/// Exact selected task fields projected from plan@1.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ImplementationTask {
    /// Task identifier.
    pub id: String,
    /// Task title.
    pub title: String,
    /// Authored file declarations.
    pub files: DeclaredFiles,
    /// Authored ordered implementation steps.
    pub steps: Vec<String>,
    /// Authored commit message.
    pub commit_message: String,
    /// Declared prerequisite task IDs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depends_on: Option<Vec<String>>,
    /// Acceptance criteria this task claims to cover.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub covers_criteria: Option<Vec<String>>,
}

/// File paths declared by a selected plan task.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DeclaredFiles {
    /// Paths expected to be created by the task.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create: Option<Vec<String>>,
    /// Paths expected to exist and be changed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modify: Option<Vec<String>>,
    /// Paths expected to provide verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test: Option<Vec<String>>,
}

/// One exact criterion referenced by the selected tasks.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextCriterion {
    /// Criterion identifier.
    pub id: String,
    /// Authored criterion text.
    pub criterion: String,
    /// Whether the criterion covers an error case, when specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_error_case: Option<bool>,
    /// Whether human judgment is required, when specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judgment_call: Option<bool>,
    /// Rationale for a judgment criterion, when specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

/// A mechanical validation that passed before context was returned.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextCheck {
    /// Stable validation check identifier.
    pub id: ContextCheckId,
    /// Passing outcome.
    pub result: ContextCheckResult,
}

/// Validation stages represented in successful context results.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextCheckId {
    /// The selected plan satisfies plan@1.
    PlanSchema,
    /// The governing spec satisfies spec@1.
    SpecSchema,
    /// Declared paths and artifact identities agree.
    SourceLinks,
    /// Plan's raw-byte spec hash matches the current spec.
    SpecHash,
    /// Batch/task and criterion mappings resolve uniquely.
    Selection,
    /// Inputs match when re-read before publication.
    InputStability,
}

/// Successful mechanical check result.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextCheckResult {
    /// The named check completed successfully.
    Passed,
}

/// A known limitation or unverified declaration in a successful context.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextGap {
    /// Stable gap category.
    pub kind: ContextGapKind,
    /// Concise explanation.
    pub finding: String,
    /// Task associated with the gap, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_id: Option<String>,
    /// Workspace-relative path associated with the gap, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<Utf8PathBuf>,
}

/// Supported gap categories for implementation-context@1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextGapKind {
    /// A declared modify target is absent.
    MissingModifyTarget,
    /// A declared test target is absent.
    MissingTestTarget,
    /// Dependency completion is outside the artifact-only check.
    DependencyCompletionUnverified,
}

#[cfg(test)]
mod tests {
    use super::{ArtifactId, ArtifactIdError};

    #[test]
    fn accepts_a_simple_identifier() {
        let id = ArtifactId::new("SPEC-001");
        assert!(matches!(id, Ok(value) if value.as_str() == "SPEC-001"));
    }

    #[test]
    fn rejects_empty_identifier() {
        assert_eq!(ArtifactId::new(""), Err(ArtifactIdError::Empty));
    }

    #[test]
    fn rejects_path_like_identifier() {
        assert!(matches!(ArtifactId::new("../SPEC-001"), Err(ArtifactIdError::Unsafe { .. })));
    }

    #[test]
    fn implementation_context_error_implements_the_rust_error_trait() {
        fn assert_error<T: std::error::Error>() {}
        assert_error::<super::ImplementationContextError>();
    }
}
