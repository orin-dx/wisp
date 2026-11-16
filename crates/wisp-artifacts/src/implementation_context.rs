//! Selected plan/spec assembly without graph discovery or Git inspection.

use std::{
    collections::HashSet,
    fs, io,
    io::Read,
    path::{Component, Path},
};

use camino::{Utf8Path, Utf8PathBuf};
use serde::Deserialize;
use serde_json::Value;
use wisp_model::{
    ContextCheck, ContextCheckId, ContextCheckResult, ContextErrorCode, ContextGap, ContextGapKind, ContextSelection,
    ContextSelectionMode, ContextSource, ContextSources, ContextSuccessStatus, ImplementationContext,
    ImplementationContextError, ImplementationTask, PlanContext, SpecContext,
};
use wisp_schema::{Contract, SpecValidationError, validate_contract, validate_implementation_context};

const CONTEXT_CONTRACT_ID: &str = "implementation-context@1";
const MAX_SOURCE_BYTES: usize = 1_048_576;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ImplementationSelection {
    /// Select a declared plan batch.
    Batch(String),
    /// Select one declared task.
    Task(String),
}

/// Assemble an artifact-only handoff for one explicit task or batch.
///
/// The operation reads only the plan, its linked spec, and metadata for
/// declared paths. It never traverses the artifact graph or invokes Git.
///
/// # Errors
///
/// Returns a typed Rust error when a required source, link, selector, path,
/// stability check, or output limit is invalid.
pub fn assemble_implementation_context(
    workspace: &Utf8Path,
    plan_path: &Utf8Path,
    selection: ImplementationSelection,
    output_limit_bytes: usize,
) -> Result<ImplementationContext, ImplementationContextError> {
    assemble_with_reader(workspace, plan_path, selection, output_limit_bytes, read_source_file)
}

fn assemble_with_reader<F>(
    workspace: &Utf8Path,
    plan_path: &Utf8Path,
    selection: ImplementationSelection,
    output_limit_bytes: usize,
    mut read: F,
) -> Result<ImplementationContext, ImplementationContextError>
where
    F: FnMut(&Utf8Path) -> io::Result<Vec<u8>>,
{
    let (selection_mode, selection_id) = match selection {
        ImplementationSelection::Batch(id) => (ContextSelectionMode::Batch, id),
        ImplementationSelection::Task(id) => (ContextSelectionMode::Task, id),
    };
    if !(256..=1_048_576).contains(&output_limit_bytes) {
        return Err(failure(
            ContextErrorCode::InvalidInput,
            "output_limit",
            None,
            "output limit must be between 256 and 1048576 bytes",
        ));
    }
    if selection_id.is_empty() {
        return Err(failure(ContextErrorCode::InvalidInput, "selection", None, "selection ID must not be empty"));
    }

    let (root, plan_file, plan_bytes, plan) = load_plan(workspace, plan_path, &mut read)?;

    let declared_plan_path = required_relative(plan.plan_file_path.as_deref(), "plan_file_path", &plan_file.relative)?;
    let declared_plan = resolve_existing(&root, &declared_plan_path, "plan_file_path")?;
    if declared_plan.absolute != plan_file.absolute {
        return Err(failure(
            ContextErrorCode::LinkMismatch,
            "plan_file_path",
            Some(plan_file.relative.clone()),
            "plan_file_path does not identify the selected plan",
        ));
    }

    let plan_spec_path = required_relative(plan.spec_file_path.as_deref(), "spec_file_path", &plan_file.relative)?;
    let spec_file = resolve_existing(&root, &plan_spec_path, "spec_file_path")?;
    let spec_bytes = read_source(&mut read, &spec_file, "spec_read", "spec_source_size")?;
    let spec_value = parse_json(&spec_bytes, "spec_json", &spec_file.relative)?;
    validate_artifact(Contract::SpecV1, &spec_value, &spec_file.relative)?;
    let spec: SpecDocument = serde_json::from_value(spec_value).map_err(|_| {
        failure(
            ContextErrorCode::SchemaViolation,
            "spec_decode",
            Some(spec_file.relative.clone()),
            "spec fields could not be decoded",
        )
    })?;

    if plan.linked_spec.as_deref() != Some(spec.id.as_str()) {
        return Err(failure(
            ContextErrorCode::LinkMismatch,
            "linked_spec",
            Some(plan_file.relative.clone()),
            "plan linked_spec does not match the selected spec ID",
        ));
    }
    if plan.spec_hash.as_deref().is_none_or(|hash| !valid_sha256(hash)) {
        return Err(failure(
            ContextErrorCode::LinkMismatch,
            "spec_hash_format",
            Some(plan_file.relative.clone()),
            "plan spec_hash must use sha256: followed by 64 lowercase hexadecimal digits",
        ));
    }
    if plan.spec_hash.as_deref() != Some(super::sha256(&spec_bytes).as_str()) {
        return Err(failure(
            ContextErrorCode::SpecDrift,
            "spec_hash",
            Some(spec_file.relative.clone()),
            "current spec bytes differ from the plan's recorded hash",
        ));
    }

    let declared_spec_in_spec =
        required_relative(spec.spec_file_path.as_deref(), "spec_file_path", &spec_file.relative)?;
    let declared_spec = resolve_existing(&root, &declared_spec_in_spec, "spec_file_path")?;
    if declared_spec.absolute != spec_file.absolute {
        return Err(failure(
            ContextErrorCode::LinkMismatch,
            "spec_file_path",
            Some(spec_file.relative.clone()),
            "spec spec_file_path does not identify the selected spec",
        ));
    }

    let tasks_and_criteria = select_tasks(&plan, &spec, selection_mode, &selection_id, &root, &plan_file.relative)?;
    let mut gaps = tasks_and_criteria.gaps;

    let plan_again = read_source(&mut read, &plan_file, "plan_stability", "plan_source_size")?;
    let spec_again = read_source(&mut read, &spec_file, "spec_stability", "spec_source_size")?;
    if plan_again != plan_bytes || spec_again != spec_bytes {
        return Err(failure(
            ContextErrorCode::InputsChanged,
            "input_stability",
            None,
            "plan or spec bytes changed during context assembly",
        ));
    }

    let result = ImplementationContext {
        contract_id: CONTEXT_CONTRACT_ID.to_owned(),
        status: ContextSuccessStatus::Ok,
        selection: ContextSelection {
            mode: selection_mode,
            id: selection_id,
            task_ids: tasks_and_criteria.task_ids,
            criterion_ids: tasks_and_criteria.criteria.iter().map(|criterion| criterion.id.clone()).collect(),
        },
        sources: ContextSources {
            plan: ContextSource {
                path: plan_file.relative,
                schema_id: Contract::PlanV1.id().to_owned(),
                sha256: super::sha256(&plan_bytes),
            },
            spec: ContextSource {
                path: spec_file.relative,
                schema_id: Contract::SpecV1.id().to_owned(),
                sha256: super::sha256(&spec_bytes),
            },
        },
        plan_context: PlanContext { goal: plan.goal, architecture: plan.architecture },
        spec_context: SpecContext {
            id: spec.id,
            purpose: spec.purpose,
            scope: spec.scope,
            non_goals: spec.non_goals,
            api_surface: spec.api_surface,
        },
        tasks: tasks_and_criteria.tasks,
        criteria: tasks_and_criteria.criteria,
        checks: passed_checks(),
        gaps: std::mem::take(&mut gaps),
        evidence_scope: "artifacts_only".to_owned(),
        output_limit_bytes,
    };

    let value = serde_json::to_value(&result).map_err(|_| {
        failure(ContextErrorCode::SchemaViolation, "result_encode", None, "result could not be serialized")
    })?;
    validate_implementation_context(&value).map_err(|_| {
        failure(
            ContextErrorCode::SchemaViolation,
            "result_schema",
            None,
            "assembled result violates implementation-context@1",
        )
    })?;
    let serialized = serde_json::to_vec(&value).map_err(|_| {
        failure(ContextErrorCode::SchemaViolation, "result_encode", None, "result could not be serialized")
    })?;
    if serialized.len().saturating_add(1) > output_limit_bytes {
        return Err(failure(
            ContextErrorCode::BudgetExceeded,
            "output_limit",
            None,
            "required implementation context exceeds the output-byte limit",
        ));
    }
    Ok(result)
}

fn load_plan<F>(
    workspace: &Utf8Path,
    plan_path: &Utf8Path,
    read: &mut F,
) -> Result<(Utf8PathBuf, ResolvedPath, Vec<u8>, PlanDocument), ImplementationContextError>
where
    F: FnMut(&Utf8Path) -> io::Result<Vec<u8>>,
{
    let root = fs::canonicalize(workspace).map_err(|error| {
        failure(
            ContextErrorCode::InvalidInput,
            "workspace",
            None,
            if error.kind() == io::ErrorKind::NotFound {
                "workspace does not exist"
            } else {
                "workspace cannot be resolved"
            },
        )
    })?;
    let root = Utf8PathBuf::from_path_buf(root)
        .map_err(|_| failure(ContextErrorCode::UnsafePath, "workspace", None, "workspace path is not valid UTF-8"))?;
    let plan_relative = safe_relative_path(plan_path.as_str(), "plan_path")?;
    let plan_file = resolve_existing(&root, &plan_relative, "plan_path")?;
    let plan_bytes = read_source(read, &plan_file, "plan_read", "plan_source_size")?;
    let plan_value = parse_json(&plan_bytes, "plan_json", &plan_file.relative)?;
    validate_artifact(Contract::PlanV1, &plan_value, &plan_file.relative)?;
    let plan = serde_json::from_value(plan_value).map_err(|_| {
        failure(
            ContextErrorCode::SchemaViolation,
            "plan_decode",
            Some(plan_file.relative.clone()),
            "plan fields could not be decoded",
        )
    })?;
    Ok((root, plan_file, plan_bytes, plan))
}

#[derive(Debug, Deserialize)]
struct PlanDocument {
    goal: String,
    architecture: String,
    tasks: Vec<PlanTask>,
    batches: Option<Vec<PlanBatch>>,
    linked_spec: Option<String>,
    spec_file_path: Option<String>,
    plan_file_path: Option<String>,
    spec_hash: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PlanTask {
    id: String,
    title: String,
    files: wisp_model::DeclaredFiles,
    steps: Vec<String>,
    commit_message: String,
    depends_on: Option<Vec<String>>,
    covers_criteria: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct PlanBatch {
    batch_id: String,
    task_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SpecDocument {
    id: String,
    purpose: String,
    scope: String,
    non_goals: Vec<String>,
    api_surface: Option<Vec<wisp_model::SpecApiEntry>>,
    spec_file_path: Option<String>,
    acceptance_criteria: Vec<wisp_model::ContextCriterion>,
}

struct SelectedTasks {
    task_ids: Vec<String>,
    tasks: Vec<ImplementationTask>,
    criteria: Vec<wisp_model::ContextCriterion>,
    gaps: Vec<ContextGap>,
}

struct ResolvedPath {
    absolute: Utf8PathBuf,
    relative: Utf8PathBuf,
}

// Keep selector, mapping, dependency, and file-declaration checks in one ordered pass.
#[allow(clippy::too_many_lines)]
fn select_tasks(
    plan: &PlanDocument,
    spec: &SpecDocument,
    selection_mode: ContextSelectionMode,
    selection_id: &str,
    root: &Utf8Path,
    plan_relative: &Utf8Path,
) -> Result<SelectedTasks, ImplementationContextError> {
    let mut task_ids = HashSet::new();
    for task in &plan.tasks {
        if task.id.is_empty() || !task_ids.insert(task.id.as_str()) {
            return Err(failure(
                ContextErrorCode::InvalidSelection,
                "task_identity",
                Some(plan_relative.to_owned()),
                "plan task IDs must be nonempty and unique",
            ));
        }
    }
    let mut criterion_ids = HashSet::new();
    for criterion in &spec.acceptance_criteria {
        if criterion.id.is_empty() || !criterion_ids.insert(criterion.id.as_str()) {
            return Err(failure(
                ContextErrorCode::InvalidSelection,
                "criterion_identity",
                None,
                "spec criterion IDs must be nonempty and unique",
            ));
        }
    }

    let selected_ids = match selection_mode {
        ContextSelectionMode::Task => {
            if !task_ids.contains(selection_id) {
                return Err(failure(
                    ContextErrorCode::InvalidSelection,
                    "task_selection",
                    Some(plan_relative.to_owned()),
                    "selected task ID is not declared in the plan",
                ));
            }
            HashSet::from([selection_id])
        }
        ContextSelectionMode::Batch => {
            let batches = plan.batches.as_ref().ok_or_else(|| {
                failure(
                    ContextErrorCode::InvalidSelection,
                    "batch_selection",
                    Some(plan_relative.to_owned()),
                    "plan does not declare batches",
                )
            })?;
            let mut batch_ids = HashSet::new();
            if batches.iter().any(|batch| batch.batch_id.is_empty() || !batch_ids.insert(batch.batch_id.as_str())) {
                return Err(failure(
                    ContextErrorCode::InvalidSelection,
                    "batch_identity",
                    Some(plan_relative.to_owned()),
                    "plan batch IDs must be nonempty and unique",
                ));
            }
            let batch = batches.iter().find(|batch| batch.batch_id == selection_id).ok_or_else(|| {
                failure(
                    ContextErrorCode::InvalidSelection,
                    "batch_selection",
                    Some(plan_relative.to_owned()),
                    "selected batch ID is not declared in the plan",
                )
            })?;
            let mut members = HashSet::new();
            if batch.task_ids.is_empty()
                || batch.task_ids.iter().any(|id| !task_ids.contains(id.as_str()) || !members.insert(id.as_str()))
            {
                return Err(failure(
                    ContextErrorCode::InvalidSelection,
                    "batch_membership",
                    Some(plan_relative.to_owned()),
                    "batch task IDs must exist and be unique",
                ));
            }
            members
        }
    };

    let mut referenced_criteria = HashSet::new();
    let mut selected_tasks = Vec::new();
    let mut gaps = Vec::new();
    for task in &plan.tasks {
        if !selected_ids.contains(task.id.as_str()) {
            continue;
        }
        let mapped = task.covers_criteria.as_ref().ok_or_else(|| {
            failure(
                ContextErrorCode::InvalidSelection,
                "criterion_mapping",
                Some(plan_relative.to_owned()),
                "selected task does not declare covers_criteria",
            )
        })?;
        let mut local_criteria = HashSet::new();
        if mapped
            .iter()
            .any(|id| id.is_empty() || !criterion_ids.contains(id.as_str()) || !local_criteria.insert(id.as_str()))
        {
            return Err(failure(
                ContextErrorCode::InvalidSelection,
                "criterion_mapping",
                Some(plan_relative.to_owned()),
                "selected task criterion mappings must be known and unique",
            ));
        }
        referenced_criteria.extend(mapped.iter().map(String::as_str));

        let dependencies = task.depends_on.as_deref().unwrap_or_default();
        let mut local_dependencies = HashSet::new();
        if dependencies
            .iter()
            .any(|id| !task_ids.contains(id.as_str()) || id == &task.id || !local_dependencies.insert(id.as_str()))
        {
            return Err(failure(
                ContextErrorCode::InvalidSelection,
                "dependency_mapping",
                Some(plan_relative.to_owned()),
                "task dependencies must refer to distinct declared tasks",
            ));
        }
        for dependency in dependencies {
            gaps.push(ContextGap {
                kind: ContextGapKind::DependencyCompletionUnverified,
                finding: format!("Completion of declared dependency {dependency} was not checked."),
                task_id: Some(task.id.clone()),
                path: None,
            });
        }

        validate_file_declarations(root, task, &mut gaps, plan_relative)?;
        selected_tasks.push(ImplementationTask {
            id: task.id.clone(),
            title: task.title.clone(),
            files: task.files.clone(),
            steps: task.steps.clone(),
            commit_message: task.commit_message.clone(),
            depends_on: task.depends_on.clone(),
            covers_criteria: task.covers_criteria.clone(),
        });
    }
    if selected_tasks.len() != selected_ids.len() {
        return Err(failure(
            ContextErrorCode::InvalidSelection,
            "selection_resolution",
            Some(plan_relative.to_owned()),
            "selected task set did not resolve uniquely",
        ));
    }
    let criteria = spec
        .acceptance_criteria
        .iter()
        .filter(|criterion| referenced_criteria.contains(criterion.id.as_str()))
        .cloned()
        .collect();
    Ok(SelectedTasks {
        task_ids: selected_tasks.iter().map(|task| task.id.clone()).collect(),
        tasks: selected_tasks,
        criteria,
        gaps,
    })
}

fn validate_file_declarations(
    root: &Utf8Path,
    task: &PlanTask,
    gaps: &mut Vec<ContextGap>,
    plan_relative: &Utf8Path,
) -> Result<(), ImplementationContextError> {
    for (paths, gap_kind) in [
        (task.files.create.as_deref().unwrap_or_default(), None),
        (task.files.modify.as_deref().unwrap_or_default(), Some(ContextGapKind::MissingModifyTarget)),
        (task.files.test.as_deref().unwrap_or_default(), Some(ContextGapKind::MissingTestTarget)),
    ] {
        for path in paths {
            let relative = safe_relative_path(path, "declared_file")?;
            match resolve_declared(root, &relative) {
                Ok(true) => {}
                Ok(false) => {
                    if let Some(kind) = gap_kind {
                        gaps.push(ContextGap {
                            kind,
                            finding: "Declared target is absent.".to_owned(),
                            task_id: Some(task.id.clone()),
                            path: Some(relative),
                        });
                    }
                }
                Err(error) => {
                    return Err(failure(
                        error,
                        "declared_file",
                        Some(plan_relative.to_owned()),
                        "declared file path is unsafe or cannot be inspected",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn resolve_declared(root: &Utf8Path, relative: &Utf8Path) -> Result<bool, ContextErrorCode> {
    let candidate = root.join(relative);
    if let Ok(metadata) = fs::symlink_metadata(&candidate)
        && metadata.file_type().is_symlink()
    {
        let path = fs::canonicalize(&candidate).map_err(|_| ContextErrorCode::UnsafePath)?;
        return if path.starts_with(root) { Ok(true) } else { Err(ContextErrorCode::UnsafePath) };
    }
    match fs::canonicalize(&candidate) {
        Ok(path) if path.starts_with(root) => Ok(true),
        Ok(_) => Err(ContextErrorCode::UnsafePath),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut ancestor = candidate.as_path();
            loop {
                let Some(parent) = ancestor.parent() else {
                    return Err(ContextErrorCode::UnsafePath);
                };
                match fs::canonicalize(parent) {
                    Ok(path) if path.starts_with(root) => return Ok(false),
                    Ok(_) => return Err(ContextErrorCode::UnsafePath),
                    Err(parent_error) if parent_error.kind() == io::ErrorKind::NotFound => ancestor = parent,
                    Err(_) => return Err(ContextErrorCode::FilesystemError),
                }
            }
        }
        Err(_) => Err(ContextErrorCode::FilesystemError),
    }
}

fn resolve_existing(
    root: &Utf8Path,
    relative: &Utf8Path,
    check: &str,
) -> Result<ResolvedPath, ImplementationContextError> {
    let absolute = fs::canonicalize(root.join(relative)).map_err(|error| {
        failure(
            if error.kind() == io::ErrorKind::NotFound {
                ContextErrorCode::MissingSource
            } else {
                ContextErrorCode::FilesystemError
            },
            check,
            Some(relative.to_owned()),
            "required source cannot be resolved",
        )
    })?;
    if !absolute.starts_with(root) {
        return Err(failure(ContextErrorCode::UnsafePath, check, None, "resolved source escapes the workspace"));
    }
    let absolute = Utf8PathBuf::from_path_buf(absolute)
        .map_err(|_| failure(ContextErrorCode::UnsafePath, check, None, "resolved source path is not valid UTF-8"))?;
    let relative = absolute
        .strip_prefix(root)
        .map_err(|_| failure(ContextErrorCode::UnsafePath, check, None, "resolved source is outside the workspace"))?
        .to_owned();
    Ok(ResolvedPath { absolute, relative })
}

fn safe_relative_path(value: &str, check: &str) -> Result<Utf8PathBuf, ImplementationContextError> {
    let path = Path::new(value);
    let portable_drive =
        value.as_bytes().get(1) == Some(&b':') && value.as_bytes().first().is_some_and(u8::is_ascii_alphabetic);
    if value.is_empty()
        || value.contains('\\')
        || path.is_absolute()
        || portable_drive
        || path.components().any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(failure(
            ContextErrorCode::UnsafePath,
            check,
            None,
            "path must be workspace-relative and traversal-free",
        ));
    }
    Ok(Utf8PathBuf::from(value))
}

fn required_relative(
    value: Option<&str>,
    field: &str,
    source: &Utf8Path,
) -> Result<Utf8PathBuf, ImplementationContextError> {
    let value = value.ok_or_else(|| {
        failure(ContextErrorCode::LinkMismatch, field, Some(source.to_owned()), "required path field is absent")
    })?;
    safe_relative_path(value, field)
}

fn parse_json(bytes: &[u8], check: &str, path: &Utf8Path) -> Result<Value, ImplementationContextError> {
    serde_json::from_slice(bytes).map_err(|_| {
        failure(ContextErrorCode::InvalidJson, check, Some(path.to_owned()), "required source is not valid JSON")
    })
}

fn validate_artifact(contract: Contract, value: &Value, path: &Utf8Path) -> Result<(), ImplementationContextError> {
    validate_contract(contract, value).map_err(|error| {
        let code = match error {
            SpecValidationError::SchemaDefinition { .. } => ContextErrorCode::FilesystemError,
            _ => ContextErrorCode::SchemaViolation,
        };
        failure(code, "artifact_schema", Some(path.to_owned()), "source does not satisfy its pinned schema")
    })
}

fn valid_sha256(value: &str) -> bool {
    let Some(digest) = value.strip_prefix("sha256:") else {
        return false;
    };
    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn passed_checks() -> Vec<ContextCheck> {
    [
        ContextCheckId::PlanSchema,
        ContextCheckId::SpecSchema,
        ContextCheckId::SourceLinks,
        ContextCheckId::SpecHash,
        ContextCheckId::Selection,
        ContextCheckId::InputStability,
    ]
    .into_iter()
    .map(|id| ContextCheck { id, result: ContextCheckResult::Passed })
    .collect()
}

fn read_source_file(path: &Utf8Path) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take((MAX_SOURCE_BYTES + 1) as u64).read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_source<F>(
    read: &mut F,
    source: &ResolvedPath,
    read_check: &str,
    size_check: &str,
) -> Result<Vec<u8>, ImplementationContextError>
where
    F: FnMut(&Utf8Path) -> io::Result<Vec<u8>>,
{
    let bytes = read(&source.absolute).map_err(|error| io_failure(read_check, &source.relative, error))?;
    if bytes.len() > MAX_SOURCE_BYTES {
        return Err(failure(
            ContextErrorCode::BudgetExceeded,
            size_check,
            Some(source.relative.clone()),
            "required source exceeds the 1048576-byte input limit",
        ));
    }
    Ok(bytes)
}

fn io_failure(check: &str, path: &Utf8Path, _source: io::Error) -> ImplementationContextError {
    failure(ContextErrorCode::FilesystemError, check, Some(path.to_owned()), "required source could not be read")
}

fn failure(
    code: ContextErrorCode,
    check: &str,
    path: Option<Utf8PathBuf>,
    message: &str,
) -> ImplementationContextError {
    ImplementationContextError { code, check: check.to_owned(), path, message: message.to_owned() }
}

#[cfg(test)]
mod tests {
    use std::{fs, process::Command};

    use camino::{Utf8Path, Utf8PathBuf};
    use serde_json::{Value, json};
    use tempfile::{TempDir, tempdir};
    use wisp_model::{ContextErrorCode, ContextGapKind};

    use super::{
        CONTEXT_CONTRACT_ID, ImplementationSelection, MAX_SOURCE_BYTES, ResolvedPath, assemble_implementation_context,
        assemble_with_reader, read_source,
    };

    fn fixture() -> TempDir {
        let workspace = tempdir().unwrap_or_else(|error| panic!("temporary workspace: {error}"));
        let root = workspace.path();
        fs::create_dir_all(root.join("docs/projects")).unwrap_or_else(|error| panic!("plan directory: {error}"));
        fs::create_dir_all(root.join("docs/specs")).unwrap_or_else(|error| panic!("spec directory: {error}"));
        let spec = json!({
            "id": "SPEC-001",
            "purpose": "Verify implementation context assembly.",
            "scope": "Selected task and criterion projection.",
            "non_goals": ["Execute commands."],
            "acceptance_criteria": [
                {"id": "AC-001", "criterion": "The selected task is preserved."},
                {"id": "AC-002", "criterion": "The output follows plan order."}
            ],
            "spec_file_path": "docs/specs/SPEC-001.json"
        });
        let spec_bytes = encode(&spec);
        fs::write(root.join("docs/specs/SPEC-001.json"), &spec_bytes)
            .unwrap_or_else(|error| panic!("write fixture spec: {error}"));
        let plan = json!({
            "goal": "Assemble selected implementation context.",
            "architecture": "Read the selected artifact chain directly.",
            "tech_stack": ["Rust"],
            "tasks": [
                {
                    "id": "T1",
                    "title": "First task",
                    "files": {"create": ["src/new.rs"], "modify": ["src/missing.rs"], "test": ["tests/missing.rs"]},
                    "steps": ["First authored step."],
                    "commit_message": "feat: add first task",
                    "depends_on": [],
                    "covers_criteria": ["AC-002"]
                },
                {
                    "id": "T2",
                    "title": "Second task",
                    "files": {},
                    "steps": ["Second authored step."],
                    "commit_message": "feat: add second task",
                    "depends_on": ["T1"],
                    "covers_criteria": ["AC-001"]
                }
            ],
            "batches": [{"batch_id": "B1", "title": "Both tasks", "target_crate": "test", "task_ids": ["T2", "T1"]}],
            "linked_spec": "SPEC-001",
            "spec_file_path": "docs/specs/SPEC-001.json",
            "plan_file_path": "docs/projects/SPEC-001.json",
            "spec_hash": super::super::sha256(&spec_bytes)
        });
        fs::write(root.join("docs/projects/SPEC-001.json"), encode(&plan))
            .unwrap_or_else(|error| panic!("write fixture plan: {error}"));
        let init = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["init", "-q"])
            .status()
            .unwrap_or_else(|error| panic!("initialize fixture repository: {error}"));
        assert!(init.success(), "temporary Git initialization succeeds");
        workspace
    }

    fn encode(value: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(value).unwrap_or_else(|error| panic!("fixture serializes: {error}"));
        bytes.push(b'\n');
        bytes
    }

    fn root(workspace: &TempDir) -> &Utf8Path {
        Utf8Path::from_path(workspace.path()).unwrap_or_else(|| panic!("fixture path is UTF-8"))
    }

    fn status(workspace: &TempDir) -> Vec<u8> {
        let output = Command::new("git")
            .arg("-C")
            .arg(workspace.path())
            .args(["--no-optional-locks", "status", "--porcelain=v1", "--untracked-files=all"])
            .env("GIT_OPTIONAL_LOCKS", "0")
            .output()
            .unwrap_or_else(|error| panic!("read fixture Git status: {error}"));
        assert!(output.status.success(), "Git status succeeds");
        output.stdout
    }

    fn error_code(
        result: Result<super::ImplementationContext, wisp_model::ImplementationContextError>,
    ) -> ContextErrorCode {
        match result {
            Ok(_) => panic!("expected a context failure"),
            Err(error) => error.code,
        }
    }

    #[test]
    fn assembles_batch_in_plan_and_spec_order_without_reading_unrelated_artifacts() {
        let workspace = fixture();
        fs::write(workspace.path().join("docs/specs/unrelated.json"), b"not JSON")
            .unwrap_or_else(|error| panic!("write unrelated invalid artifact: {error}"));
        fs::create_dir_all(workspace.path().join("src"))
            .unwrap_or_else(|error| panic!("create declared-file directory: {error}"));
        fs::write(workspace.path().join("src/new.rs"), "existing declared create target")
            .unwrap_or_else(|error| panic!("create declared create target: {error}"));
        let before = status(&workspace);
        let plan_before = fs::read(workspace.path().join("docs/projects/SPEC-001.json"))
            .unwrap_or_else(|error| panic!("read plan before assembly: {error}"));
        let spec_before = fs::read(workspace.path().join("docs/specs/SPEC-001.json"))
            .unwrap_or_else(|error| panic!("read spec before assembly: {error}"));

        let context = assemble_implementation_context(
            root(&workspace),
            Utf8Path::new("docs/projects/SPEC-001.json"),
            ImplementationSelection::Batch("B1".to_owned()),
            32_768,
        )
        .unwrap_or_else(|error| panic!("valid batch assembles: {error:?}"));

        assert_eq!(context.contract_id, CONTEXT_CONTRACT_ID);
        assert_eq!(context.selection.task_ids, ["T1", "T2"]);
        assert_eq!(context.selection.criterion_ids, ["AC-001", "AC-002"]);
        assert_eq!(context.tasks[0].steps, ["First authored step."]);
        assert_eq!(context.criteria[0].criterion, "The selected task is preserved.");
        assert!(context.gaps.iter().any(|gap| gap.kind == ContextGapKind::MissingModifyTarget));
        assert!(context.gaps.iter().any(|gap| gap.kind == ContextGapKind::MissingTestTarget));
        assert!(context.gaps.iter().any(|gap| gap.kind == ContextGapKind::DependencyCompletionUnverified));
        assert!(!workspace.path().join(".wisp").exists());
        assert_eq!(
            fs::read(workspace.path().join("docs/projects/SPEC-001.json"))
                .unwrap_or_else(|error| panic!("read plan after assembly: {error}")),
            plan_before
        );
        assert_eq!(
            fs::read(workspace.path().join("docs/specs/SPEC-001.json"))
                .unwrap_or_else(|error| panic!("read spec after assembly: {error}")),
            spec_before
        );
        assert_eq!(status(&workspace), before);
    }

    #[test]
    fn assembles_one_task_and_emits_a_schema_valid_result() {
        let workspace = fixture();
        let context = assemble_implementation_context(
            root(&workspace),
            Utf8Path::new("docs/projects/SPEC-001.json"),
            ImplementationSelection::Task("T2".to_owned()),
            32_768,
        )
        .unwrap_or_else(|error| panic!("valid task assembles: {error:?}"));
        assert_eq!(context.selection.task_ids, ["T2"]);
        assert_eq!(context.selection.criterion_ids, ["AC-001"]);
        let value = serde_json::to_value(context).unwrap_or_else(|error| panic!("context serializes: {error}"));
        assert!(wisp_schema::validate_implementation_context(&value).is_ok());
    }

    #[test]
    fn rejects_unknown_batch_and_task_selections() {
        let workspace = fixture();
        let plan = Utf8Path::new("docs/projects/SPEC-001.json");
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan,
                ImplementationSelection::Batch("B9".to_owned()),
                32_768
            )),
            ContextErrorCode::InvalidSelection
        );
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan,
                ImplementationSelection::Task("T9".to_owned()),
                32_768
            )),
            ContextErrorCode::InvalidSelection
        );
    }

    #[test]
    fn rejects_unsafe_plan_and_spec_paths() {
        let workspace = fixture();
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("../outside.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::UnsafePath
        );

        let workspace = fixture();
        let absolute_plan = Utf8PathBuf::from_path_buf(workspace.path().join("docs/projects/SPEC-001.json"))
            .unwrap_or_else(|_| panic!("temporary plan path is UTF-8"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                &absolute_plan,
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::UnsafePath
        );
        for unsafe_path in
            [Utf8Path::new("docs\\projects\\SPEC-001.json"), Utf8Path::new("C:/docs/projects/SPEC-001.json")]
        {
            assert_eq!(
                error_code(assemble_implementation_context(
                    root(&workspace),
                    unsafe_path,
                    ImplementationSelection::Task("T1".to_owned()),
                    32_768,
                )),
                ContextErrorCode::UnsafePath,
                "unsafe path variant: {unsafe_path}"
            );
        }
        let path = workspace.path().join("docs/projects/SPEC-001.json");
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["spec_file_path"] = json!("../outside.json");
        fs::write(path, encode(&plan)).unwrap_or_else(|error| panic!("write modified plan: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::UnsafePath
        );
    }

    #[test]
    fn rejects_link_identity_dependency_json_and_schema_failures() {
        let plan_relative = Utf8Path::new("docs/projects/SPEC-001.json");

        let workspace = fixture();
        let path = workspace.path().join(plan_relative.as_str());
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["linked_spec"] = json!("SPEC-404");
        fs::write(&path, encode(&plan)).unwrap_or_else(|error| panic!("write modified plan: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::LinkMismatch
        );

        let workspace = fixture();
        let path = workspace.path().join(plan_relative.as_str());
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["tasks"][1]["id"] = json!("T1");
        fs::write(&path, encode(&plan)).unwrap_or_else(|error| panic!("write duplicate task: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::InvalidSelection
        );

        let workspace = fixture();
        let path = workspace.path().join(plan_relative.as_str());
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["tasks"][0]["depends_on"] = json!(["T404"]);
        fs::write(&path, encode(&plan)).unwrap_or_else(|error| panic!("write invalid dependency: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::InvalidSelection
        );

        let workspace = fixture();
        fs::write(workspace.path().join("docs/specs/SPEC-001.json"), b"{")
            .unwrap_or_else(|error| panic!("write malformed spec: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::InvalidJson
        );

        let workspace = fixture();
        let spec_path = workspace.path().join("docs/specs/SPEC-001.json");
        let mut spec: Value =
            serde_json::from_slice(&fs::read(&spec_path).unwrap_or_else(|error| panic!("read spec: {error}")))
                .unwrap_or_else(|error| panic!("parse spec: {error}"));
        spec.as_object_mut().unwrap_or_else(|| panic!("spec is an object")).remove("purpose");
        let bytes = encode(&spec);
        fs::write(&spec_path, &bytes).unwrap_or_else(|error| panic!("write invalid spec: {error}"));
        let plan_path = workspace.path().join(plan_relative.as_str());
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&plan_path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["spec_hash"] = json!(super::super::sha256(&bytes));
        fs::write(&plan_path, encode(&plan)).unwrap_or_else(|error| panic!("update plan hash: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::SchemaViolation
        );

        let workspace = fixture();
        fs::remove_file(workspace.path().join(plan_relative.as_str()))
            .unwrap_or_else(|error| panic!("remove plan: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::MissingSource
        );

        let workspace = fixture();
        let spec_path = workspace.path().join("docs/specs/SPEC-001.json");
        let mut spec: Value =
            serde_json::from_slice(&fs::read(&spec_path).unwrap_or_else(|error| panic!("read spec: {error}")))
                .unwrap_or_else(|error| panic!("parse spec: {error}"));
        spec["unexpected"] = json!(true);
        let spec_bytes = encode(&spec);
        fs::write(&spec_path, &spec_bytes).unwrap_or_else(|error| panic!("write extra-property spec: {error}"));
        let plan_path = workspace.path().join(plan_relative.as_str());
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&plan_path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["spec_hash"] = json!(super::super::sha256(&spec_bytes));
        fs::write(&plan_path, encode(&plan)).unwrap_or_else(|error| panic!("update plan hash: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::SchemaViolation
        );
    }

    #[test]
    fn rejects_duplicate_criteria_unknown_mappings_and_invalid_batch_members() {
        let plan_relative = Utf8Path::new("docs/projects/SPEC-001.json");

        let workspace = fixture();
        let spec_path = workspace.path().join("docs/specs/SPEC-001.json");
        let mut spec: Value =
            serde_json::from_slice(&fs::read(&spec_path).unwrap_or_else(|error| panic!("read spec: {error}")))
                .unwrap_or_else(|error| panic!("parse spec: {error}"));
        spec["acceptance_criteria"][1]["id"] = json!("AC-001");
        let spec_bytes = encode(&spec);
        fs::write(&spec_path, &spec_bytes).unwrap_or_else(|error| panic!("write duplicate criterion: {error}"));
        let plan_path = workspace.path().join(plan_relative.as_str());
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&plan_path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["spec_hash"] = json!(super::super::sha256(&spec_bytes));
        fs::write(&plan_path, encode(&plan)).unwrap_or_else(|error| panic!("update plan hash: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::InvalidSelection
        );

        let workspace = fixture();
        let path = workspace.path().join(plan_relative.as_str());
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["tasks"][0]["covers_criteria"] = json!(["AC-404"]);
        fs::write(&path, encode(&plan)).unwrap_or_else(|error| panic!("write unknown mapping: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::InvalidSelection
        );

        let workspace = fixture();
        let path = workspace.path().join(plan_relative.as_str());
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["batches"][0]["task_ids"] = json!(["T1", "T1"]);
        fs::write(&path, encode(&plan)).unwrap_or_else(|error| panic!("write duplicate batch member: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Batch("B1".to_owned()),
                32_768
            )),
            ContextErrorCode::InvalidSelection
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_declared_file_symlink_that_escapes_the_workspace() {
        use std::os::unix::fs::symlink;

        let workspace = fixture();
        let outside = tempdir().unwrap_or_else(|error| panic!("outside directory: {error}"));
        fs::write(outside.path().join("existing.rs"), "outside")
            .unwrap_or_else(|error| panic!("write outside file: {error}"));
        symlink(outside.path(), workspace.path().join("src"))
            .unwrap_or_else(|error| panic!("create intermediate directory symlink: {error}"));
        assert_eq!(
            super::resolve_declared(root(&workspace), Utf8Path::new("src/existing.rs")),
            Err(ContextErrorCode::UnsafePath)
        );
        assert_eq!(
            super::resolve_declared(root(&workspace), Utf8Path::new("src/missing.rs")),
            Err(ContextErrorCode::UnsafePath)
        );
        let plan_path = workspace.path().join("docs/projects/SPEC-001.json");
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&plan_path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["tasks"][0]["files"]["modify"] = json!(["src/existing.rs"]);
        fs::write(&plan_path, encode(&plan)).unwrap_or_else(|error| panic!("write modified plan: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::UnsafePath
        );

        plan["tasks"][0]["files"]["modify"] = json!(["src/missing.rs"]);
        fs::write(&plan_path, encode(&plan)).unwrap_or_else(|error| panic!("write missing external target: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::UnsafePath
        );
    }

    #[test]
    fn requires_plan_and_spec_declared_paths_to_match_the_selected_sources() {
        let plan_relative = Utf8Path::new("docs/projects/SPEC-001.json");

        let workspace = fixture();
        let path = workspace.path().join(plan_relative.as_str());
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["plan_file_path"] = json!("docs/projects/other.json");
        let plan_bytes = encode(&plan);
        fs::write(&path, &plan_bytes).unwrap_or_else(|error| panic!("write changed plan: {error}"));
        fs::write(workspace.path().join("docs/projects/other.json"), plan_bytes)
            .unwrap_or_else(|error| panic!("write declared plan alias: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::LinkMismatch
        );

        let workspace = fixture();
        let spec_path = workspace.path().join("docs/specs/SPEC-001.json");
        let mut spec: Value =
            serde_json::from_slice(&fs::read(&spec_path).unwrap_or_else(|error| panic!("read spec: {error}")))
                .unwrap_or_else(|error| panic!("parse spec: {error}"));
        spec["spec_file_path"] = json!("docs/specs/other.json");
        let spec_bytes = encode(&spec);
        fs::write(&spec_path, &spec_bytes).unwrap_or_else(|error| panic!("write changed spec: {error}"));
        fs::write(workspace.path().join("docs/specs/other.json"), &spec_bytes)
            .unwrap_or_else(|error| panic!("write declared spec alias: {error}"));
        let plan_path = workspace.path().join(plan_relative.as_str());
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&plan_path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["spec_hash"] = json!(super::super::sha256(&spec_bytes));
        fs::write(&plan_path, encode(&plan)).unwrap_or_else(|error| panic!("update plan hash: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                plan_relative,
                ImplementationSelection::Task("T1".to_owned()),
                32_768
            )),
            ContextErrorCode::LinkMismatch
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_plan_symlink_that_escapes_the_workspace() {
        use std::os::unix::fs::symlink;

        let workspace = fixture();
        let outside = tempdir().unwrap_or_else(|error| panic!("outside directory: {error}"));
        let external_plan = outside.path().join("plan.json");
        fs::copy(workspace.path().join("docs/projects/SPEC-001.json"), &external_plan)
            .unwrap_or_else(|error| panic!("copy external plan: {error}"));
        let link = workspace.path().join("docs/projects/external.json");
        symlink(external_plan, &link).unwrap_or_else(|error| panic!("create symlink: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/external.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::UnsafePath
        );

        let workspace = fixture();
        let outside_spec = outside.path().join("spec.json");
        fs::copy(workspace.path().join("docs/specs/SPEC-001.json"), &outside_spec)
            .unwrap_or_else(|error| panic!("copy external spec: {error}"));
        let spec_path = workspace.path().join("docs/specs/SPEC-001.json");
        fs::remove_file(&spec_path).unwrap_or_else(|error| panic!("remove original spec: {error}"));
        symlink(outside_spec, &spec_path).unwrap_or_else(|error| panic!("create external spec link: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::UnsafePath
        );
    }

    #[test]
    fn reports_stale_and_malformed_hashes_as_typed_failures() {
        let workspace = fixture();
        let plan_path = workspace.path().join("docs/projects/SPEC-001.json");
        let mut plan: Value =
            serde_json::from_slice(&fs::read(&plan_path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["spec_hash"] = json!("sha256:short");
        fs::write(&plan_path, encode(&plan)).unwrap_or_else(|error| panic!("write plan: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::LinkMismatch
        );

        let mut plan: Value =
            serde_json::from_slice(&fs::read(&plan_path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["spec_hash"] = json!(format!("sha256:{}", "0".repeat(63)));
        fs::write(&plan_path, encode(&plan)).unwrap_or_else(|error| panic!("write short hexadecimal hash: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::LinkMismatch
        );

        let mut plan: Value =
            serde_json::from_slice(&fs::read(&plan_path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["spec_hash"] = json!(format!("sha256:{}x", "0".repeat(63)));
        fs::write(&plan_path, encode(&plan)).unwrap_or_else(|error| panic!("write invalid hexadecimal hash: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::LinkMismatch
        );

        let mut plan: Value =
            serde_json::from_slice(&fs::read(&plan_path).unwrap_or_else(|error| panic!("read plan: {error}")))
                .unwrap_or_else(|error| panic!("parse plan: {error}"));
        plan["spec_hash"] = json!(format!("sha256:{}", "0".repeat(64)));
        fs::write(&plan_path, encode(&plan)).unwrap_or_else(|error| panic!("write plan: {error}"));
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
            )),
            ContextErrorCode::SpecDrift
        );
    }

    #[test]
    fn rejects_contexts_that_exceed_the_output_limit_without_truncation() {
        let workspace = fixture();
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Batch("B1".to_owned()),
                256,
            )),
            ContextErrorCode::BudgetExceeded
        );
    }

    #[test]
    fn detects_plan_or_spec_edits_during_assembly() {
        for relative in ["docs/projects/SPEC-001.json", "docs/specs/SPEC-001.json"] {
            let workspace = fixture();
            let root = root(&workspace).to_owned();
            let plan = Utf8Path::new("docs/projects/SPEC-001.json");
            let changed_absolute = workspace.path().join(relative);
            let mut reads = 0;
            let result =
                assemble_with_reader(&root, plan, ImplementationSelection::Task("T1".to_owned()), 32_768, |path| {
                    reads += 1;
                    let reread =
                        (relative.contains("projects") && reads == 3) || (relative.contains("specs") && reads == 4);
                    if reread {
                        fs::write(&changed_absolute, b"changed while assembling")?;
                    }
                    fs::read(path)
                });
            assert_eq!(error_code(result), ContextErrorCode::InputsChanged, "changed source: {relative}");
        }
    }

    #[test]
    fn rejects_an_invalid_output_limit() {
        let workspace = fixture();
        assert_eq!(
            error_code(assemble_implementation_context(
                root(&workspace),
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Task("T1".to_owned()),
                255,
            )),
            ContextErrorCode::InvalidInput
        );
    }

    #[test]
    fn source_reader_accepts_the_inclusive_limit_and_rejects_one_byte_over() {
        let directory = tempdir().unwrap_or_else(|error| panic!("temporary source directory: {error}"));
        let path = directory.path().join("large.json");
        fs::write(&path, vec![b' '; MAX_SOURCE_BYTES + 32])
            .unwrap_or_else(|error| panic!("write oversized source: {error}"));
        let path = Utf8Path::from_path(path.as_path()).unwrap_or_else(|| panic!("source path is UTF-8"));
        assert_eq!(
            super::read_source_file(path).unwrap_or_else(|error| panic!("bounded source read succeeds: {error}")).len(),
            MAX_SOURCE_BYTES + 1
        );

        let source = ResolvedPath {
            absolute: Utf8PathBuf::from("unused.json"),
            relative: Utf8PathBuf::from("docs/specs/SPEC-001.json"),
        };
        let at_limit = read_source(&mut |_| Ok(vec![b' '; MAX_SOURCE_BYTES]), &source, "spec_read", "spec_source_size")
            .unwrap_or_else(|error| panic!("inclusive input limit accepted: {error}"));
        assert_eq!(at_limit.len(), MAX_SOURCE_BYTES);

        let error =
            read_source(&mut |_| Ok(vec![b' '; MAX_SOURCE_BYTES + 1]), &source, "spec_read", "spec_source_size")
                .expect_err("one byte over the input limit is rejected");
        assert_eq!(error.code, ContextErrorCode::BudgetExceeded);
        assert_eq!(error.check, "spec_source_size");
        assert_eq!(error.path.as_deref(), Some(Utf8Path::new("docs/specs/SPEC-001.json")));
    }

    #[test]
    fn rejects_oversized_plan_and_spec_on_initial_and_stability_reads() {
        for (relative, oversized_read, check) in [
            ("docs/projects/SPEC-001.json", 1, "plan_source_size"),
            ("docs/specs/SPEC-001.json", 2, "spec_source_size"),
            ("docs/projects/SPEC-001.json", 3, "plan_source_size"),
            ("docs/specs/SPEC-001.json", 4, "spec_source_size"),
        ] {
            let workspace = fixture();
            let root = root(&workspace).to_owned();
            let oversized_path = Utf8PathBuf::from_path_buf(
                fs::canonicalize(workspace.path().join(relative))
                    .unwrap_or_else(|error| panic!("canonicalize fixture path: {error}")),
            )
            .unwrap_or_else(|_| panic!("test path is UTF-8"));
            let mut reads = 0;
            let result = assemble_with_reader(
                &root,
                Utf8Path::new("docs/projects/SPEC-001.json"),
                ImplementationSelection::Task("T1".to_owned()),
                32_768,
                |path| {
                    reads += 1;
                    if path == oversized_path && reads == oversized_read {
                        Ok(vec![b' '; MAX_SOURCE_BYTES + 1])
                    } else {
                        fs::read(path)
                    }
                },
            );
            let error =
                result.expect_err(&format!("oversized {relative} read {oversized_read} fails after {reads} reads"));
            assert_eq!(error.code, ContextErrorCode::BudgetExceeded);
            assert_eq!(error.check, check);
            assert_eq!(error.path.as_deref(), Some(Utf8Path::new(relative)));
        }
    }
}
