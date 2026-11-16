//! Command-line entry point for Wisp.

use std::{fs, io::Read, process::ExitCode};

use camino::Utf8PathBuf;
use clap::{Parser, Subcommand, ValueEnum};
use miette::Diagnostic;
use serde_json::{Value, json};
use thiserror::Error;
use wisp_artifacts::{
    ArtifactError, ImplementationSelection, assemble_implementation_context, get_spec, persist_spec, spec_relative_path,
};
use wisp_model::{
    ArtifactId, ContextError, ContextFailureStatus, ImplementationContextError, ImplementationContextFailure,
};
use wisp_schema::{SPEC_V1_SCHEMA_ID, SpecValidationError, validate_spec_json};

#[derive(Debug, Parser)]
#[command(name = "wisp", about = "Local-first project intelligence")]
struct Cli {
    /// Render errors as machine JSON or human diagnostics.
    #[arg(long, global = true, default_value = "json")]
    format: OutputFormat,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum OutputFormat {
    /// Stable machine-readable error objects.
    #[default]
    Json,
    /// Rich human diagnostics on standard error.
    Human,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Operate on canonical project artifacts.
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    /// Compile bounded context for one explicitly selected implementation task or batch.
    Brief {
        #[command(subcommand)]
        command: BriefCommand,
    },
}

#[derive(Debug, Subcommand)]
enum BriefCommand {
    /// Assemble the selected plan/spec chain without graph discovery or Git inspection.
    Implement {
        /// Workspace root.
        #[arg(long, default_value = ".")]
        workspace: String,
        /// Workspace-relative plan JSON path.
        #[arg(long)]
        plan: Option<String>,
        /// Select one declared plan batch.
        #[arg(long, action = clap::ArgAction::Append)]
        batch: Vec<String>,
        /// Select one declared task.
        #[arg(long, action = clap::ArgAction::Append)]
        task: Vec<String>,
        /// Maximum serialized JSON bytes, including the trailing newline.
        #[arg(long, default_value_t = 32_768)]
        max_bytes: usize,
    },
}

#[derive(Debug, Subcommand)]
enum ArtifactCommand {
    /// Validate a candidate spec JSON file, or `-` for standard input.
    Validate { candidate: String },
    /// Validate and atomically persist a candidate spec JSON file.
    Persist {
        candidate: String,
        #[arg(long, default_value = ".")]
        workspace: String,
    },
    /// Revalidate and retrieve a canonical spec by ID.
    Get {
        id: String,
        #[arg(long, default_value = ".")]
        workspace: String,
    },
    /// Report whether the requested canonical spec is absent, uncommitted, or clean.
    Status {
        id: String,
        #[arg(long, default_value = ".")]
        workspace: String,
    },
}

#[derive(Debug, Diagnostic, Error)]
enum CliError {
    #[diagnostic(code(wisp::cli::input))]
    #[error("could not read candidate: {0}")]
    Input(#[source] std::io::Error),
    #[diagnostic(code(wisp::cli::workspace_path))]
    #[error("workspace path is not valid UTF-8")]
    WorkspacePath,
    #[diagnostic(code(wisp::cli::unsafe_id))]
    #[error("artifact ID is invalid: {0}")]
    Id(#[source] wisp_model::ArtifactIdError),
    #[diagnostic(code(wisp::artifact))]
    #[error(transparent)]
    Artifact(#[from] ArtifactError),
    #[diagnostic(transparent)]
    #[error(transparent)]
    Validation(#[from] SpecValidationError),
    #[diagnostic(code(wisp::implementation_context))]
    #[error("implementation context could not be assembled")]
    ImplementationContext(ImplementationContextFailure),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let format = cli.format;
    match run(cli) {
        Ok(value) => write_json(&value, ExitCode::SUCCESS),
        Err(error) => match format {
            OutputFormat::Json => write_json(&error_json(&error), ExitCode::from(1)),
            OutputFormat::Human => {
                eprintln!("{:?}", miette::Report::new(error));
                ExitCode::from(1)
            }
        },
    }
}

fn run(cli: Cli) -> Result<Value, CliError> {
    match cli.command {
        Command::Artifact { command } => match command {
            ArtifactCommand::Validate { candidate } => {
                let validated = validate_spec_json(&read_candidate(&candidate)?)?;
                Ok(json!({"status":"validated", "artifact_type":"spec@1", "id":validated.id}))
            }
            ArtifactCommand::Persist { candidate, workspace } => {
                let receipt = persist_spec(&workspace_path(workspace)?, &read_candidate(&candidate)?)?;
                Ok(serde_json::to_value(receipt).map_err(|error| {
                    CliError::Validation(SpecValidationError::SchemaDefinition {
                        contract_id: SPEC_V1_SCHEMA_ID,
                        message: error.to_string(),
                    })
                })?)
            }
            ArtifactCommand::Get { id, workspace } => {
                let id = ArtifactId::new(id).map_err(CliError::Id)?;
                Ok(serde_json::to_value(get_spec(&workspace_path(workspace)?, &id)?).map_err(|error| {
                    CliError::Validation(SpecValidationError::SchemaDefinition {
                        contract_id: SPEC_V1_SCHEMA_ID,
                        message: error.to_string(),
                    })
                })?)
            }
            ArtifactCommand::Status { id, workspace } => {
                let id = ArtifactId::new(id).map_err(CliError::Id)?;
                let workspace = workspace_path(workspace)?;
                match get_spec(&workspace, &id) {
                    Ok(record) => {
                        Ok(json!({"status":record.state, "artifact_type":"spec@1", "id":id, "path":record.path}))
                    }
                    Err(ArtifactError::Absent { .. }) => Ok(
                        json!({"status":"absent", "artifact_type":"spec@1", "id":id, "path":spec_relative_path(&id)}),
                    ),
                    Err(error) => Err(CliError::Artifact(error)),
                }
            }
        },
        Command::Brief { command } => match command {
            BriefCommand::Implement { workspace, plan, batch, task, max_bytes } => {
                let plan = plan.ok_or_else(|| context_input_failure("plan_path", "--plan is required"))?;
                let selection = match (batch.as_slice(), task.as_slice()) {
                    ([id], []) => ImplementationSelection::Batch(id.clone()),
                    ([], [id]) => ImplementationSelection::Task(id.clone()),
                    ([], []) => {
                        return Err(context_input_failure("selection", "exactly one of --batch or --task is required"));
                    }
                    _ => {
                        return Err(context_input_failure(
                            "selection",
                            "provide exactly one selector value using only --batch or --task",
                        ));
                    }
                };
                let context = assemble_implementation_context(
                    &workspace_path(workspace)?,
                    camino::Utf8Path::new(&plan),
                    selection,
                    max_bytes,
                )
                .map_err(|error| CliError::ImplementationContext(context_failure(error)))?;
                serde_json::to_value(context).map_err(|error| {
                    CliError::Validation(SpecValidationError::SchemaDefinition {
                        contract_id: "implementation-context@1",
                        message: error.to_string(),
                    })
                })
            }
        },
    }
}

fn context_input_failure(check: &str, message: &str) -> CliError {
    CliError::ImplementationContext(ImplementationContextFailure {
        contract_id: "implementation-context@1".to_owned(),
        status: wisp_model::ContextFailureStatus::Error,
        error: wisp_model::ContextError {
            code: wisp_model::ContextErrorCode::InvalidInput,
            check: check.to_owned(),
            path: None,
            message: message.to_owned(),
        },
    })
}

fn context_failure(error: ImplementationContextError) -> ImplementationContextFailure {
    ImplementationContextFailure {
        contract_id: "implementation-context@1".to_owned(),
        status: ContextFailureStatus::Error,
        error: ContextError { code: error.code, check: error.check, path: error.path, message: error.message },
    }
}

fn workspace_path(value: String) -> Result<Utf8PathBuf, CliError> {
    Utf8PathBuf::from_path_buf(std::path::PathBuf::from(value)).map_err(|_| CliError::WorkspacePath)
}

fn read_candidate(candidate: &str) -> Result<Vec<u8>, CliError> {
    if candidate == "-" {
        let mut bytes = Vec::new();
        std::io::stdin().read_to_end(&mut bytes).map_err(CliError::Input)?;
        Ok(bytes)
    } else {
        fs::read(candidate).map_err(CliError::Input)
    }
}

fn error_json(error: &CliError) -> Value {
    if let CliError::ImplementationContext(failure) = error {
        return serde_json::to_value(failure)
            .unwrap_or_else(|_| json!({"contract_id":"implementation-context@1","status":"error","error":{"code":"filesystem_error","check":"error_encode","message":"error could not be serialized"}}));
    }
    let code = match error {
        CliError::Input(_) => "input_error",
        CliError::WorkspacePath => "workspace_path_error",
        CliError::Id(_) | CliError::Validation(SpecValidationError::UnsafeId { .. }) => "unsafe_id",
        CliError::Validation(SpecValidationError::InvalidJson { .. }) => "invalid_json",
        CliError::Validation(SpecValidationError::SchemaViolation { .. }) => "schema_violation",
        CliError::Validation(SpecValidationError::SchemaDefinition { .. }) => "schema_definition_error",
        CliError::Artifact(ArtifactError::Validation { .. }) => "validation_error",
        CliError::Artifact(ArtifactError::Absent { .. }) => "absent",
        CliError::Artifact(ArtifactError::Filesystem { .. }) => "filesystem_error",
        CliError::Artifact(ArtifactError::Serialization { .. }) => "serialization_error",
        CliError::ImplementationContext(_) => unreachable!("handled above"),
    };
    json!({"status":"error", "code":code})
}

fn write_json(value: &Value, exit: ExitCode) -> ExitCode {
    match serde_json::to_string(value) {
        Ok(serialized) => println!("{serialized}"),
        Err(_) => println!("{{\"status\":\"error\",\"code\":\"output_error\"}}"),
    }
    exit
}
