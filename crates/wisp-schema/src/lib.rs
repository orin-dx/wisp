//! Version-pinned schema contracts for Wisp artifacts.

use miette::{Diagnostic, NamedSource, SourceSpan};
use serde_json::Value;
use thiserror::Error;
use wisp_model::{ArtifactId, ArtifactIdError};

/// The JSON Schema identifier for the spec contract.
pub const SPEC_V1_SCHEMA_ID: &str = "spec@1";

/// Portable canonical contracts supported by Wisp's initial registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Contract {
    /// A captured need.
    RequirementV1,
    /// Evidence informing a requirement.
    ResearchReportV1,
    /// A testable specification.
    SpecV1,
    /// An implementation plan.
    PlanV1,
    /// A workspace architecture map.
    ArchModelV1,
    /// A workspace architecture map with optional decision references.
    ArchModelV2,
}

impl Contract {
    /// Stable schema identifier.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::RequirementV1 => "requirement@1",
            Self::ResearchReportV1 => "research-report@1",
            Self::SpecV1 => "spec@1",
            Self::PlanV1 => "plan@1",
            Self::ArchModelV1 => "arch-model@1",
            Self::ArchModelV2 => "arch-model@2",
        }
    }

    /// Canonical workspace-relative path pattern.
    #[must_use]
    pub const fn canonical_directory(self) -> &'static str {
        match self {
            Self::RequirementV1 => "docs/requirements",
            Self::ResearchReportV1 => "docs/research",
            Self::SpecV1 => "docs/specs",
            Self::PlanV1 => "docs/projects",
            Self::ArchModelV1 | Self::ArchModelV2 => "docs/architecture",
        }
    }

    /// Resolve an exact registered schema identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ContractLookupError::UnknownContract`] when `id` is not
    /// registered.
    pub fn from_id(id: &str) -> Result<Self, ContractLookupError> {
        match id {
            "requirement@1" => Ok(Self::RequirementV1),
            "research-report@1" => Ok(Self::ResearchReportV1),
            "spec@1" => Ok(Self::SpecV1),
            "plan@1" => Ok(Self::PlanV1),
            "arch-model@1" => Ok(Self::ArchModelV1),
            "arch-model@2" => Ok(Self::ArchModelV2),
            _ => Err(ContractLookupError::UnknownContract { id: id.to_owned() }),
        }
    }
}

/// Failure returned when an exact schema identifier is not registered.
#[derive(Debug, Diagnostic, Error, Eq, PartialEq)]
pub enum ContractLookupError {
    /// The requested contract identifier is unknown to this registry.
    #[diagnostic(code(wisp::schema::unknown_contract))]
    #[error("unknown artifact contract ID: {id}")]
    UnknownContract {
        /// The exact identifier supplied by the caller.
        id: String,
    },
}

const EMBEDDED_SPEC_V1_SCHEMA: &str = include_str!("../../../schemas/spec@1.json");
const EMBEDDED_REQUIREMENT_V1_SCHEMA: &str = include_str!("../../../schemas/requirement@1.json");
const EMBEDDED_RESEARCH_REPORT_V1_SCHEMA: &str = include_str!("../../../schemas/research-report@1.json");
const EMBEDDED_PLAN_V1_SCHEMA: &str = include_str!("../../../schemas/plan@1.json");
const EMBEDDED_ARCH_MODEL_V1_SCHEMA: &str = include_str!("../../../schemas/arch-model@1.json");
const EMBEDDED_ARCH_MODEL_V2_SCHEMA: &str = include_str!("../../../schemas/arch-model@2.json");
const EMBEDDED_IMPLEMENTATION_CONTEXT_V1_SCHEMA: &str = include_str!("../../../schemas/implementation-context@1.json");

/// Validate a parsed document against a selected pinned contract.
///
/// # Errors
///
/// Returns a typed error when the embedded schema is invalid or the document
/// does not conform to it.
pub fn validate_contract(contract: Contract, value: &Value) -> Result<(), SpecValidationError> {
    let source = match contract {
        Contract::RequirementV1 => EMBEDDED_REQUIREMENT_V1_SCHEMA,
        Contract::ResearchReportV1 => EMBEDDED_RESEARCH_REPORT_V1_SCHEMA,
        Contract::SpecV1 => EMBEDDED_SPEC_V1_SCHEMA,
        Contract::PlanV1 => EMBEDDED_PLAN_V1_SCHEMA,
        Contract::ArchModelV1 => EMBEDDED_ARCH_MODEL_V1_SCHEMA,
        Contract::ArchModelV2 => EMBEDDED_ARCH_MODEL_V2_SCHEMA,
    };
    validate_embedded_schema(contract.id(), source, value)
}

/// Validate a transient implementation-context result against its pinned wire contract.
///
/// This output schema has no canonical workspace directory and is not an
/// artifact variant in [`Contract`].
///
/// # Errors
///
/// Returns a typed error when the embedded schema is invalid or the result
/// violates implementation-context@1.
pub fn validate_implementation_context(value: &Value) -> Result<(), SpecValidationError> {
    validate_embedded_schema("implementation-context@1", EMBEDDED_IMPLEMENTATION_CONTEXT_V1_SCHEMA, value)
}

fn validate_embedded_schema(contract_id: &'static str, source: &str, value: &Value) -> Result<(), SpecValidationError> {
    let schema: Value = serde_json::from_str(source)
        .map_err(|error| SpecValidationError::SchemaDefinition { contract_id, message: error.to_string() })?;
    let validator = jsonschema::validator_for(&schema)
        .map_err(|error| SpecValidationError::SchemaDefinition { contract_id, message: error.to_string() })?;
    validator
        .validate(value)
        .map_err(|error| SpecValidationError::SchemaViolation { contract_id, message: error.to_string() })
}

/// A `spec@1` document that has passed both its JSON Schema and Wisp ID checks.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedSpec {
    /// The validated artifact identifier.
    pub id: ArtifactId,
    /// The original parsed JSON document.
    pub value: Value,
}

/// An error encountered while parsing or validating a `spec@1` document.
#[derive(Debug, Diagnostic, Error)]
pub enum SpecValidationError {
    /// The candidate bytes are not valid JSON.
    #[diagnostic(code(wisp::schema::invalid_json))]
    #[error("the spec document is not valid JSON: {source}")]
    InvalidJson {
        /// Candidate source used by human diagnostics.
        #[source_code]
        source_code: NamedSource<String>,
        /// The parser location in the candidate source.
        #[label("invalid JSON here")]
        span: SourceSpan,
        /// The underlying JSON parser error.
        #[source]
        source: serde_json::Error,
    },
    /// The embedded schema could not be compiled.
    #[diagnostic(code(wisp::schema::definition))]
    #[error("the embedded {contract_id} schema is invalid: {message}")]
    SchemaDefinition {
        /// The registered contract whose schema could not be compiled.
        contract_id: &'static str,
        /// A stable diagnostic suitable for logs, not terminal presentation.
        message: String,
    },
    /// The candidate does not satisfy the `spec@1` JSON Schema.
    #[diagnostic(code(wisp::schema::violation))]
    #[error("the document violates {contract_id}: {message}")]
    SchemaViolation {
        /// The registered contract selected for validation.
        contract_id: &'static str,
        /// The first validator diagnostic.
        message: String,
    },
    /// The schema-valid `id` is not safe for a Wisp artifact path.
    #[diagnostic(code(wisp::schema::unsafe_id))]
    #[error("the spec document has an unsafe ID: {source}")]
    UnsafeId {
        /// The artifact ID validation error.
        #[source]
        source: ArtifactIdError,
    },
}

/// Parse and validate candidate JSON bytes as a `spec@1` document.
///
/// # Errors
///
/// Returns an error when the bytes are malformed, the document violates the
/// pinned schema, or its otherwise schema-valid ID is unsafe for Wisp paths.
pub fn validate_spec_json(input: &[u8]) -> Result<ValidatedSpec, SpecValidationError> {
    let value = serde_json::from_slice(input).map_err(|source| invalid_json(input, source))?;
    validate_spec_value(value)
}

/// Validate an already parsed JSON value as a `spec@1` document.
///
/// # Errors
///
/// Returns an error when the document violates the pinned schema or its ID is
/// unsafe for Wisp artifact paths.
pub fn validate_spec_value(value: Value) -> Result<ValidatedSpec, SpecValidationError> {
    let schema: Value = serde_json::from_str(EMBEDDED_SPEC_V1_SCHEMA).map_err(|source| {
        SpecValidationError::SchemaDefinition { contract_id: SPEC_V1_SCHEMA_ID, message: source.to_string() }
    })?;
    let validator = jsonschema::validator_for(&schema).map_err(|error| SpecValidationError::SchemaDefinition {
        contract_id: SPEC_V1_SCHEMA_ID,
        message: error.to_string(),
    })?;
    if let Err(error) = validator.validate(&value) {
        return Err(SpecValidationError::SchemaViolation {
            contract_id: SPEC_V1_SCHEMA_ID,
            message: error.to_string(),
        });
    }

    let id = value.get("id").and_then(Value::as_str).ok_or_else(|| SpecValidationError::SchemaViolation {
        contract_id: SPEC_V1_SCHEMA_ID,
        message: "spec@1 accepted a document without a string id".to_owned(),
    })?;
    let id = ArtifactId::new(id).map_err(|source| SpecValidationError::UnsafeId { source })?;

    Ok(ValidatedSpec { id, value })
}

fn invalid_json(input: &[u8], source: serde_json::Error) -> SpecValidationError {
    let source_text = String::from_utf8_lossy(input).into_owned();
    let line = source.line().saturating_sub(1);
    let column = source.column().saturating_sub(1);
    let line_offset = source_text.lines().take(line).map(|line| line.len() + 1).sum::<usize>();
    let offset = line_offset.saturating_add(column).min(source_text.len());
    SpecValidationError::InvalidJson {
        source_code: NamedSource::new("spec candidate", source_text),
        span: SourceSpan::from((offset, 1)),
        source,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::{
        Contract, ContractLookupError, SpecValidationError, validate_contract, validate_implementation_context,
        validate_spec_json, validate_spec_value,
    };

    const LEGACY_ARCH_MODEL_FIXTURE: &str = r#"{"modules":[],"canonical_abstractions":[],"invariants":[{"name":"Legacy invariant","rule":"A legacy rule.","rationale":"Preserve compatibility."}]}"#;

    const CONTRACT_FIXTURES: [(Contract, &str, &str, &str); 10] = [
        (
            Contract::RequirementV1,
            include_str!("../../../schemas/requirement@1.json"),
            include_str!("../../../docs/requirements/REQ-WISP-002.json"),
            "docs/requirements",
        ),
        (
            Contract::RequirementV1,
            include_str!("../../../schemas/requirement@1.json"),
            include_str!("../../../docs/requirements/REQ-WISP-004.json"),
            "docs/requirements",
        ),
        (
            Contract::ResearchReportV1,
            include_str!("../../../schemas/research-report@1.json"),
            include_str!("../../../docs/research/RESEARCH-WISP-002.json"),
            "docs/research",
        ),
        (
            Contract::ResearchReportV1,
            include_str!("../../../schemas/research-report@1.json"),
            include_str!("../../../docs/research/RESEARCH-WISP-004.json"),
            "docs/research",
        ),
        (
            Contract::SpecV1,
            include_str!("../../../schemas/spec@1.json"),
            include_str!("../../../docs/specs/WISP-002.json"),
            "docs/specs",
        ),
        (
            Contract::SpecV1,
            include_str!("../../../schemas/spec@1.json"),
            include_str!("../../../docs/specs/WISP-004.json"),
            "docs/specs",
        ),
        (
            Contract::PlanV1,
            include_str!("../../../schemas/plan@1.json"),
            include_str!("../../../docs/projects/WISP-002.json"),
            "docs/projects",
        ),
        (
            Contract::PlanV1,
            include_str!("../../../schemas/plan@1.json"),
            include_str!("../../../docs/projects/WISP-004.json"),
            "docs/projects",
        ),
        (
            Contract::ArchModelV1,
            include_str!("../../../schemas/arch-model@1.json"),
            LEGACY_ARCH_MODEL_FIXTURE,
            "docs/architecture",
        ),
        (
            Contract::ArchModelV2,
            include_str!("../../../schemas/arch-model@2.json"),
            include_str!("../../../docs/architecture/model.json"),
            "docs/architecture",
        ),
    ];

    fn valid_spec() -> serde_json::Value {
        json!({
            "id": "WISP-001",
            "purpose": "Define a testable artifact contract.",
            "scope": "A small, valid spec document.",
            "non_goals": ["Implement persistence."],
            "acceptance_criteria": [{
                "id": "AC-001",
                "criterion": "The document validates."
            }]
        })
    }

    fn valid_implementation_context() -> serde_json::Value {
        json!({
            "contract_id": "implementation-context@1",
            "status": "ok",
            "selection": {
                "mode": "task",
                "id": "T1",
                "task_ids": ["T1"],
                "criterion_ids": ["AC-001"]
            },
            "sources": {
                "plan": {"path": "docs/projects/SPEC-001.json", "schema_id": "plan@1", "sha256": format!("sha256:{}", "a".repeat(64))},
                "spec": {"path": "docs/specs/SPEC-001.json", "schema_id": "spec@1", "sha256": format!("sha256:{}", "b".repeat(64))}
            },
            "plan_context": {"goal": "Implement the selected work.", "architecture": "Use existing layers."},
            "spec_context": {"id": "SPEC-001", "purpose": "A valid spec.", "scope": "A focused scope.", "non_goals": []},
            "tasks": [{"id": "T1", "title": "Build the feature.", "files": {}, "steps": ["Implement the operation."], "commit_message": "feat: add operation"}],
            "criteria": [{"id": "AC-001", "criterion": "The operation validates."}],
            "checks": [
                {"id": "plan_schema", "result": "passed"},
                {"id": "spec_schema", "result": "passed"},
                {"id": "source_links", "result": "passed"},
                {"id": "spec_hash", "result": "passed"},
                {"id": "selection", "result": "passed"},
                {"id": "input_stability", "result": "passed"}
            ],
            "gaps": [],
            "evidence_scope": "artifacts_only",
            "output_limit_bytes": 32768
        })
    }

    fn valid_implementation_context_error() -> serde_json::Value {
        json!({
            "contract_id": "implementation-context@1",
            "status": "error",
            "error": {
                "code": "spec_drift",
                "check": "spec_hash",
                "path": "docs/specs/SPEC-001.json",
                "message": "The plan references different spec bytes."
            }
        })
    }

    #[test]
    fn accepts_a_valid_spec() {
        let result = validate_spec_value(valid_spec());
        assert!(result.is_ok());
    }

    #[test]
    fn validates_success_and_failure_implementation_context_envelopes() {
        assert!(validate_implementation_context(&valid_implementation_context()).is_ok());
        assert!(validate_implementation_context(&valid_implementation_context_error()).is_ok());
    }

    #[test]
    fn rejects_implementation_context_with_an_unknown_property() {
        let mut candidate = valid_implementation_context();
        candidate["private_reasoning"] = json!("must not cross the wire");
        assert!(matches!(
            validate_implementation_context(&candidate),
            Err(SpecValidationError::SchemaViolation { contract_id: "implementation-context@1", .. })
        ));
    }

    #[test]
    fn rejects_malformed_json() {
        let result = validate_spec_json(br#"{"id":"WISP-001""#);
        assert!(matches!(result, Err(SpecValidationError::InvalidJson { .. })));
    }

    #[test]
    fn rejects_an_unknown_property() {
        let mut candidate = valid_spec();
        candidate["unexpected"] = json!(true);
        let result = validate_spec_value(candidate);
        assert!(matches!(result, Err(SpecValidationError::SchemaViolation { .. })));
    }

    #[test]
    fn rejects_a_missing_required_property() {
        let mut candidate = valid_spec();
        candidate.as_object_mut().map(|object| object.remove("scope"));
        let result = validate_spec_value(candidate);
        assert!(matches!(result, Err(SpecValidationError::SchemaViolation { .. })));
    }

    #[test]
    fn rejects_an_unsafe_id() {
        let mut candidate = valid_spec();
        candidate["id"] = json!("../escape");
        let result = validate_spec_value(candidate);
        assert!(matches!(result, Err(SpecValidationError::UnsafeId { .. })));
    }

    #[test]
    fn resolves_and_validates_every_registered_contract() {
        for (contract, schema_fixture, artifact_fixture, canonical_directory) in CONTRACT_FIXTURES {
            assert_eq!(Contract::from_id(contract.id()), Ok(contract));
            assert_eq!(contract.canonical_directory(), canonical_directory);

            let schema: serde_json::Value = serde_json::from_str(schema_fixture)
                .unwrap_or_else(|error| panic!("{} schema is valid JSON: {error}", contract.id()));
            assert_eq!(
                schema["$id"].as_str(),
                Some(contract.id()),
                "embedded schema ID must match its registry identity"
            );
            let value: serde_json::Value = serde_json::from_str(artifact_fixture)
                .unwrap_or_else(|error| panic!("{contract:?} fixture is valid JSON: {error}"));
            assert!(validate_contract(contract, &value).is_ok(), "valid fixture must satisfy {}", contract.id());
        }
    }

    #[test]
    fn provenance_records_match_all_embedded_schema_bytes() {
        let provenance = include_str!("../../../schemas/PROVENANCE.md");

        for (contract, schema_fixture, _, _) in CONTRACT_FIXTURES {
            let digest = format!("{:x}", Sha256::digest(schema_fixture.as_bytes()));
            let table_row = format!("| `{}` | `{digest}` |", contract.id());
            let detail_record = format!("- Schema identifier: `{}`\n- SHA-256: `{digest}`", contract.id());
            assert!(
                provenance.contains(&table_row) || provenance.contains(&detail_record),
                "provenance must pin the exact bytes for {}",
                contract.id()
            );
        }
    }

    #[test]
    fn rejects_an_unknown_contract_id() {
        assert_eq!(
            Contract::from_id("arch-model@3"),
            Err(ContractLookupError::UnknownContract { id: "arch-model@3".to_owned() })
        );
    }

    #[test]
    fn validates_legacy_architecture_models_with_the_v2_contract() {
        let value: serde_json::Value = serde_json::from_str(LEGACY_ARCH_MODEL_FIXTURE)
            .unwrap_or_else(|error| panic!("architecture model fixture is valid JSON: {error}"));
        assert!(value["invariants"][0].get("decision_ref").is_none());
        assert!(validate_contract(Contract::ArchModelV1, &value).is_ok());
        assert!(validate_contract(Contract::ArchModelV2, &value).is_ok());
    }

    #[test]
    fn live_architecture_model_uses_v2_and_references_accepted_adrs() {
        let value: serde_json::Value = serde_json::from_str(include_str!("../../../docs/architecture/model.json"))
            .unwrap_or_else(|error| panic!("architecture model fixture is valid JSON: {error}"));
        assert!(validate_contract(Contract::ArchModelV2, &value).is_ok());
        assert_eq!(
            value["invariants"]
                .as_array()
                .and_then(|items| items
                    .iter()
                    .find(|item| item["name"] == "Keep library errors independent of the JSON envelope"))
                .and_then(|item| item["decision_ref"].as_str()),
            Some("docs/adr/001-rust-api-and-wire-boundary.md")
        );
        assert_eq!(
            value["invariants"]
                .as_array()
                .and_then(|items| items
                    .iter()
                    .find(|item| item["name"] == "Implementation context is a selected-chain read"))
                .and_then(|item| item["decision_ref"].as_str()),
            Some("docs/adr/002-filesystem-snapshot-boundary.md")
        );
    }

    #[test]
    fn accepts_a_string_decision_reference_in_architecture_model_v2() {
        let mut value: serde_json::Value = serde_json::from_str(include_str!("../../../docs/architecture/model.json"))
            .unwrap_or_else(|error| panic!("architecture model fixture is valid JSON: {error}"));
        value["invariants"][0]["decision_ref"] = json!("docs/adr/example.md");
        assert!(validate_contract(Contract::ArchModelV2, &value).is_ok());
    }

    #[test]
    fn rejects_a_non_string_decision_reference_in_architecture_model_v2() {
        let mut value: serde_json::Value = serde_json::from_str(include_str!("../../../docs/architecture/model.json"))
            .unwrap_or_else(|error| panic!("architecture model fixture is valid JSON: {error}"));
        value["invariants"][0]["decision_ref"] = json!(42);
        assert!(matches!(
            validate_contract(Contract::ArchModelV2, &value),
            Err(SpecValidationError::SchemaViolation { .. })
        ));
    }

    #[test]
    fn contract_validation_diagnostic_names_the_selected_schema() {
        let Err(error) = validate_contract(Contract::ArchModelV2, &json!({})) else {
            panic!("empty document violates arch-model@2");
        };
        assert!(error.to_string().contains("arch-model@2"));
    }
}
