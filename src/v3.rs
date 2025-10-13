//! Represents the CVSS v3.0 and v3.1 specifications.

use serde::{Deserialize, Serialize};

use crate::version::VersionV3;
use crate::Cvss;
use crate::Severity as UnifiedSeverity;

/// Represents a CVSS v3.0 or v3.1 score object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV3 {
    /// The version of the CVSS standard.
    pub version: VersionV3,
    /// The CVSS vector string.
    pub vector_string: String,
    /// The base score, a value between 0.0 and 10.0.
    pub base_score: f64,
    /// The qualitative severity rating for the base score.
    pub base_severity: Severity,
    /// The attack vector metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_vector: Option<AttackVector>,
    /// The attack complexity metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attack_complexity: Option<AttackComplexity>,
    /// The privileges required metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges_required: Option<PrivilegesRequired>,
    /// The user interaction metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_interaction: Option<UserInteraction>,
    /// The scope metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// The confidentiality impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_impact: Option<Impact>,
    /// The integrity impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_impact: Option<Impact>,
    /// The availability impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_impact: Option<Impact>,

    // Temporal Metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal_severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exploit_code_maturity: Option<ExploitCodeMaturity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_level: Option<RemediationLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_confidence: Option<ReportConfidence>,

    // Environmental Metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environmental_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environmental_severity: Option<Severity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_requirement: Option<SecurityRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_requirement: Option<SecurityRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_requirement: Option<SecurityRequirement>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_vector: Option<AttackVector>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_complexity: Option<AttackComplexity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_privileges_required: Option<PrivilegesRequired>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_user_interaction: Option<UserInteraction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_scope: Option<Scope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_confidentiality_impact: Option<Impact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_integrity_impact: Option<Impact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_availability_impact: Option<Impact>,
}

/// Represents the qualitative severity rating of a vulnerability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// Represents the attack vector metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackVector {
    Network,
    AdjacentNetwork,
    Local,
    Physical,
    NotDefined,
}

/// Represents the attack complexity metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackComplexity {
    Low,
    High,
    NotDefined,
}

/// Represents the privileges required metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
    NotDefined,
}

/// Represents the user interaction metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserInteraction {
    None,
    Required,
    NotDefined,
}

/// Represents the scope metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Scope {
    Unchanged,
    Changed,
    NotDefined,
}

/// Represents the impact metrics (confidentiality, integrity, availability).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Impact {
    High,
    Low,
    None,
    NotDefined,
}

/// Represents the exploit code maturity metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExploitCodeMaturity {
    Unproven,
    ProofOfConcept,
    Functional,
    High,
    NotDefined,
}

/// Represents the remediation level metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RemediationLevel {
    OfficialFix,
    TemporaryFix,
    Workaround,
    Unavailable,
    NotDefined,
}

/// Represents the report confidence metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportConfidence {
    Unknown,
    Reasonable,
    Confirmed,
    NotDefined,
}

/// Represents the security requirement metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SecurityRequirement {
    Low,
    Medium,
    High,
    NotDefined,
}

impl Cvss for CvssV3 {
    fn version(&self) -> crate::version::Version {
        match self.version {
            VersionV3::V3_0 => crate::version::Version::V3_0,
            VersionV3::V3_1 => crate::version::Version::V3_1,
        }
    }

    fn vector_string(&self) -> &str {
        &self.vector_string
    }

    fn base_score(&self) -> f64 {
        self.base_score
    }

    fn base_severity(&self) -> Option<UnifiedSeverity> {
        Some(match self.base_severity {
            Severity::None => UnifiedSeverity::None,
            Severity::Low => UnifiedSeverity::Low,
            Severity::Medium => UnifiedSeverity::Medium,
            Severity::High => UnifiedSeverity::High,
            Severity::Critical => UnifiedSeverity::Critical,
        })
    }
}
