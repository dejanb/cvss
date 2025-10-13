//! Represents the CVSS v2.0 specification.

use serde::{Deserialize, Serialize};

use crate::version::VersionV2;
use crate::Cvss;
use crate::Severity as UnifiedSeverity;

/// Represents a CVSS v2.0 score object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV2 {
    /// The version of the CVSS standard.
    pub version: VersionV2,
    /// The CVSS vector string.
    pub vector_string: String,
    /// The qualitative severity rating.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// The base score, a value between 0.0 and 10.0.
    pub base_score: f64,
    /// The temporal score, a value between 0.0 and 10.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temporal_score: Option<f64>,
    /// The environmental score, a value between 0.0 and 10.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environmental_score: Option<f64>,
    /// The access vector metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_vector: Option<AccessVector>,
    /// The access complexity metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_complexity: Option<AccessComplexity>,
    /// The authentication metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Authentication>,
    /// The confidentiality impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_impact: Option<Impact>,
    /// The integrity impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_impact: Option<Impact>,
    /// The availability impact metric.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_impact: Option<Impact>,
}

/// Represents the qualitative severity rating of a vulnerability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

/// Represents the access vector metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessVector {
    Network,
    AdjacentNetwork,
    Local,
}

/// Represents the access complexity metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AccessComplexity {
    High,
    Medium,
    Low,
}

/// Represents the authentication metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Authentication {
    Multiple,
    Single,
    None,
}

/// Represents the impact metrics (confidentiality, integrity, availability).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Impact {
    None,
    Partial,
    Complete,
}

impl Cvss for CvssV2 {
    fn version(&self) -> crate::version::Version {
        match self.version {
            VersionV2::V2_0 => crate::version::Version::V2_0,
        }
    }

    fn vector_string(&self) -> &str {
        &self.vector_string
    }

    fn base_score(&self) -> f64 {
        self.base_score
    }

    fn base_severity(&self) -> Option<UnifiedSeverity> {
        self.severity.as_ref().map(|s| match s {
            Severity::Low => UnifiedSeverity::Low,
            Severity::Medium => UnifiedSeverity::Medium,
            Severity::High => UnifiedSeverity::High,
        })
    }
}
