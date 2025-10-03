//! Represents the CVSS v2.0 specification.

use serde::{Deserialize, Serialize};

use crate::version::VersionV2;

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
    pub access_vector: AccessVector,
    /// The access complexity metric.
    pub access_complexity: AccessComplexity,
    /// The authentication metric.
    pub authentication: Authentication,
    /// The confidentiality impact metric.
    pub confidentiality_impact: Impact,
    /// The integrity impact metric.
    pub integrity_impact: Impact,
    /// The availability impact metric.
    pub availability_impact: Impact,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::VersionV2;

    const SAMPLE_JSON: &str = r#"{
        "version": "2.0",
        "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
        "accessVector": "NETWORK",
        "accessComplexity": "LOW",
        "authentication": "NONE",
        "confidentialityImpact": "PARTIAL",
        "integrityImpact": "PARTIAL",
        "availabilityImpact": "PARTIAL",
        "baseScore": 7.5,
        "severity": "High"
    }"#;

    fn sample_cvss_v2() -> CvssV2 {
        CvssV2 {
            version: VersionV2::V2_0,
            vector_string: "AV:N/AC:L/Au:N/C:P/I:P/A:P".to_string(),
            access_vector: AccessVector::Network,
            access_complexity: AccessComplexity::Low,
            authentication: Authentication::None,
            confidentiality_impact: Impact::Partial,
            integrity_impact: Impact::Partial,
            availability_impact: Impact::Partial,
            base_score: 7.5,
            severity: Some(Severity::High),
            temporal_score: None,
            environmental_score: None,
        }
    }

    #[test]
    fn test_deserialize_v2_0() {
        let cvss: CvssV2 = serde_json::from_str(SAMPLE_JSON).unwrap();
        assert_eq!(cvss, sample_cvss_v2());
    }

    #[test]
    fn test_serialize_v2_0() {
        let cvss = sample_cvss_v2();
        let json = serde_json::to_string_pretty(&cvss).unwrap();
        // Note: The order of fields in the serialized JSON is not guaranteed.
        // A full roundtrip test is more robust.
        assert!(json.contains(r#""version": "2.0""#));
        assert!(json.contains(r#""baseScore": 7.5"#));
    }

    #[test]
    fn test_roundtrip_v2_0() {
        let cvss: CvssV2 = serde_json::from_str(SAMPLE_JSON).unwrap();
        let json = serde_json::to_string(&cvss).unwrap();
        let cvss_rt: CvssV2 = serde_json::from_str(&json).unwrap();
        assert_eq!(cvss, cvss_rt);
    }
}
