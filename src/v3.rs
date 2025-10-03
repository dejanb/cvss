//! Represents the CVSS v3.0 and v3.1 specifications.

use serde::{Deserialize, Serialize};

use crate::version::VersionV3;

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
    pub attack_vector: AttackVector,
    /// The attack complexity metric.
    pub attack_complexity: AttackComplexity,
    /// The privileges required metric.
    pub privileges_required: PrivilegesRequired,
    /// The user interaction metric.
    pub user_interaction: UserInteraction,
    /// The scope metric.
    pub scope: Scope,
    /// The confidentiality impact metric.
    pub confidentiality_impact: Impact,
    /// The integrity impact metric.
    pub integrity_impact: Impact,
    /// The availability impact metric.
    pub availability_impact: Impact,

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
#[serde(rename_all = "UPPERCASE")]
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
#[serde(rename_all = "UPPERCASE")]
pub enum UserInteraction {
    None,
    Required,
    NotDefined,
}

/// Represents the scope metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Scope {
    Unchanged,
    Changed,
    NotDefined,
}

/// Represents the impact metrics (confidentiality, integrity, availability).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
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
#[serde(rename_all = "UPPERCASE")]
pub enum ReportConfidence {
    Unknown,
    Reasonable,
    Confirmed,
    NotDefined,
}

/// Represents the security requirement metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum SecurityRequirement {
    Low,
    Medium,
    High,
    NotDefined,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::version::VersionV3;

    const SAMPLE_JSON_V3_1: &str = r#"{
        "version": "3.1",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH",
        "availabilityImpact": "HIGH",
        "baseScore": 9.8,
        "baseSeverity": "CRITICAL"
    }"#;

    const SAMPLE_JSON_V3_0: &str = r#"{
        "version": "3.0",
        "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH",
        "availabilityImpact": "HIGH",
        "baseScore": 9.8,
        "baseSeverity": "CRITICAL"
    }"#;

    fn sample_cvss_v3() -> CvssV3 {
        CvssV3 {
            version: VersionV3::V3_1,
            vector_string: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            scope: Scope::Unchanged,
            confidentiality_impact: Impact::High,
            integrity_impact: Impact::High,
            availability_impact: Impact::High,
            base_score: 9.8,
            base_severity: Severity::Critical,
            temporal_score: None,
            temporal_severity: None,
            exploit_code_maturity: None,
            remediation_level: None,
            report_confidence: None,
            environmental_score: None,
            environmental_severity: None,
            confidentiality_requirement: None,
            integrity_requirement: None,
            availability_requirement: None,
            modified_attack_vector: None,
            modified_attack_complexity: None,
            modified_privileges_required: None,
            modified_user_interaction: None,
            modified_scope: None,
            modified_confidentiality_impact: None,
            modified_integrity_impact: None,
            modified_availability_impact: None,
        }
    }

    #[test]
    fn test_deserialize_v3_1() {
        let cvss: CvssV3 = serde_json::from_str(SAMPLE_JSON_V3_1).unwrap();
        assert_eq!(cvss, sample_cvss_v3());
    }

    #[test]
    fn test_deserialize_v3_0() {
        let mut expected = sample_cvss_v3();
        expected.version = VersionV3::V3_0;
        expected.vector_string = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string();
        let cvss: CvssV3 = serde_json::from_str(SAMPLE_JSON_V3_0).unwrap();
        assert_eq!(cvss, expected);
    }

    #[test]
    fn test_serialize_v3() {
        let cvss = sample_cvss_v3();
        let json = serde_json::to_string_pretty(&cvss).unwrap();
        assert!(json.contains(r#""version": "3.1""#));
        assert!(json.contains(r#""baseScore": 9.8"#));
        assert!(json.contains(r#""baseSeverity": "CRITICAL""#));
        assert!(!json.contains(r#""temporalScore""#));
    }

    #[test]
    fn test_roundtrip_v3() {
        let cvss: CvssV3 = serde_json::from_str(SAMPLE_JSON_V3_1).unwrap();
        let json = serde_json::to_string(&cvss).unwrap();
        let cvss_rt: CvssV3 = serde_json::from_str(&json).unwrap();
        assert_eq!(cvss, cvss_rt);
    }
}
