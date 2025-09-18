//! Represents the CVSS v3.0 specification.

use serde::{Deserialize, Serialize};

/// Represents a CVSS v3.0 score object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV3 {
    /// The version of the CVSS standard.
    pub version: String,
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
}

/// Represents the qualitative severity rating of a vulnerability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
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
}

/// Represents the attack complexity metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackComplexity {
    Low,
    High,
}

/// Represents the privileges required metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

/// Represents the user interaction metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum UserInteraction {
    None,
    Required,
}

/// Represents the scope metric.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Scope {
    Unchanged,
    Changed,
}

/// Represents the impact metrics (confidentiality, integrity, availability).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Impact {
    High,
    Low,
    None,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JSON: &str = r#"{
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
        "baseSeverity": "Critical"
    }"#;

    fn sample_cvss_v3() -> CvssV3 {
        CvssV3 {
            version: "3.0".to_string(),
            vector_string: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string(),
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
        }
    }

    #[test]
    fn test_deserialize_v3_0() {
        let cvss: CvssV3 = serde_json::from_str(SAMPLE_JSON).unwrap();
        assert_eq!(cvss, sample_cvss_v3());
    }

    #[test]
    fn test_serialize_v3_0() {
        let cvss = sample_cvss_v3();
        let json = serde_json::to_string_pretty(&cvss).unwrap();
        assert!(json.contains(r#""version": "3.0""#));
        assert!(json.contains(r#""baseScore": 9.8"#));
        assert!(json.contains(r#""baseSeverity": "Critical""#));
    }

    #[test]
    fn test_roundtrip_v3_0() {
        let cvss: CvssV3 = serde_json::from_str(SAMPLE_JSON).unwrap();
        let json = serde_json::to_string(&cvss).unwrap();
        let cvss_rt: CvssV3 = serde_json::from_str(&json).unwrap();
        assert_eq!(cvss, cvss_rt);
    }
}
