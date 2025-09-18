//! Represents the CVSS v4.0 specification.

use serde::{Deserialize, Serialize};

/// Represents a CVSS v4.0 score object.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CvssV4 {
    /// The version of the CVSS standard, which must be "4.0".
    pub version: String,
    /// The CVSS vector string.
    pub vector_string: String,
    /// The base score, a value between 0.0 and 10.0.
    pub base_score: f64,
    /// The qualitative severity rating for the base score.
    pub base_severity: Severity,

    // --- Base Metrics ---
    /// Attack Vector (AV).
    pub attack_vector: AttackVector,
    /// Attack Complexity (AC).
    pub attack_complexity: AttackComplexity,
    /// Attack Requirements (AT).
    pub attack_requirements: AttackRequirements,
    /// Privileges Required (PR).
    pub privileges_required: PrivilegesRequired,
    /// User Interaction (UI).
    pub user_interaction: UserInteraction,
    /// Vulnerable System Confidentiality Impact (VC).
    pub vuln_confidentiality_impact: Impact,
    /// Vulnerable System Integrity Impact (VI).
    pub vuln_integrity_impact: Impact,
    /// Vulnerable System Availability Impact (VA).
    pub vuln_availability_impact: Impact,
    /// Subsequent System Confidentiality Impact (SC).
    pub sub_confidentiality_impact: Impact,
    /// Subsequent System Integrity Impact (SI).
    pub sub_integrity_impact: Impact,
    /// Subsequent System Availability Impact (SA).
    pub sub_availability_impact: Impact,

    // --- Threat Metrics ---
    /// Exploit Maturity (E).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exploit_maturity: Option<ExploitMaturity>,

    // --- Environmental Metrics ---
    /// Confidentiality Requirement (CR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidentiality_requirement: Option<Requirement>,
    /// Integrity Requirement (IR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity_requirement: Option<Requirement>,
    /// Availability Requirement (AR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability_requirement: Option<Requirement>,
    /// Modified Attack Vector (MAV).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_vector: Option<AttackVector>,
    /// Modified Attack Complexity (MAC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_complexity: Option<AttackComplexity>,
    /// Modified Attack Requirements (MAT).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_attack_requirements: Option<AttackRequirements>,
    /// Modified Privileges Required (MPR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_privileges_required: Option<PrivilegesRequired>,
    /// Modified User Interaction (MUI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_user_interaction: Option<UserInteraction>,
    /// Modified Vulnerable System Confidentiality Impact (MVC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_vuln_confidentiality_impact: Option<Impact>,
    /// Modified Vulnerable System Integrity Impact (MVI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_vuln_integrity_impact: Option<Impact>,
    /// Modified Vulnerable System Availability Impact (MVA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_vuln_availability_impact: Option<Impact>,
    /// Modified Subsequent System Confidentiality Impact (MSC).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_sub_confidentiality_impact: Option<Impact>,
    /// Modified Subsequent System Integrity Impact (MSI).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_sub_integrity_impact: Option<Impact>,
    /// Modified Subsequent System Availability Impact (MSA).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_sub_availability_impact: Option<Impact>,

    // --- Supplemental Metrics ---
    #[serde(rename = "Safety")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety: Option<Safety>,
    #[serde(rename = "Automatable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automatable: Option<Automatable>,
    #[serde(rename = "Recovery")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery: Option<Recovery>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value_density: Option<ValueDensity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerability_response_effort: Option<VulnerabilityResponseEffort>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_urgency: Option<ProviderUrgency>,
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

/// Attack Vector (AV) / Modified Attack Vector (MAV).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttackVector {
    Network,
    Adjacent,
    Local,
    Physical,
}

/// Attack Complexity (AC) / Modified Attack Complexity (MAC).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackComplexity {
    Low,
    High,
}

/// Attack Requirements (AT) / Modified Attack Requirements (MAT).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AttackRequirements {
    None,
    Present,
}

/// Privileges Required (PR) / Modified Privileges Required (MPR).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

/// User Interaction (UI) / Modified User Interaction (MUI).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum UserInteraction {
    None,
    Passive,
    Active,
}

/// Impact metrics (VC, VI, VA, SC, SI, SA and their modified versions).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Impact {
    High,
    Low,
    None,
}

/// Exploit Maturity (E).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExploitMaturity {
    Attacked,
    ProofOfConcept,
    Unreported,
}

/// Requirement metrics (CR, IR, AR).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Requirement {
    High,
    Medium,
    Low,
}

/// Safety (S).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Safety {
    Negligible,
    Present,
    NotDefined,
}

/// Automatable (AU).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Automatable {
    No,
    Yes,
    NotDefined,
}

/// Recovery (R).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Recovery {
    Automatic,
    User,
    Irrecoverable,
    NotDefined,
}

/// Value Density (V).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValueDensity {
    Diffuse,
    Concentrated,
    NotDefined,
}

/// Vulnerability Response Effort (RE).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VulnerabilityResponseEffort {
    Low,
    Moderate,
    High,
    NotDefined,
}

/// Provider Urgency (U).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProviderUrgency {
    Clear,
    Green,
    Amber,
    Red,
    NotDefined,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JSON: &str = r#"{
        "version": "4.0",
        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
        "baseScore": 9.3,
        "baseSeverity": "CRITICAL",
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "attackRequirements": "NONE",
        "privilegesRequired": "NONE",
        "userInteraction": "NONE",
        "vulnConfidentialityImpact": "HIGH",
        "vulnIntegrityImpact": "HIGH",
        "vulnAvailabilityImpact": "HIGH",
        "subConfidentialityImpact": "NONE",
        "subIntegrityImpact": "NONE",
        "subAvailabilityImpact": "NONE"
    }"#;

    const CVE_SAMPLE_JSON: &str = r#"{
        "Automatable": "NOT_DEFINED",
        "Recovery": "NOT_DEFINED",
        "Safety": "NOT_DEFINED",
        "attackComplexity": "LOW",
        "attackRequirements": "PRESENT",
        "attackVector": "NETWORK",
        "baseScore": 5.9,
        "baseSeverity": "MEDIUM",
        "privilegesRequired": "LOW",
        "providerUrgency": "NOT_DEFINED",
        "subAvailabilityImpact": "NONE",
        "subConfidentialityImpact": "NONE",
        "subIntegrityImpact": "NONE",
        "userInteraction": "PASSIVE",
        "valueDensity": "NOT_DEFINED",
        "vectorString": "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N",
        "version": "4.0",
        "vulnAvailabilityImpact": "NONE",
        "vulnConfidentialityImpact": "HIGH",
        "vulnIntegrityImpact": "LOW",
        "vulnerabilityResponseEffort": "NOT_DEFINED"
    }"#;

    fn sample_cvss_v4() -> CvssV4 {
        CvssV4 {
            version: "4.0".to_string(),
            vector_string: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
                .to_string(),
            base_score: 9.3,
            base_severity: Severity::Critical,
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            attack_requirements: AttackRequirements::None,
            privileges_required: PrivilegesRequired::None,
            user_interaction: UserInteraction::None,
            vuln_confidentiality_impact: Impact::High,
            vuln_integrity_impact: Impact::High,
            vuln_availability_impact: Impact::High,
            sub_confidentiality_impact: Impact::None,
            sub_integrity_impact: Impact::None,
            sub_availability_impact: Impact::None,
            exploit_maturity: None,
            confidentiality_requirement: None,
            integrity_requirement: None,
            availability_requirement: None,
            modified_attack_vector: None,
            modified_attack_complexity: None,
            modified_attack_requirements: None,
            modified_privileges_required: None,
            modified_user_interaction: None,
            modified_vuln_confidentiality_impact: None,
            modified_vuln_integrity_impact: None,
            modified_vuln_availability_impact: None,
            modified_sub_confidentiality_impact: None,
            modified_sub_integrity_impact: None,
            modified_sub_availability_impact: None,
            safety: None,
            automatable: None,
            recovery: None,
            value_density: None,
            vulnerability_response_effort: None,
            provider_urgency: None,
        }
    }

    #[test]
    fn test_deserialize_v4_0() {
        let cvss: CvssV4 = serde_json::from_str(SAMPLE_JSON).unwrap();
        assert_eq!(cvss, sample_cvss_v4());
    }

    #[test]
    fn test_deserialize_cve_v4_0() {
        let cvss: CvssV4 = serde_json::from_str(CVE_SAMPLE_JSON).unwrap();
        let expected = CvssV4 {
            version: "4.0".to_string(),
            vector_string: "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:H/VI:L/VA:N/SC:N/SI:N/SA:N"
                .to_string(),
            base_score: 5.9,
            base_severity: Severity::Medium,
            attack_vector: AttackVector::Network,
            attack_complexity: AttackComplexity::Low,
            attack_requirements: AttackRequirements::Present,
            privileges_required: PrivilegesRequired::Low,
            user_interaction: UserInteraction::Passive,
            vuln_confidentiality_impact: Impact::High,
            vuln_integrity_impact: Impact::Low,
            vuln_availability_impact: Impact::None,
            sub_confidentiality_impact: Impact::None,
            sub_integrity_impact: Impact::None,
            sub_availability_impact: Impact::None,
            exploit_maturity: None,
            confidentiality_requirement: None,
            integrity_requirement: None,
            availability_requirement: None,
            modified_attack_vector: None,
            modified_attack_complexity: None,
            modified_attack_requirements: None,
            modified_privileges_required: None,
            modified_user_interaction: None,
            modified_vuln_confidentiality_impact: None,
            modified_vuln_integrity_impact: None,
            modified_vuln_availability_impact: None,
            modified_sub_confidentiality_impact: None,
            modified_sub_integrity_impact: None,
            modified_sub_availability_impact: None,
            safety: Some(Safety::NotDefined),
            automatable: Some(Automatable::NotDefined),
            recovery: Some(Recovery::NotDefined),
            value_density: Some(ValueDensity::NotDefined),
            vulnerability_response_effort: Some(VulnerabilityResponseEffort::NotDefined),
            provider_urgency: Some(ProviderUrgency::NotDefined),
        };
        assert_eq!(cvss, expected);
    }

    #[test]
    fn test_serialize_v4_0() {
        let cvss = sample_cvss_v4();
        let json = serde_json::to_string_pretty(&cvss).unwrap();
        assert!(json.contains(r#""version": "4.0""#));
        assert!(json.contains(r#""baseScore": 9.3"#));
        assert!(json.contains(r#""baseSeverity": "CRITICAL""#));
    }

    #[test]
    fn test_roundtrip_v4_0() {
        let cvss: CvssV4 = serde_json::from_str(SAMPLE_JSON).unwrap();
        let json = serde_json::to_string(&cvss).unwrap();
        let cvss_rt: CvssV4 = serde_json::from_str(&json).unwrap();
        assert_eq!(cvss, cvss_rt);
    }
}
