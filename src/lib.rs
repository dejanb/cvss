//! A Rust library for representing and deserializing CVSS data.
//!
//! This crate provides Rust types that map directly to the official
//! JSON schema representations for CVSS versions 2.0, 3.0, 3.1, and 4.0.
//!
//! # Example
//!
//! Deserializing a CVSS v3.1 JSON object:
//!
//! ```
//! use cvss::v3::{CvssV3, Severity};
//! use cvss::version::VersionV3;
//!
//! let json_data = r#"{
//!   "version": "3.1",
//!   "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
//!   "attackVector": "NETWORK",
//!   "attackComplexity": "LOW",
//!   "privilegesRequired": "NONE",
//!   "userInteraction": "NONE",
//!   "scope": "UNCHANGED",
//!   "confidentialityImpact": "HIGH",
//!   "integrityImpact": "HIGH",
//!   "availabilityImpact": "HIGH",
//!   "baseScore": 9.8,
//!   "baseSeverity": "CRITICAL"
//! }"#;
//!
//! let cvss: CvssV3 = serde_json::from_str(json_data).unwrap();
//!
//! assert_eq!(cvss.version, VersionV3::V3_1);
//! assert_eq!(cvss.base_score, 9.8);
//! assert_eq!(cvss.base_severity, Severity::Critical);
//! ```

pub mod v2_0;
pub mod v3;
pub mod v4_0;
pub mod version;

/// An enum to hold any version of a CVSS object.
pub enum AnyCvss {
    V2(v2_0::CvssV2),
    V3(v3::CvssV3),
    V4(v4_0::CvssV4),
}

/// Represents the qualitative severity rating of a vulnerability.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// A trait for abstracting over different CVSS versions.
pub trait Cvss {
    /// Returns the version of the CVSS standard.
    fn version(&self) -> version::Version;
    /// Returns the CVSS vector string.
    fn vector_string(&self) -> &str;
    /// Returns the base score.
    fn base_score(&self) -> f64;
    /// Returns the base severity.
    fn base_severity(&self) -> Option<Severity>;
}

impl Cvss for AnyCvss {
    fn version(&self) -> version::Version {
        match self {
            AnyCvss::V2(c) => c.version(),
            AnyCvss::V3(c) => c.version(),
            AnyCvss::V4(c) => c.version(),
        }
    }

    fn vector_string(&self) -> &str {
        match self {
            AnyCvss::V2(c) => c.vector_string(),
            AnyCvss::V3(c) => c.vector_string(),
            AnyCvss::V4(c) => c.vector_string(),
        }
    }

    fn base_score(&self) -> f64 {
        match self {
            AnyCvss::V2(c) => c.base_score(),
            AnyCvss::V3(c) => c.base_score(),
            AnyCvss::V4(c) => c.base_score(),
        }
    }

    fn base_severity(&self) -> Option<Severity> {
        match self {
            AnyCvss::V2(c) => c.base_severity(),
            AnyCvss::V3(c) => c.base_severity(),
            AnyCvss::V4(c) => c.base_severity(),
        }
    }
}
