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
//! use cvss::v3_1::{CvssV3_1, Severity};
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
//! let cvss: CvssV3_1 = serde_json::from_str(json_data).unwrap();
//!
//! assert_eq!(cvss.version, "3.1");
//! assert_eq!(cvss.base_score, 9.8);
//! assert_eq!(cvss.base_severity, Severity::Critical);
//! ```

#![forbid(unsafe_code)]

pub mod v2_0;
pub mod v3_0;
pub mod v3_1;
pub mod v4_0;
