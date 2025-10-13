use serde::{Deserialize, Serialize};
use std::fmt;

/// Represents a unified CVSS version across all specifications.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    V2_0,
    V3_0,
    V3_1,
    V4_0,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Version::V2_0 => write!(f, "2.0"),
            Version::V3_0 => write!(f, "3.0"),
            Version::V3_1 => write!(f, "3.1"),
            Version::V4_0 => write!(f, "4.0"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VersionV2 {
    #[serde(rename = "2.0")]
    V2_0,
}

impl fmt::Display for VersionV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionV2::V2_0 => write!(f, "2.0"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VersionV3 {
    #[serde(rename = "3.0")]
    V3_0,
    #[serde(rename = "3.1")]
    V3_1,
}

impl fmt::Display for VersionV3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionV3::V3_0 => write!(f, "3.0"),
            VersionV3::V3_1 => write!(f, "3.1"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VersionV4 {
    #[serde(rename = "4.0")]
    V4_0,
}

impl fmt::Display for VersionV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionV4::V4_0 => write!(f, "4.0"),
        }
    }
}
