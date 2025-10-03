use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VersionV2 {
    #[serde(rename = "2.0")]
    V2_0,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VersionV3 {
    #[serde(rename = "3.0")]
    V3_0,
    #[serde(rename = "3.1")]
    V3_1,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum VersionV4 {
    #[serde(rename = "4.0")]
    V4_0,
}
