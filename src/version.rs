use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Display, EnumString)]
pub enum VersionV2 {
    #[serde(rename = "2.0")]
    #[strum(serialize = "2.0")]
    V2_0,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Display, EnumString)]
pub enum VersionV3 {
    #[serde(rename = "3.0")]
    #[strum(serialize = "3.0")]
    V3_0,
    #[serde(rename = "3.1")]
    #[strum(serialize = "3.1")]
    V3_1,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, Display, EnumString)]
pub enum VersionV4 {
    #[serde(rename = "4.0")]
    #[strum(serialize = "4.0")]
    V4_0,
}
