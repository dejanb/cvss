#[test]
fn test_v4_0_example() {
    let input_json = include_str!("data/v4_0_example.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V4);
    assert_eq!(cvss.base_score(), 9.3);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Critical);
}

#[test]
fn test_v4_0_cve_example() {
    let input_json = include_str!("data/v4_0_cve_example.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V4);
    assert_eq!(cvss.base_score(), 5.9);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Medium);
}

#[test]
fn test_v4_0_minimal() {
    let input_json = include_str!("data/v4_0_minimal.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V4);
    assert_eq!(cvss.base_score(), 9.9);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Critical);
}
