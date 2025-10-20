use cvss::v3::AttackVector;

#[test]
fn test_v3_1_critical() {
    let input_json = include_str!("data/v3_1_critical.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V3_1);
    assert_eq!(cvss.base_score(), 9.8);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Critical);
}

#[test]
fn test_v3_0_critical() {
    let input_json = include_str!("data/v3_0_critical.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V3_0);
    assert_eq!(cvss.base_score(), 9.8);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Critical);
}

#[test]
fn test_v3_1_medium() {
    let input_json = include_str!("data/v3_1_medium.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V3_1);
    assert_eq!(cvss.base_score(), 5.8);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Medium);

    // Custom assertion for v3_1_medium
    if let cvss::Cvss::V3_1(c) = cvss {
        assert_eq!(c.attack_vector, Some(AttackVector::Local));
    } else {
        panic!("Wrong enum variant");
    }
}

#[test]
fn test_v3_environmental() {
    let input_json = include_str!("data/v3_environmental.json");
    let cvss: cvss::Cvss = serde_json::from_str(input_json).unwrap();

    assert_eq!(cvss.version(), cvss::Version::V3_1);
    assert_eq!(cvss.base_score(), 9.6);
    assert_eq!(cvss.base_severity().unwrap(), cvss::Severity::Critical);
}
