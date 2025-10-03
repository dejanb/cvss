use serde::Deserialize;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

#[derive(Deserialize)]
struct TestCase {
    name: String,
    input: serde_json::Value,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    version: String,
    base_score: f64,
    base_severity: String,
}

fn main() {
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated_tests.rs");

    let test_data_path = "tests/v3_test_data.json";
    let test_data = fs::read_to_string(test_data_path).unwrap();
    let test_cases: Vec<TestCase> = serde_json::from_str(&test_data).unwrap();

    let mut generated_code = Vec::new();
    for case in &test_cases {
        writeln!(&mut generated_code, "#[test]").unwrap();
        writeln!(&mut generated_code, "fn test_{}() {{", case.name).unwrap();
        write!(&mut generated_code, "    let input_json = r#\"").unwrap();
        generated_code
            .write_all(case.input.to_string().as_bytes())
            .unwrap();
        writeln!(&mut generated_code, "\"#;").unwrap();
        writeln!(
            &mut generated_code,
            "    let cvss: CvssV3 = serde_json::from_str(input_json).unwrap();\n"
        )
        .unwrap();

        writeln!(
            &mut generated_code,
            "    assert_eq!(cvss.version, VersionV3::{});",
            case.expected.version
        )
        .unwrap();
        writeln!(
            &mut generated_code,
            "    assert_eq!(cvss.base_score, {});",
            case.expected.base_score
        )
        .unwrap();
        writeln!(
            &mut generated_code,
            "    assert_eq!(cvss.base_severity, Severity::{});",
            case.expected.base_severity
        )
        .unwrap();

        if case.name == "v3_1_medium" {
            writeln!(
                &mut generated_code,
                "\n    // Custom assertion for {}",
                case.name
            )
            .unwrap();
            writeln!(
                &mut generated_code,
                "    assert_eq!(cvss.attack_vector, AttackVector::Local);"
            )
            .unwrap();
        }

        writeln!(&mut generated_code, "}}\n").unwrap();
    }

    fs::write(&dest_path, generated_code).unwrap();
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed={test_data_path}");
}
