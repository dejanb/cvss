use anyhow::{anyhow, bail};
use cvss::{v2_0::CvssV2, v3::CvssV3, v4_0::CvssV4, AnyCvss, Cvss};
use indicatif::{ParallelProgressIterator, ProgressBar, ProgressStyle};
use rayon::prelude::*;
use serde::Deserialize;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use walkdir::WalkDir;

#[derive(Deserialize)]
struct CveRoot {
    containers: CnaContainers,
}

#[derive(Deserialize)]
struct CnaContainers {
    cna: Cna,
}

#[derive(Deserialize)]
struct Cna {
    metrics: Option<Vec<Metric>>,
}

#[derive(Deserialize)]
struct Metric {
    #[serde(rename = "cvssV3_1")]
    cvss_v3_1: Option<CvssV3>,
    #[serde(rename = "cvssV3_0")]
    cvss_v3_0: Option<CvssV3>,
    #[serde(rename = "cvssV2_0")]
    cvss_v2_0: Option<CvssV2>,
    #[serde(rename = "cvssV4_0")]
    cvss_v4_0: Option<CvssV4>,
}

#[test]
fn test_walkall() -> anyhow::Result<()> {
    let source = match env::var("CVE_BASE_DIR") {
        Ok(val) => val,
        Err(_) => {
            println!("CVE_BASE_DIR not set, skipping test");
            return Ok(());
        }
    };

    let walker = WalkDir::new(source).follow_links(true).contents_first(true);
    let mut files = Vec::new();

    for entry in walker {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        if entry.path().extension().and_then(OsStr::to_str) != Some("json") {
            continue;
        }
        let name = match entry.file_name().to_str() {
            None => continue,
            Some(name) => name,
        };
        if !name.starts_with("CVE-") {
            continue;
        }
        files.push(entry.into_path());
    }

    let pb = ProgressBar::new(files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg} {wide_bar} {pos}/{len} ({eta})")
            .unwrap(),
    );

    let failed_files = Mutex::new(Vec::new());

    files.into_par_iter().progress_with(pb).for_each(|file| {
        if let Err(e) = process(&file) {
            failed_files.lock().unwrap().push((file, e.to_string()));
        }
    });

    let failed = failed_files.lock().unwrap();
    if !failed.is_empty() {
        for (file, error) in failed.iter() {
            eprintln!("Failed to process file: {:?}, error: {}", file, error);
        }
        bail!("{} files failed to process", failed.len());
    }

    Ok(())
}

fn process(path: &Path) -> anyhow::Result<()> {
    let content = fs::read(path)?;
    let cve: CveRoot = serde_json::from_slice(&content)
        .map_err(|e| anyhow!("Failed to deserialize CVE: {}", e))?;

    if let Some(metrics) = cve.containers.cna.metrics {
        for metric in metrics {
            let cvss_objects: Vec<AnyCvss> = vec![
                metric.cvss_v3_1.map(AnyCvss::V3),
                metric.cvss_v3_0.map(AnyCvss::V3),
                metric.cvss_v2_0.map(AnyCvss::V2),
                metric.cvss_v4_0.map(AnyCvss::V4),
            ]
            .into_iter()
            .flatten()
            .collect();

            for cvss in cvss_objects {
                let score = cvss.base_score();
                if !(0.0..=10.0).contains(&score) {
                    bail!("Invalid base_score for CVSS v{}: {}", cvss.version(), score);
                }
            }
        }
    }

    Ok(())
}
