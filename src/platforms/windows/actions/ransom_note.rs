use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;
use anyhow::{Context, Result};
use chrono::Utc;
use dirs::desktop_dir;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

/// Create a benign "ransom note" text file on the current user's Desktop.
/// The content is clearly labeled as a test artifact with MAGNET metadata.
#[derive(Default)]
pub struct RansomNote;

impl RansomNote {
    fn build_note_content(test_id: &str) -> String {
        let now = Utc::now().to_rfc3339();
        let lines = vec![
            "=== MAGNET RANSOM-NOTE SIMULATION ===".to_string(),
            "".to_string(),
            "THIS IS A BENIGN TEST ARTIFACT CREATED BY THE MAGNET TOOL.".to_string(),
            "DO NOT RESPOND — this file is safe and created for purple-team testing.".to_string(),
            "".to_string(),
            format!("MAGNET-TEST-ID: {}", test_id),
            format!("TIMESTAMP: {}", now),
            "".to_string(),
            "To the SOC: This artifact is used to validate detection, ingestion and response.".to_string(),
            "".to_string(),
            "=== END OF NOTE ===".to_string(),
        ];
        lines.join("\r\n")
    }

    fn desktop_path() -> Option<PathBuf> {
        desktop_dir()
    }

    fn note_path(desktop: &PathBuf) -> PathBuf {
        desktop.join("RANSOM_NOTE.txt")
    }
}

impl Simulation for RansomNote {
    fn name(&self) -> &'static str {
        "windows::ransom_note"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let test_id = &cfg.test_id;
        let content = Self::build_note_content(test_id);

        let desktop = Self::desktop_path().context("could not determine Desktop path")?;
        let path = Self::note_path(&desktop);

        // Minimal, one-line status: starting action
        logger::action_running("Writing ransom note to Desktop");

        // Dry-run: only record and show minimal status
        if cfg.dry_run {
            logger::info(&format!("dry-run: would write to {}", path.display()));

            // still record an action entry to telemetry in dry-run mode
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "ransom_note".into(),
                status: "dry-run".into(),
                details: "dry-run: no file written".into(),
                artifact_path: Some(path.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);

            logger::action_ok();
            return Ok(());
        }

        // Try to write the file
        match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .with_context(|| format!("failed to open file {}", path.display()))
        {
            Ok(mut file) => {
                if let Err(e) = file.write_all(content.as_bytes())
                    .with_context(|| format!("failed to write to {}", path.display()))
                {
                    logger::action_fail("failed to write ransom note");
                    // record failure to telemetry
                    let rec = ActionRecord {
                        test_id: cfg.test_id.clone(),
                        timestamp: Utc::now().to_rfc3339(),
                        action: "ransom_note".into(),
                        status: "failed".into(),
                        details: format!("write error: {}", e),
                        artifact_path: Some(path.display().to_string()),
                    };
                    let _ = write_action_record(cfg, &rec);
                    return Err(e);
                }

                // success
                logger::action_ok();

                // Write telemetry record for this action
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: "ransom_note".into(),
                    status: "written".into(),
                    details: format!("Wrote ransom note to Desktop: {}", path.display()),
                    artifact_path: Some(path.display().to_string()),
                };

                if let Err(e) = write_action_record(cfg, &rec) {
                    logger::warn(&format!("failed to write telemetry record: {}", e));
                }

                Ok(())
            }
            Err(e) => {
                logger::action_fail("failed to open ransom note file");
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: "ransom_note".into(),
                    status: "failed".into(),
                    details: format!("open error: {}", e),
                    artifact_path: Some(path.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);
                Err(e)
            }
        }
    }
}
