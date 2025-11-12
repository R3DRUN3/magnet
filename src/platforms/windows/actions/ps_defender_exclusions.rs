//! Adds Windows Defender exclusion paths via PowerShell for testing and simulation.

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;
use anyhow::{Context, Result};
use chrono::Utc;
use std::env;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

/// Adds Windows Defender exclusions for specific user folders and logs telemetry.
#[derive(Default)]
pub struct PsDefenderExclusions;

impl PsDefenderExclusions {
    fn retrieve_defender_path_exclusions() -> Result<String> {
        let output = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-MpPreference | Select -ExpandProperty ExclusionPath",
            ])
            .output()
            .context("Failed to run PowerShell to get Defender exclusions")?;

        let list = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(list)
    }

    fn add_exclusions() -> Result<()> {
        let userprofile = env::var("USERPROFILE").unwrap_or_else(|_| "C:\\".into());
        let desktop = format!("{}\\Desktop\\Magnet", userprofile);
        let documents = format!("{}\\Documents\\Magnet", userprofile);
        let downloads = format!("{}\\Downloads\\Magnet", userprofile);

        let ps_script = format!(
            "Add-MpPreference -ExclusionPath '{}','{}','{}'",
            desktop, documents, downloads
        );

        let status = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &ps_script,
            ])
            .status()
            .context("Failed to execute PowerShell command")?;

        if status.success() {
            logger::info("✅ Defender exclusions added successfully.");
        } else {
            logger::warn("❌ Failed to add exclusions. Run as Administrator.");
        }

        Ok(())
    }

    fn telemetry_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn write_detailed_telemetry(cfg: &Config, details: &str) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir)
            .with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        let mut log = dir.clone();
        log.push(format!("ps_defender_exclusions_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .with_context(|| format!("opening telemetry log {}", log.display()))?;

        writeln!(lf, "============================================================")?;
        writeln!(lf, "TEST ID   : {}", cfg.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", Utc::now().to_rfc3339())?;
        writeln!(lf, "DETAILS   : {}", details)?;
        writeln!(lf)?;

        Ok(())
    }
}

impl Simulation for PsDefenderExclusions {
    fn name(&self) -> &'static str {
        "windows::ps_defender_exclusions"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Adding Windows Defender exclusions via PowerShell");

        if cfg.dry_run {
            logger::info("dry-run: would execute PowerShell to add Defender exclusions");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "ps_defender_exclusions".into(),
                status: "dry-run".into(),
                details: "dry-run: no PowerShell executed".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // 1) Add exclusions
        if let Err(e) = Self::add_exclusions() {
            logger::action_fail("failed to add Defender exclusions");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "ps_defender_exclusions".into(),
                status: "failed".into(),
                details: format!("add_exclusions error: {}", e),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            return Err(e);
        }

        // 2) Retrieve and log exclusions
        let exclusions = match Self::retrieve_defender_path_exclusions() {
            Ok(list) => list,
            Err(e) => {
                logger::warn(&format!("failed to retrieve exclusions: {}", e));
                "<failed to retrieve>".into()
            }
        };

        // Write telemetry
        if let Err(e) = Self::write_detailed_telemetry(cfg, &exclusions) {
            logger::warn(&format!("failed to write detailed telemetry: {}", e));
        }

        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: "ps_defender_exclusions".into(),
            status: "written".into(),
            details: "Successfully added Defender exclusions".into(),
            artifact_path: None,
        };
        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
