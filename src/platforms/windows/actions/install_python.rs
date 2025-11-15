//! Ensures winget is preconfigured and installs Python automatically (T1105).
//! Needs admin rights for full automation.

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::fs;
use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command};
use dirs::home_dir;

/// Telemetry record for the python-installer module.
#[derive(Serialize)]
struct PythonInstallTelemetry {
    test_id: String,
    timestamp: String,
    settings_path: String,
    winget_status: String,
    elapsed_ms: u128,
    parent: String,
}

/// Module type
#[derive(Default)]
pub struct InstallPythonSimulation;

impl InstallPythonSimulation {
    /// Location for Winget settings.json
    fn winget_settings_path() -> Result<PathBuf> {
        let localappdata = std::env::var("LOCALAPPDATA")
            .context("LOCALAPPDATA not set")?;

        let p = Path::new(&localappdata)
            .join("Packages")
            .join("Microsoft.DesktopAppInstaller_8wekyb3d8bbwe")
            .join("LocalState")
            .join("settings.json");

        Ok(p)
    }

    /// Telemetry directory
    fn telemetry_dir() -> Option<PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    /// Write JSONL + LOG files
    fn write_detailed_telemetry(cfg: &Config, rec: &PythonInstallTelemetry) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry path"))?;
        create_dir_all(&dir)
            .with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        // JSONL
        let mut jsonl = dir.clone();
        jsonl.push(format!("install_python_{}.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl)
            .with_context(|| format!("opening telemetry file {}", jsonl.display()))?;
        let j = serde_json::to_string(rec)?;
        writeln!(jf, "{}", j)?;

        // human-readable log
        let mut log = dir;
        log.push(format!("install_python_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .with_context(|| format!("opening human log {}", log.display()))?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", rec.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
        writeln!(lf, "settings  : {}", rec.settings_path)?;
        writeln!(lf, "winget    : {}", rec.winget_status)?;
        writeln!(lf, "ELAPSED_MS: {}", rec.elapsed_ms)?;
        writeln!(lf)?;

        Ok(())
    }

    /// Ensures Winget settings.json exists with "US" region preset
    fn ensure_settings_json(path: &Path) -> Result<()> {
        if !path.exists() {
            let json = r#"
            {
                "source": {
                    "msstore": { "region": "US" }
                }
            }
            "#;
            if let Some(parent) = path.parent() {
                create_dir_all(parent)
                    .with_context(|| format!("creating parent dir {}", parent.display()))?;
            }
            fs::write(path, json)
                .with_context(|| format!("writing settings.json at {}", path.display()))?;
        }
        Ok(())
    }

    /// Perform the Winget Python installation
    fn install_python() -> Result<String> {
        let status = Command::new("winget")
            .args([
                "install",
                "--id", "Python.Python.3.14",
                "--exact",
                "--scope", "machine",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ])
            .status()
            .context("failed to execute winget process")?;

        if status.success() {
            Ok("Python install: success".to_string())
        } else {
            Ok(format!("Python install: failed with code {:?}", status.code()))
        }
    }
}

impl Simulation for InstallPythonSimulation {
    fn name(&self) -> &'static str {
        "windows::install_python"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = std::time::Instant::now();

        logger::action_running("Installing Python via winget");

        let path = Self::winget_settings_path()?;

        // Dry-run
        if cfg.dry_run {
            logger::info(&format!("dry-run: would ensure settings.json at {}", path.display()));
            logger::info("dry-run: would run winget python installation");

            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1105 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: no settings or installation run".into(),
                artifact_path: Some(path.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // 1) Ensure settings.json exists
        if let Err(e) = Self::ensure_settings_json(&path) {
            logger::action_fail("failed to create winget settings.json");

            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1105 - {}", self.name()),
                status: "failed".into(),
                details: format!("settings.json error: {}", e),
                artifact_path: Some(path.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            return Err(e);
        }

        // 2) Execute winget installation
        let result = match Self::install_python() {
            Ok(s) => s,
            Err(e) => {
                logger::action_fail("winget installation failed");

                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1105 - {}", self.name()),
                    status: "failed".into(),
                    details: format!("winget error: {}", e),
                    artifact_path: Some(path.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);
                return Err(e);
            }
        };

        // Done — telemetry
        let elapsed = start.elapsed();
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        let telem = PythonInstallTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            settings_path: path.display().to_string(),
            winget_status: result.clone(),
            elapsed_ms: elapsed.as_millis(),
            parent,
        };

        if let Err(e) = Self::write_detailed_telemetry(cfg, &telem) {
            logger::warn(&format!("failed to write telemetry: {}", e));
        }

        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1105 - {}", self.name()),
            status: "written".into(),
            details: result,
            artifact_path: Some(path.display().to_string()),
        };
        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
