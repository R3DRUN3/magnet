//! Simulates benign persistence using Windows Registry Run Keys.
//!
//! This module:
//!   1. Creates a small .cmd file in %TEMP%
//!   2. Writes a Run Key pointing to that .cmd (HKCU Run Key Persistence)
//!   3. Verifies the Run Key exists
//!   4. Logs telemetry
//!   5. Removes the Run Key afterward
//!

use crate::core::config::Config;
use crate::core::logger;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};

use anyhow::{Context, Result};
use chrono::Utc;
use dirs::home_dir;
use serde::Serialize;

use std::fs::{create_dir_all, OpenOptions, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

#[derive(Default)]
pub struct RegistryPersistenceSim;

#[derive(Serialize)]
struct RegistryPersistenceTelemetry {
    test_id: String,
    timestamp: String,
    registry_path: String,
    cmd_drop_path: String,
    artifact_path: String,
    value_verified: bool,
    elapsed_ms: u128,
    parent: String,
}

impl RegistryPersistenceSim {
    /// Telemetry directory
    fn telemetry_dir() -> Option<PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    /// Run key name: MagnetRunKey_<id>
    fn run_key_name(cfg: &Config) -> String {
        format!("MagnetRunKey_{}", cfg.test_id)
    }

    /// Registry path: HKCU:...
    fn registry_path(cfg: &Config) -> String {
        format!(
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\{}",
            Self::run_key_name(cfg)
        )
    }

    /// Location where the .cmd file will go (in %TEMP%)
    fn cmd_drop_path(cfg: &Config) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("magnet_runkey_{}.cmd", cfg.test_id));
        p
    }

    /// Target artifact written by the .cmd on next logon
    fn artifact_path(cfg: &Config) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("magnet_runkey_artifact_{}.txt", cfg.test_id));
        p
    }

    /// Create the .cmd file that RunKey will execute on next logon.
    fn write_cmd_drop(cmd_path: &PathBuf, artifact_path: &PathBuf) -> Result<()> {
        let mut f = File::create(cmd_path)
            .with_context(|| format!("failed to create cmd drop {}", cmd_path.display()))?;

        // The marker it will write
        let content = format!(
            "@echo off\r\n\
             echo MAGNET RUNKEY TEST > \"{}\"\r\n",
            artifact_path.display()
        );

        f.write_all(content.as_bytes())?;
        Ok(())
    }

    /// Write the Run Key pointing to the command file
    fn write_run_key(cfg: &Config, cmd_path: &PathBuf) -> Result<()> {
        let ps_cmd = format!(
            "Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' \
             -Name '{}' -Value '{}' -Force",
            Self::run_key_name(cfg),
            cmd_path.display()
        );

        let status = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps_cmd])
            .status()
            .context("failed to run PowerShell to set Run key")?;

        if !status.success() {
            return Err(anyhow::anyhow!("failed to create registry Run key"));
        }

        Ok(())
    }

    /// Verify the run key exists and returns the value
    fn verify_run_key(cfg: &Config) -> bool {
        let ps = format!(
            "Get-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' \
             -Name '{}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty {}",
            Self::run_key_name(cfg),
            Self::run_key_name(cfg)
        );

        match Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
            .output()
        {
            Ok(o) => o.status.success() && !o.stdout.is_empty(),
            Err(_) => false,
        }
    }

    /// Remove the Run Key
    fn cleanup_run_key(cfg: &Config) {
        let ps = format!(
            "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' \
             -Name '{}' -ErrorAction SilentlyContinue",
            Self::run_key_name(cfg),
        );

        let _ = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &ps])
            .status();
    }

    fn write_telemetry(cfg: &Config, t: &RegistryPersistenceTelemetry) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry dir"))?;

        create_dir_all(&dir)?;

        // JSONL
        let mut jsonl = dir.clone();
        jsonl.push(format!("registry_persistence_{}.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new().create(true).append(true).open(&jsonl)?;
        writeln!(jf, "{}", serde_json::to_string(&t)?)?;

        // Human log
        let mut log = dir.clone();
        log.push(format!("registry_persistence_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new().create(true).append(true).open(&log)?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID          : {}", t.test_id)?;
        writeln!(lf, "TIMESTAMP        : {}", t.timestamp)?;
        writeln!(lf, "REGISTRY PATH    : {}", t.registry_path)?;
        writeln!(lf, "CMD DROP PATH    : {}", t.cmd_drop_path)?;
        writeln!(lf, "ARTIFACT PATH    : {}", t.artifact_path)?;
        writeln!(lf, "VALUE VERIFIED   : {}", t.value_verified)?;
        writeln!(lf, "ELAPSED_MS       : {}", t.elapsed_ms)?;
        writeln!(lf, "PARENT           : {}", t.parent)?;
        writeln!(lf)?;

        Ok(())
    }
}

impl Simulation for RegistryPersistenceSim {
    fn name(&self) -> &'static str {
        "windows::registry_persistence"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        use std::time::Instant;
        let start = Instant::now();

        logger::action_running("Simulating persistence via HKCU Registry Run Key");

        if cfg.dry_run {
            logger::info("dry-run: would create Run key pointing to benign .cmd file");

            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "registry_persistence".into(),
                status: "dry-run".into(),
                details: "dry-run: no Run key created".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // Paths
        let cmd_path = Self::cmd_drop_path(cfg);
        let artifact = Self::artifact_path(cfg);
        let reg_path = Self::registry_path(cfg);

        // 1. Drop .cmd file
        Self::write_cmd_drop(&cmd_path, &artifact)?;

        logger::info(&format!("Dropped command file: {}", cmd_path.display()));

        // 2. Write the Run Key
        Self::write_run_key(cfg, &cmd_path)?;
        logger::info(&format!("Registry Run key written: {}", reg_path));

        // 3. Verify
        let verified = Self::verify_run_key(cfg);
        if verified {
            logger::info("Run key verification successful.");
        } else {
            logger::warn("Run key verification FAILED.");
        }

        // Telemetry
        let telemetry = RegistryPersistenceTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            registry_path: reg_path.clone(),
            cmd_drop_path: cmd_path.display().to_string(),
            artifact_path: artifact.display().to_string(),
            value_verified: verified,
            elapsed_ms: start.elapsed().as_millis(),
            parent: std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".to_string()),
        };

        if let Err(e) = Self::write_telemetry(cfg, &telemetry) {
            logger::warn(&format!("failed to write telemetry: {}", e));
        }

        // 4. Cleanup Run Key (we leave the .cmd file & artifact in TEMP)
        Self::cleanup_run_key(cfg);

        // Action record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: "registry_persistence".into(),
            status: "written".into(),
            details: "Registry RunKey persistence simulated".into(),
            artifact_path: Some(artifact.display().to_string()),
        };
        let _ = write_action_record(cfg, &rec);

        logger::action_ok();
        Ok(())
    }
}
