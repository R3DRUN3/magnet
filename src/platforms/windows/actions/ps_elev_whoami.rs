//! Open powershell as administrator and launch a simple command (T1059.001).
//! This action is not fully automated but requires user manual interaction (if not launched as admin).

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;
use anyhow::{Context, Result};
use chrono::Utc;
use dirs::home_dir;
use serde::Serialize;
use std::fs::{create_dir_all, write, read, remove_file};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Instant;
use std::io::Write;

/// Module: open PowerShell (attempt elevated), enable script execution (Process scope),
/// run `whoami` and capture telemetry.
#[derive(Default)]
pub struct PsElevWhoami;

#[derive(Serialize)]
struct PsWhoamiTelemetry {
    test_id: String,
    timestamp: String,
    attempted_elevated_start: bool,
    elevated_start_status: String,
    whoami_stdout: String,
    whoami_stderr: String,
    elevated_output_path: Option<String>,
    elevated_output_contents: Option<String>,
    elapsed_ms: u128,
    parent: String,
}

impl PsElevWhoami {
    fn telemetry_dir() -> Option<PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn elevated_output_path(cfg: &Config) -> Option<PathBuf> {
        Self::telemetry_dir().map(|mut p| {
            p.push(format!("ps_elev_whoami_{}.txt", cfg.test_id));
            p
        })
    }

    fn elevated_script_path(cfg: &Config) -> Option<PathBuf> {
        Self::telemetry_dir().map(|mut p| {
            p.push(format!("ps_elev_whoami_{}.ps1", cfg.test_id));
            p
        })
    }

    fn write_detailed_telemetry(cfg: &Config, rec: &PsWhoamiTelemetry) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir)
            .with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        // jsonl
        let mut jsonl = dir.clone();
        jsonl.push(format!("ps_elev_whoami_{}.jsonl", cfg.test_id));
        {
            let mut jf = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&jsonl)
                .with_context(|| format!("opening telemetry file {}", jsonl.display()))?;
            let j = serde_json::to_string(rec)?;
            writeln!(jf, "{}", j)?;
        }

        // human-readable log
        let mut log = dir;
        log.push(format!("ps_elev_whoami_{}.log", cfg.test_id));
        {
            let mut lf = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log)
                .with_context(|| format!("opening human log: {}", log.display()))?;
            writeln!(lf, "================================================================")?;
            writeln!(lf, "TEST ID   : {}", rec.test_id)?;
            writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
            writeln!(lf, "ELEVATED ATTEMPT: {}", rec.attempted_elevated_start)?;
            writeln!(lf, "ELEVATED STATUS : {}", rec.elevated_start_status)?;
            writeln!(lf, "WHOAMI STDOUT    : {}", rec.whoami_stdout)?;
            writeln!(lf, "WHOAMI STDERR    : {}", rec.whoami_stderr)?;
            if let Some(ref p) = rec.elevated_output_path {
                writeln!(lf, "ELEVATED OUT PATH: {}", p)?;
            }
            if let Some(ref c) = rec.elevated_output_contents {
                writeln!(lf, "ELEVATED OUT DATA:\n{}", c)?;
            }
            writeln!(lf, "PARENT    : {}", rec.parent)?;
            writeln!(lf, "ELAPSED_MS: {}", rec.elapsed_ms)?;
            writeln!(lf)?;
        }

        Ok(())
    }

    /// Safely read PowerShell output file: tries UTF-16LE (common on Windows) then falls back to UTF-8.
    fn read_text_auto(path: &PathBuf) -> Result<String> {
        let bytes = read(path)?;
        // Check BOM for UTF-16LE (0xFF 0xFE) or UTF-16BE (0xFE 0xFF)
        if bytes.len() >= 2 && &bytes[0..2] == [0xFF, 0xFE] {
            // UTF-16LE with BOM
            let u16_slice: Vec<u16> = bytes[2..]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            return Ok(String::from_utf16(&u16_slice)
                .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).into_owned()));
        }
        if bytes.len() >= 2 && &bytes[0..2] == [0xFE, 0xFF] {
            // UTF-16BE with BOM
            let u16_slice: Vec<u16> = bytes[2..]
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            return Ok(String::from_utf16(&u16_slice)
                .unwrap_or_else(|_| String::from_utf8_lossy(&bytes).into_owned()));
        }
        // Fallback: assume UTF-8
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }
}

impl Simulation for PsElevWhoami {
    fn name(&self) -> &'static str {
        "windows::ps_elev_whoami"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();
        logger::action_running(
            "Simulating: open PowerShell (attempt elevated), enable script execution, run whoami",
        );

        // Dry-run
        if cfg.dry_run {
            logger::info(
                "dry-run: would attempt elevated Start-Process and run whoami with Process-scope execution policy",
            );
            let example_output = Self::elevated_output_path(cfg)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "<telemetry_path_unknown>".into());

            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1059.001 - {}", self.name()),
                status: "dry-run".into(),
                details: format!(
                    "dry-run: would run PowerShell: Set-ExecutionPolicy Bypass -Scope Process; whoami → {}",
                    example_output
                ),
                artifact_path: Some(example_output),
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        if std::env::consts::OS.to_lowercase() != "windows" {
            logger::action_fail("ps_elev_whoami is Windows-only");
            return Err(anyhow::anyhow!("ps_elev_whoami: not running on Windows"));
        }

        // 1. Run whoami non-elevated
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Set-ExecutionPolicy Bypass -Scope Process -Force; whoami",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        let (whoami_stdout, whoami_stderr) = match output {
            Ok(o) => (
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            ),
            Err(e) => (String::new(), format!("spawn-error: {}", e)),
        };
        logger::info(&format!("whoami (in-process) stdout: {}", whoami_stdout.trim()));

        // 2. Prepare elevated script
        let elevated_output_path = Self::elevated_output_path(cfg)
            .ok_or_else(|| anyhow::anyhow!("telemetry path"))?;
        let script_path = Self::elevated_script_path(cfg)
            .ok_or_else(|| anyhow::anyhow!("script path"))?;
        if let Some(dir) = Self::telemetry_dir() {
            let _ = create_dir_all(&dir);
        }
        let script = format!(
            "Set-ExecutionPolicy Bypass -Scope Process -Force\nwhoami > \"{}\"\nexit\n",
            elevated_output_path.display()
        );
        write(&script_path, script.as_bytes())?;

        // 3. Attempt elevation
        let start_process = format!(
            "Start-Process powershell -Verb runAs -ArgumentList '-NoProfile','-File','{}' -Wait",
            script_path.display()
        );
        let elev_result = Command::new("powershell")
            .args(&["-NoProfile", "-NonInteractive", "-Command", &start_process])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output();

        let attempted_elevated_start: bool;
        let elevated_start_status: String;
        let elevated_output_contents: Option<String>;

        match elev_result {
            Ok(res) if res.status.success() => {
                attempted_elevated_start = true;
                elevated_start_status = "elevated-start-command-succeeded".into();
                let contents = match PsElevWhoami::read_text_auto(&elevated_output_path) {
                    Ok(s) => s,
                    Err(e) => format!("failed-to-read-elevated-output: {}", e),
                };
                elevated_output_contents = Some(contents);
            }
            Ok(res) => {
                attempted_elevated_start = true;
                let stderr = String::from_utf8_lossy(&res.stderr).to_string();
                elevated_start_status = format!("elevated-start-failed: {}", stderr.trim());
                elevated_output_contents = None;
            }
            Err(e) => {
                attempted_elevated_start = true;
                elevated_start_status = format!("spawn-error: {}", e);
                elevated_output_contents = None;
            }
        }

        let _ = remove_file(&script_path);

        // 4. Telemetry
        let elapsed = start.elapsed();
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".into());

        let telemetry = PsWhoamiTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            attempted_elevated_start,
            elevated_start_status: elevated_start_status.clone(),
            whoami_stdout: whoami_stdout.clone(),
            whoami_stderr: whoami_stderr.clone(),
            elevated_output_path: Some(elevated_output_path.display().to_string()),
            elevated_output_contents,
            elapsed_ms: elapsed.as_millis(),
            parent,
        };

        if let Err(e) = Self::write_detailed_telemetry(cfg, &telemetry) {
            logger::warn(&format!("failed to write detailed telemetry: {}", e));
        }

        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1059.001 - {}", self.name()),
            status: "written".into(),
            details: format!(
                "whoami(stdout_len={}): {}; elevated_status: {}",
                telemetry.whoami_stdout.len(),
                telemetry.whoami_stdout.trim(),
                telemetry.elevated_start_status
            ),
            artifact_path: Some(elevated_output_path.display().to_string()),
        };

        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
