use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::logger;
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use dirs::home_dir;
use serde::Serialize;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

/// How many bytes of stdout/stderr to keep in the telemetry JSON (avoid huge blobs).
const MAX_CAPTURE_BYTES: usize = 16 * 1024; // 16 KB

#[derive(Default)]
pub struct DiscoverySim;

#[derive(Serialize)]
struct CmdRecord {
    test_id: String,
    timestamp: String,
    command: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    parent: String,
}

impl DiscoverySim {
    fn default_commands() -> Vec<&'static str> {
        vec![
            "whoami /all",
            "net user",
            "net localgroup administrators",
            "tasklist /v",
            "query user",
            "systeminfo",
            "ipconfig /all",
            "netstat -ano",
            "wmic product get name,version",
            "wmic logicaldisk get deviceid,filesystem,freespace,size",
        ]
    }

    fn capture_output(cmd: &str) -> Result<(Option<i32>, String, String)> {
        let output = Command::new("cmd")
            .args(["/C", cmd])
            .output()
            .with_context(|| format!("failed to execute command: {}", cmd))?;

        let exit_code = output.status.code();
        let mut stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let mut stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if stdout.len() > MAX_CAPTURE_BYTES {
            stdout.truncate(MAX_CAPTURE_BYTES);
            stdout.push_str("\n...TRUNCATED...");
        }
        if stderr.len() > MAX_CAPTURE_BYTES {
            stderr.truncate(MAX_CAPTURE_BYTES);
            stderr.push_str("\n...TRUNCATED...");
        }

        Ok((exit_code, stdout, stderr))
    }

    fn telemetry_dir() -> Option<PathBuf> {
        // Prefer %USERPROFILE%\Documents\MagnetTelemetry
        if let Some(mut p) = home_dir() {
            p.push("Documents");
            p.push("MagnetTelemetry");
            Some(p)
        } else {
            None
        }
    }

    /// Normalize output: convert CRLF -> LF, trim, and keep readable.
    fn sanitize_output(s: &str) -> String {
        let replaced = s.replace("\r\n", "\n").replace('\r', "");
        replaced.trim().to_string()
    }

    /// Writes both JSONL (machine-readable) and .log (human-readable) files.
    fn write_record(cfg: &Config, rec: &CmdRecord) -> Result<()> {
        let dir = Self::telemetry_dir().ok_or_else(|| anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir)
            .with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        // --- JSONL telemetry ---
        let mut jsonl_path = dir.clone();
        jsonl_path.push(format!("magnet_discovery_{}.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl_path)
            .with_context(|| format!("opening telemetry file {}", jsonl_path.display()))?;
        let j = serde_json::to_string(rec)?;
        writeln!(jf, "{}", j)?;

        // --- Human-readable log ---
        let mut log_path = dir;
        log_path.push(format!("magnet_discovery_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("opening human log {}", log_path.display()))?;

        let stdout = Self::sanitize_output(&rec.stdout);
        let stderr = Self::sanitize_output(&rec.stderr);

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", rec.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
        writeln!(lf, "COMMAND   : {}", rec.command)?;
        writeln!(
            lf,
            "EXIT CODE : {}",
            rec.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "N/A".into())
        )?;
        writeln!(lf, "PARENT    : {}", rec.parent)?;
        writeln!(lf, "----------------------------------------------------------------")?;
        writeln!(lf, "STDOUT:\n{}", stdout)?;
        if !stderr.is_empty() {
            writeln!(lf, "----------------------------------------------------------------")?;
            writeln!(lf, "STDERR:\n{}", stderr)?;
        }
        writeln!(lf)?;

        Ok(())
    }
}

impl Simulation for DiscoverySim {
    fn name(&self) -> &'static str {
        "windows::discovery_sim"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        for cmd in Self::default_commands() {
            // Minimal single-line start
            logger::action_running(&format!("Running: {}", cmd));

            if cfg.dry_run {
                logger::info(&format!("dry-run: would run '{}'", cmd));
                logger::action_ok();
                continue;
            }

            let (exit_code, stdout, stderr) = match Self::capture_output(cmd) {
                Ok(r) => r,
                Err(e) => {
                    logger::action_fail("command execution failed");
                    // record the failure for SOC to see
                    let rec = CmdRecord {
                        test_id: cfg.test_id.clone(),
                        timestamp: Utc::now().to_rfc3339(),
                        command: cmd.to_string(),
                        exit_code: None,
                        stdout: String::new(),
                        stderr: format!("failed to run command: {}", e),
                        parent: parent.clone(),
                    };
                    // Best-effort write; log error if it fails
                    if let Err(wr_err) = Self::write_record(cfg, &rec) {
                        logger::error(&format!("failed to write telemetry: {}", wr_err));
                    }
                    continue;
                }
            };

            let rec = CmdRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                command: cmd.to_string(),
                exit_code,
                stdout,
                stderr,
                parent: parent.clone(),
            };

            match Self::write_record(cfg, &rec) {
                Ok(_) => {
                    logger::action_ok();
                }
                Err(e) => {
                    logger::error(&format!("failed to write telemetry: {}", e));
                    logger::action_fail("failed to write telemetry");
                }
            }
        }

        logger::info(&format!("Done. MAGNET-TEST-ID: {}", cfg.test_id));
        Ok(())
    }
}
