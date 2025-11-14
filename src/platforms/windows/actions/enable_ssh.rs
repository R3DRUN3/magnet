//! Windows SSH enabling module.
//!
//! This module installs/starts OpenSSH Server and ensures port 22 is open,
//! following the same structure and telemetry style as other PB simulations.

use crate::core::config::Config;
use crate::core::logger;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{write_action_record, ActionRecord};

use anyhow::{Context, Result};
use chrono::Utc;
use dirs::home_dir;
use serde::Serialize;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

#[derive(Default)]
pub struct EnableSshSimulation;

#[derive(Serialize)]
struct EnableSshTelemetry {
    test_id: String,
    timestamp: String,
    ssh_status: String,
    commands_run: Vec<String>,
    port_check: String,
    elapsed_ms: u128,
    parent: String,
}

/// Telemetry directory: %USERPROFILE%\Documents\MagnetTelemetry
fn telemetry_dir() -> Option<PathBuf> {
    home_dir().map(|mut p| {
        p.push("Documents");
        p.push("MagnetTelemetry");
        p
    })
}

/// Run a PowerShell command string
fn run_ps(cmd: &str) -> Result<()> {
    let status = Command::new("powershell")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd])
        .status()
        .context("running PowerShell command")?;

    if !status.success() {
        anyhow::bail!("PowerShell command failed: {}", cmd);
    }

    Ok(())
}

impl Simulation for EnableSshSimulation {
    fn name(&self) -> &'static str {
        "windows::enable_ssh"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();

        // -----------------------------------------------------
        // Command list identical to PA
        // -----------------------------------------------------
        let commands = vec![
            r#"Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"#.to_string(),
            r#"Set-Service -Name sshd -StartupType Automatic"#.to_string(),
            r#"Start-Service sshd"#.to_string(),
            r#"New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22"#.to_string(),
        ];

        logger::action_running("Enabling SSH (install, start service, open firewall port)");

        if cfg.dry_run {
            logger::info("dry-run: would install OpenSSH Server and enable port 22");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "enable_ssh".into(),
                status: "dry-run".into(),
                details: "dry-run: no commands executed".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // -----------------------------------------------------
        // Execute commands
        // -----------------------------------------------------
        for cmd in &commands {
            logger::info(&format!("  → running: {}", cmd));
            if let Err(e) = run_ps(cmd) {
                logger::warn(&format!("Command failed: {}", e));
            }
        }

        // -----------------------------------------------------
        // Check port 22
        // -----------------------------------------------------
        logger::info("checking whether port 22 is reachable...");

        let port_status = match TcpStream::connect("127.0.0.1:22") {
            Ok(_) => {
                logger::info("SSH is ENABLED and reachable on port 22.");
                "reachable".to_string()
            }
            Err(e) => {
                logger::warn(&format!("SSH NOT reachable: {}", e));
                format!("unreachable: {}", e)
            }
        };

        // -----------------------------------------------------
        // Telemetry
        // -----------------------------------------------------
        logger::info("writing SSH enablement telemetry...");

        let elapsed = start.elapsed();
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        let t = EnableSshTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            ssh_status: port_status.clone(),
            commands_run: commands.clone(),
            port_check: port_status.clone(),
            elapsed_ms: elapsed.as_millis(),
            parent,
        };

        // JSONL + human-readable logs
        if let Some(dir) = telemetry_dir() {
            if let Err(e) = create_dir_all(&dir) {
                logger::warn(&format!("could not create telemetry dir: {}", e));
            } else {
                // jsonl
                let mut jsonl = dir.clone();
                jsonl.push(format!("enable_ssh_{}.jsonl", cfg.test_id));
                if let Ok(mut jf) = OpenOptions::new().create(true).append(true).open(&jsonl) {
                    let _ = writeln!(jf, "{}", serde_json::to_string(&t).unwrap_or_default());
                }

                // human log
                let mut log = dir.clone();
                log.push(format!("enable_ssh_{}.log", cfg.test_id));
                if let Ok(mut lf) = OpenOptions::new().create(true).append(true).open(&log) {
                    let _ = writeln!(lf, "==============================================================");
                    let _ = writeln!(lf, "TEST ID   : {}", t.test_id);
                    let _ = writeln!(lf, "TIMESTAMP : {}", t.timestamp);
                    let _ = writeln!(lf, "SSH STATUS: {}", t.ssh_status);
                    let _ = writeln!(lf, "PORT CHECK: {}", t.port_check);
                    let _ = writeln!(lf, "ELAPSED_MS: {}", t.elapsed_ms);
                    let _ = writeln!(lf, "PARENT    : {}", t.parent);
                    let _ = writeln!(lf);
                }
            }
        }

        // -----------------------------------------------------
        // Action record
        // -----------------------------------------------------
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: "enable_ssh".into(),
            status: "written".into(),
            details: format!("SSH status: {}", port_status),
            artifact_path: None,
        };

        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
