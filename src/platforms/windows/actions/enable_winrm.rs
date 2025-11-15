//! Windows WinRM enabling module (T1021.006).
//!
//! This module enables/starts WinRM, configures firewall rules, and confirms WinRM is reachable on TCP port 5985.
//! This action requires admin privileges to run.

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
use std::path::{PathBuf};
use std::process::Command;
use std::time::Instant;

#[derive(Default)]
pub struct EnableWinRMSimulation;

#[derive(Serialize)]
struct EnableWinRmTelemetry {
    test_id: String,
    timestamp: String,
    winrm_status: String,
    commands_run: Vec<String>,
    firewall_status: String,
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

impl Simulation for EnableWinRMSimulation {
    fn name(&self) -> &'static str {
        "windows::enable_winrm"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();

        // -----------------------------------------------------
        // WinRM Commands (now fully robust)
        // -----------------------------------------------------
        let commands = vec![
            // Enable WinRM / PSRemoting (may warn on Public networks — safe)
            r#"Enable-PSRemoting -Force"#.to_string(),

            // Ensure WinRM service is configured and running
            r#"Set-Service -Name WinRM -StartupType Automatic"#.to_string(),
            r#"Start-Service WinRM"#.to_string(),

            // Fully dynamic firewall enabling (fixes your previous errors)
            r#"Get-NetFirewallRule | Where-Object {$_.DisplayName -like '*WinRM*' -and $_.Direction -eq 'Inbound'} | Enable-NetFirewallRule"#
                .to_string(),
        ];

        logger::action_running("Enabling WinRM (PSRemoting, service, firewall)");

        if cfg.dry_run {
            logger::info("dry-run: would enable WinRM and open port 5985");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1021.006 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: no commands executed".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // -----------------------------------------------------
        // Execute enablement commands
        // -----------------------------------------------------
        let mut firewall_status = "unknown".to_string();

        for cmd in &commands {
            logger::info(&format!("  → running: {}", cmd));

            match run_ps(cmd) {
                Ok(_) => {
                    if cmd.contains("Get-NetFirewallRule") {
                        firewall_status = "firewall rules enabled".into();
                    }
                }
                Err(e) => {
                    logger::warn(&format!("Command failed: {}", e));
                    if cmd.contains("Get-NetFirewallRule") {
                        firewall_status = "firewall rule error".into();
                    }
                }
            }
        }

        // -----------------------------------------------------
        // Verify WinRM port 5985 is reachable
        // -----------------------------------------------------
        logger::info("checking whether WinRM port 5985 is reachable...");

        let port_status = match TcpStream::connect("127.0.0.1:5985") {
            Ok(_) => {
                logger::info("WinRM is ENABLED and reachable on port 5985.");
                "reachable".to_string()
            }
            Err(e) => {
                logger::warn(&format!("WinRM NOT reachable: {}", e));
                format!("unreachable: {}", e)
            }
        };

        // Determine overall WinRM status
        let winrm_status = if port_status == "reachable" {
            "enabled".to_string()
        } else {
            "enabled-but-not-reachable".to_string()
        };

        // -----------------------------------------------------
        // Telemetry (JSONL + log files)
        // -----------------------------------------------------
        logger::info("writing WinRM enablement telemetry...");

        let elapsed = start.elapsed();
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        let t = EnableWinRmTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            winrm_status,
            commands_run: commands.clone(),
            firewall_status,
            port_check: port_status.clone(),
            elapsed_ms: elapsed.as_millis(),
            parent,
        };

        if let Some(dir) = telemetry_dir() {
            if let Err(e) = create_dir_all(&dir) {
                logger::warn(&format!("could not create telemetry dir: {}", e));
            } else {
                // JSONL
                let mut jsonl = dir.clone();
                jsonl.push(format!("enable_winrm_{}.jsonl", cfg.test_id));
                if let Ok(mut jf) = OpenOptions::new().create(true).append(true).open(&jsonl) {
                    let _ = writeln!(jf, "{}", serde_json::to_string(&t).unwrap_or_default());
                }

                // Human log
                let mut log = dir.clone();
                log.push(format!("enable_winrm_{}.log", cfg.test_id));
                if let Ok(mut lf) = OpenOptions::new().create(true).append(true).open(&log) {
                    let _ = writeln!(lf, "==============================================================");
                    let _ = writeln!(lf, "TEST ID   : {}", t.test_id);
                    let _ = writeln!(lf, "TIMESTAMP : {}", t.timestamp);
                    let _ = writeln!(lf, "WINRM STATUS: {}", t.winrm_status);
                    let _ = writeln!(lf, "FIREWALL STATUS: {}", t.firewall_status);
                    let _ = writeln!(lf, "PORT CHECK: {}", t.port_check);
                    let _ = writeln!(lf, "ELAPSED_MS: {}", t.elapsed_ms);
                    let _ = writeln!(lf, "PARENT    : {}", t.parent);
                    let _ = writeln!(lf);
                }
            }
        }

        // -----------------------------------------------------
        // ActionRecord
        // -----------------------------------------------------
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1021.006 - {}", self.name()),
            status: "written".into(),
            details: format!(
                "WinRM status: {}; Firewall: {}; Port: {}",
                t.winrm_status, t.firewall_status, t.port_check
            ),
            artifact_path: None,
        };

        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
