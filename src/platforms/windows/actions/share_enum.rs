//! Enumerates local and network SMB shares using common attacker TTPs.
//! SAFE: Read-only enumeration. No share access, no modification.

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;

use anyhow::Result;
use chrono::Utc;
use std::process::{Command, Stdio};

/// Execute a command and capture stdout as String.
fn run_capture(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|_| "<exec-failed>".to_string())
}

#[derive(Default)]
pub struct ShareEnumSimulation;

impl Simulation for ShareEnumSimulation {
    fn name(&self) -> &'static str {
        "windows::share_enum"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Enumerating SMB shares (safe, read-only)");

        // DRY RUN
        if cfg.dry_run {
            logger::info("dry-run: would run share enumeration commands");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "share_enum".to_string(),
                status: "dry-run".to_string(),
                details: "Would run net view, net share, PowerShell, and WMI enumeration".to_string(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // === REAL ENUMERATION ===

        logger::info("Running: net view");
        let net_view = run_capture("net", &["view"]);

        logger::info("Running: net share");
        let net_share = run_capture("net", &["share"]);

        logger::info("Running: PowerShell Get-SmbShare");
        let get_smb = run_capture("powershell", &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-SmbShare | Format-Table -AutoSize"
        ]);

        logger::info("Running: WMI Win32_Share query");
        let wmi_out = run_capture("powershell", &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-WmiObject -Class Win32_Share | Format-Table -AutoSize"
        ]);

        // Combine telemetry details
        let details = format!(
            "net_view:\n{}\n\nnet_share:\n{}\n\nGet-SmbShare:\n{}\n\nWMI:\n{}\n",
            net_view, net_share, get_smb, wmi_out
        );

        // Write telemetry record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: "share_enum".to_string(),
            status: "completed".to_string(),
            details,
            artifact_path: None,
        };
        let _ = write_action_record(cfg, &rec);

        logger::action_ok();
        Ok(())
    }
}
