//! Enables Windows RDP using registry edits + firewall rules (T1021.001),
//! then verifies listener on port 3389.
//! This action requires admin privileges to run.

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;

use anyhow::Result;
use chrono::Utc;
use std::process::Command;

/// Helper wrapper matching PA behavior.
fn run(cmd: &str, args: &[&str]) -> bool {
    Command::new(cmd)
        .args(args)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Verifies port 3389 listener the same way PA does.
fn verify_rdp_listener() -> bool {
    Command::new("cmd")
        .args(&["/C", "netstat -ano | findstr :3389"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

#[derive(Default)]
pub struct EnableRdpSimulation;

impl Simulation for EnableRdpSimulation {
    fn name(&self) -> &'static str {
        "windows::enable_rdp"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Enabling Windows RDP (registry + firewall + verification)");

        // DRY-RUN MODE
        if cfg.dry_run {
            logger::info("dry-run: would enable RDP via registry + firewall + listener verification");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1021.001 - {}", self.name()),
                status: "dry-run".to_string(),
                details: "dry-run: no registry changes, no firewall changes".to_string(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // === 1) Registry modification ===
        let reg_ok = run(
            "reg",
            &[
                "add",
                r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
                "/v",
                "fDenyTSConnections",
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ],
        );

        // === 2) Firewall enable ===
        let fw_ok = run(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                r#"Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'"#,
            ],
        );

        // === 3) Verification ===
        let verify_ok = verify_rdp_listener();

        // Logging results
        logger::info(&format!("Registry enable: {}", reg_ok));
        logger::info(&format!("Firewall enable: {}", fw_ok));
        logger::info(&format!("Listener check: {}", verify_ok));

        let all_ok = reg_ok && fw_ok && verify_ok;

        // Action record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1021.001 - {}", self.name()),
            status: if all_ok { "completed" } else { "partial" }.to_string(),
            details: format!(
                "registry={}, firewall={}, verify={}",
                reg_ok, fw_ok, verify_ok
            ),
            artifact_path: None,
        };
        let _ = write_action_record(cfg, &rec);

        if all_ok {
            logger::action_ok();
        } else {
            logger::action_fail("one or more RDP steps failed");
        }

        // Error return if verification failed
        if !verify_ok {
            return Err(anyhow::anyhow!("RDP listener not detected on port 3389"));
        }

        Ok(())
    }
}
