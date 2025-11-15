//! Creation and execution of a benign Windows scheduled task (T1053.005).  

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;
use anyhow::{Context, Result};
use chrono::{Local, Utc, Duration};
use dirs::home_dir;
use std::fs::{create_dir_all, OpenOptions, File};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Create a benign Windows Scheduled Task to simulate persistence activity.
/// The task runs a short PowerShell script writing a marker file in Documents\MagnetTelemetry.
#[derive(Default)]
pub struct ScheduledTaskSim;

impl ScheduledTaskSim {
    fn telemetry_dir() -> Option<PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn task_name(cfg: &Config) -> String {
        format!("Magnet_ScheduledTask_{}", cfg.test_id)
    }

    /// Write the PowerShell payload to a short script file.
    fn create_action_script(cfg: &Config, artifact_path: &PathBuf) -> Result<PathBuf> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry dir"))?;
        create_dir_all(&dir)?;

        let mut ps_path = dir.clone();
        ps_path.push(format!("task_action_{}.ps1", cfg.test_id));

        let now = Utc::now().to_rfc3339();
        let content = format!(
            "$msg = 'MAGNET-SCHEDULED-TASK`nTEST_ID: {}`nTIMESTAMP: {}'; \
             Set-Content -Path '{}' -Value $msg -Encoding UTF8",
            cfg.test_id,
            now,
            artifact_path.display()
        );

        let mut f = File::create(&ps_path)?;
        f.write_all(content.as_bytes())?;
        Ok(ps_path)
    }

    fn create_schtask(task_name: &str, ps_script: &PathBuf, start_time_hhmm: &str) -> Result<()> {
        let ps_path = ps_script.display().to_string();
        let action = format!(
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"{}\"",
            ps_path
        );

        // schtasks /Create /SC ONCE /TN <task> /TR "<action>" /ST HH:mm /F
        let output = Command::new("schtasks.exe")
            .args([
                "/Create",
                "/SC", "ONCE",
                "/TN", task_name,
                "/TR", &action,
                "/ST", start_time_hhmm,
                "/F",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("failed to spawn schtasks.exe")?;

        if output.status.success() {
            logger::info(&format!("Scheduled task {} created.", task_name));
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "schtasks create failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    fn delete_schtask(task_name: &str) -> Result<()> {
        let output = Command::new("schtasks.exe")
            .args(["/Delete", "/TN", task_name, "/F"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("failed to spawn schtasks delete")?;

        if output.status.success() {
            logger::info(&format!("Scheduled task {} deleted.", task_name));
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "schtasks delete failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ))
        }
    }

    fn write_detailed_telemetry(cfg: &Config, details: &str) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir)?;

        let mut log = dir.clone();
        log.push(format!("scheduled_task_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new().create(true).append(true).open(&log)?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", cfg.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", Utc::now().to_rfc3339())?;
        writeln!(lf, "DETAILS   : {}", details)?;
        writeln!(lf)?;

        Ok(())
    }
}

impl Simulation for ScheduledTaskSim {
    fn name(&self) -> &'static str {
        "windows::scheduled_task_sim"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Creating benign Scheduled Task");
        logger::action_running("Waiting 1 minute for task execution");

        if cfg.dry_run {
            logger::info("dry-run: would create a scheduled task to run a benign PowerShell script");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1053.005 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: no scheduled task created".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // Prepare telemetry and artifact
        let telemetry_dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&telemetry_dir)?;

        let mut artifact = telemetry_dir.clone();
        artifact.push(format!("scheduled_task_artifact_{}.txt", cfg.test_id));

        // Write PowerShell script
        let ps_script = Self::create_action_script(cfg, &artifact)?;

        // Schedule 1 minute in future
        let start_time = Local::now() + Duration::minutes(1);
        let start_time_hhmm = start_time.format("%H:%M").to_string();

        // Create the scheduled task
        if let Err(e) = Self::create_schtask(&Self::task_name(cfg), &ps_script, &start_time_hhmm) {
            logger::action_fail("failed to create scheduled task");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1053.005 - {}", self.name()),
                status: "failed".into(),
                details: format!("create task error: {}", e),
                artifact_path: Some(telemetry_dir.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            return Err(e);
        }

        // Wait briefly for execution
        std::thread::sleep(std::time::Duration::from_secs(61));

        // Check if artifact written
        let details = match std::fs::read_to_string(&artifact) {
            Ok(s) => {
                logger::info(&format!("Scheduled task executed successfully; artifact: {}", artifact.display()));
                format!("Artifact content:\n{}", s)
            }
            Err(e) => {
                logger::warn(&format!("Artifact not found after scheduled execution: {}", e));
                format!("Artifact not found or unreadable: {}", e)
            }
        };

        // Cleanup
        if let Err(e) = Self::delete_schtask(&Self::task_name(cfg)) {
            logger::warn(&format!("Failed to delete scheduled task: {}", e));
        }

        if let Err(e) = Self::write_detailed_telemetry(cfg, &details) {
            logger::warn(&format!("failed to write detailed telemetry: {}", e));
        }

        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1053.005 - {}", self.name()),
            status: "written".into(),
            details: format!("Scheduled task executed; {}", details.lines().next().unwrap_or("")),
            artifact_path: Some(telemetry_dir.display().to_string()),
        };
        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
