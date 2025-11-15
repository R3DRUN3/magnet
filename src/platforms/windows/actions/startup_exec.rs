//! Simulates persistence via the Windows Startup folder (T1547.001).  
//!
//! This module creates a benign script inside:
//!   %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
//!
//! The script runs at every user logon and writes:
//!   "Hello from Magnet!" + timestamp + test_id
//! into the telemetry directory.

use crate::core::config::Config;
use crate::core::logger;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{write_action_record, ActionRecord};

use anyhow::{Context, Result};
use chrono::Utc;
use dirs::{home_dir, config_dir};
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::Write;
use std::path::{PathBuf};

#[derive(Default)]
pub struct StartupExecSim;

impl StartupExecSim {
    /// Telemetry dir:  %USERPROFILE%\Documents\MagnetTelemetry
    fn telemetry_dir() -> Option<PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    /// Startup folder:
    ///   %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
    fn startup_folder() -> Option<PathBuf> {
        config_dir().map(|mut p| {
            // config_dir() typically gives %APPDATA%, so append manually.
            // On Windows: %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup
            p.push("Microsoft");
            p.push("Windows");
            p.push("Start Menu");
            p.push("Programs");
            p.push("Startup");
            p
        })
    }

    /// The script that will be executed at startup.
    fn script_name(cfg: &Config) -> String {
        format!("magnet_startup_{}.cmd", cfg.test_id)
    }

    /// Write the .cmd script to the startup folder.
    fn write_script(startup_dir: &PathBuf, cfg: &Config) -> Result<PathBuf> {
        create_dir_all(startup_dir)
            .context("could not create startup folder")?;

        let mut script_path = startup_dir.clone();
        script_path.push(Self::script_name(cfg));

        let telemetry_dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry dir"))?;

        create_dir_all(&telemetry_dir)
            .context("could not create telemetry dir")?;

        let mut log_path = telemetry_dir.clone();
        log_path.push(format!("startup_exec_log_{}.txt", cfg.test_id));

        // Script content: prints "Hello from Magnet!"
        // and writes a log entry into MagnetTelemetry
        let content = format!(
            "@echo off\r\n\
             echo Hello from Magnet! >> \"{}\"\r\n\
             echo TEST-ID: {} >> \"{}\"\r\n\
             echo TIMESTAMP: {} >> \"{}\"\r\n\
             exit /b 0\r\n",
            log_path.display(),
            cfg.test_id,
            log_path.display(),
            Utc::now().to_rfc3339(),
            log_path.display()
        );

        let mut file = File::create(&script_path)
            .context("failed to create startup script")?;
        file.write_all(content.as_bytes())
            .context("failed to write startup script content")?;

        Ok(script_path)
    }

    /// Write concise human-readable telemetry
    fn write_detailed_telemetry(cfg: &Config, script_path: &PathBuf) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir)
            .context("creating telemetry directory")?;

        let mut log = dir.clone();
        log.push(format!("startup_exec_{}.log", cfg.test_id));

        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .context("opening human log file")?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", cfg.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", Utc::now().to_rfc3339())?;
        writeln!(lf, "SCRIPT    : {}", script_path.display())?;
        writeln!(lf, "DETAILS   : Startup-script persistence simulated")?;
        writeln!(lf)?;

        Ok(())
    }
}


impl Simulation for StartupExecSim {
    fn name(&self) -> &'static str {
        "windows::startup_exec"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Simulating persistence via Startup folder");

        if cfg.dry_run {
            logger::info("dry-run: would create a benign startup script");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1547.001 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: no startup script written".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        let startup_dir = Self::startup_folder()
            .ok_or_else(|| anyhow::anyhow!("could not determine Startup folder"))?;

        // Create startup script
        let script_path = match Self::write_script(&startup_dir, cfg) {
            Ok(p) => {
                logger::info(&format!("\nStartup script created:\n {}", p.display()));
                p
            }
            Err(e) => {
                logger::action_fail("failed to write startup script");
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1547.001 - {}", self.name()),
                    status: "failed".into(),
                    details: format!("script creation error: {}", e),
                    artifact_path: None,
                };
                let _ = write_action_record(cfg, &rec);
                return Err(e);
            }
        };

        // Write telemetry
        if let Err(e) = Self::write_detailed_telemetry(cfg, &script_path) {
            logger::warn(&format!("failed to write detailed telemetry: {}", e));
        }

        // Action record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1547.001 - {}", self.name()),
            status: "written".into(),
            details: format!("startup script: {}", script_path.display()),
            artifact_path: Some(script_path.display().to_string()),
        };
        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
