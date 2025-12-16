//! Environment Variables Collector
//! MITRE: T1082 - System Information Discovery

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

use std::env;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const MITRE_TTP: &str = "T1082";
const MODULE_NAME: &str = "windows::get_env_vars";

#[derive(Default)]
pub struct EnvVarsSimulation;

/// Per-variable record
#[derive(Serialize, Clone)]
pub struct EnvVarRecord {
    timestamp: String,
    key: String,
    value: String,
}

#[derive(Serialize)]
struct EnvVarsTelemetry {
    test_id: String,
    timestamp: String,
    mitre: String,
    module: String,
    total_vars: usize,
    parent: String,
}

impl EnvVarsSimulation {
    fn telemetry_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn write_detailed_telemetry(
        cfg: &Config,
        telemetry: &EnvVarsTelemetry,
        per_var: &[EnvVarRecord],
    ) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine telemetry dir"))?;

        create_dir_all(&dir)?;

        // Summary JSONL
        let mut summary = dir.clone();
        summary.push(format!("env_vars_{}_summary.jsonl", cfg.test_id));

        let mut sf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&summary)?;

        writeln!(sf, "{}", serde_json::to_string(telemetry)?)?;

        // Human-readable per-module log (optional, separate from Magnet log)
        let mut log = dir;
        log.push(format!("env_vars_{}.log", cfg.test_id));

        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)?;

        writeln!(lf, "===============================================================")?;
        writeln!(lf, "TEST ID       : {}", telemetry.test_id)?;
        writeln!(lf, "TIMESTAMP     : {}", telemetry.timestamp)?;
        writeln!(lf, "MODULE        : {}", telemetry.module)?;
        writeln!(lf, "MITRE TTP     : {}", telemetry.mitre)?;
        writeln!(lf, "TOTAL VARS    : {}", telemetry.total_vars)?;
        writeln!(lf, "---------------- ENV VARIABLES ----------------")?;

        for var in per_var {
            writeln!(lf, "{}={}", var.key, var.value)?;
        }

        writeln!(lf)?;
        Ok(())
    }
}

impl Simulation for EnvVarsSimulation {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Environment Variables Collection\n");

        if cfg.dry_run {
            logger::info("dry-run: no environment variables collected.");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("{} - {}", MITRE_TTP, MODULE_NAME),
                status: "dry-run".into(),
                details: "Env vars collection skipped".into(),
                artifact_path: None,
            };
            // Append to existing Magnet log
            write_action_record(cfg, &rec)?;
            logger::action_ok();
            return Ok(());
        }

        let vars: Vec<EnvVarRecord> = env::vars()
            .map(|(k, v)| EnvVarRecord {
                timestamp: Utc::now().to_rfc3339(),
                key: k,
                value: v,
            })
            .collect();

        for var in &vars {
            logger::info(&format!("{}={}", var.key, var.value));
        }

        let telemetry = EnvVarsTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            mitre: MITRE_TTP.into(),
            module: MODULE_NAME.into(),
            total_vars: vars.len(),
            parent: std::env::current_exe()
                .map(|x| x.display().to_string())
                .unwrap_or("<unknown>".into()),
        };

        if let Err(e) = Self::write_detailed_telemetry(cfg, &telemetry, &vars) {
            logger::warn(&format!("telemetry write failed: {}", e));
        }

        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("{} - {}", MITRE_TTP, MODULE_NAME),
            status: "completed".into(),
            details: format!("Collected {} environment variables.", vars.len()),
            artifact_path: None,
        };
        // Append action record to Magnet log instead of creating a new one
        write_action_record(cfg, &rec)?;

        logger::action_ok();
        Ok(())
    }
}
