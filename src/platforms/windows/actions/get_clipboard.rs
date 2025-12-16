//! Clipboard Content Collector
//! MITRE: T1115 - Clipboard Data

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use arboard::Clipboard;

use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const MITRE_TTP: &str = "T1115";
const MODULE_NAME: &str = "windows::get_clipboard";

#[derive(Default)]
pub struct ClipboardSimulation;

/// Per-clipboard entry record
#[derive(Serialize, Clone)]
pub struct ClipboardRecord {
    timestamp: String,
    content: String,
}

#[derive(Serialize)]
struct ClipboardTelemetry {
    test_id: String,
    timestamp: String,
    mitre: String,
    module: String,
    total_entries: usize,
    parent: String,
}

impl ClipboardSimulation {
    fn telemetry_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn write_detailed_telemetry(
        cfg: &Config,
        telemetry: &ClipboardTelemetry,
        per_clip: &[ClipboardRecord],
    ) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine telemetry dir"))?;

        create_dir_all(&dir)?;

        // Summary JSONL
        let mut summary = dir.clone();
        summary.push(format!("clipboard_{}_summary.jsonl", cfg.test_id));

        let mut sf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&summary)?;

        writeln!(sf, "{}", serde_json::to_string(telemetry)?)?;

        // Human-readable log
        let mut log = dir;
        log.push(format!("clipboard_{}.log", cfg.test_id));

        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)?;

        writeln!(lf, "===============================================================")?;
        writeln!(lf, "TEST ID       : {}", telemetry.test_id)?;
        writeln!(lf, "TIMESTAMP     : {}", telemetry.timestamp)?;
        writeln!(lf, "MODULE        : {}", telemetry.module)?;
        writeln!(lf, "MITRE TTP     : {}", telemetry.mitre)?;
        writeln!(lf, "TOTAL ENTRIES : {}", telemetry.total_entries)?;
        writeln!(lf, "---------------- CLIPBOARD CONTENT ----------------")?;

        for entry in per_clip {
            writeln!(lf, "{}", entry.content)?;
        }

        writeln!(lf)?;
        Ok(())
    }
}

impl Simulation for ClipboardSimulation {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Clipboard Content Collection\n");

        if cfg.dry_run {
            logger::info("dry-run: clipboard collection skipped.");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("{} - {}", MITRE_TTP, MODULE_NAME),
                status: "dry-run".into(),
                details: "Clipboard collection skipped".into(),
                artifact_path: None,
            };
            write_action_record(cfg, &rec)?;
            logger::action_ok();
            return Ok(());
        }

        let clipboard_text = Clipboard::new()
            .and_then(|mut clip| clip.get_text())
            .unwrap_or_else(|_| "<unavailable>".to_string());

        let record = ClipboardRecord {
            timestamp: Utc::now().to_rfc3339(),
            content: clipboard_text.clone(),
        };

        logger::info(&format!("Clipboard content: {}", clipboard_text));

        let telemetry = ClipboardTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            mitre: MITRE_TTP.into(),
            module: MODULE_NAME.into(),
            total_entries: 1,
            parent: std::env::current_exe()
                .map(|x| x.display().to_string())
                .unwrap_or("<unknown>".into()),
        };

        if let Err(e) = Self::write_detailed_telemetry(cfg, &telemetry, &[record.clone()]) {
            logger::warn(&format!("telemetry write failed: {}", e));
        }

        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("{} - {}", MITRE_TTP, MODULE_NAME),
            status: "completed".into(),
            details: format!("Collected clipboard content ({} chars).", clipboard_text.len()),
            artifact_path: None,
        };
        write_action_record(cfg, &rec)?;

        logger::action_ok();
        Ok(())
    }
}
