//! System Time Manipulation Simulation (simulates system clock tampering)
//! MITRE: T1124 (System Time Discovery), T1070.006 (Timestomp)
//! Requires admin rights for changing system time succesfully

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;

use anyhow::{Result, anyhow};
use chrono::{Utc, Duration, Datelike, Timelike};
use serde::Serialize;

use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use windows_sys::Win32::System::SystemInformation::{
    GetSystemTime,
    SetSystemTime,
};
use windows_sys::Win32::Foundation::SYSTEMTIME;

const MODULE_NAME: &str = "windows::time_manipulation_sim";
const MITRE_TTPS: &str = "T1124 - T1070.006";

#[derive(Default)]
pub struct TimeManipulationSimulation;

#[derive(Serialize, Clone)]
pub struct TimeAttempt {
    timestamp: String,
    attempted_offset_seconds: i64,
    result: String,
}

#[derive(Serialize)]
struct TimeTelemetry {
    test_id: String,
    timestamp: String,
    mitre: String,
    module: String,
    attempts: usize,
    successful: usize,
    restored: bool,
    parent: String,
}

impl TimeManipulationSimulation {
    fn telemetry_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn write_detailed_telemetry(
        cfg: &Config,
        summary: &TimeTelemetry,
        attempts: &[TimeAttempt],
    ) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow!("cannot determine telemetry dir"))?;

        create_dir_all(&dir)?;

        let mut summary_path = dir.clone();
        summary_path.push(format!("time_manipulation_{}_summary.jsonl", cfg.test_id));

        let mut sf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&summary_path)?;

        writeln!(sf, "{}", serde_json::to_string(summary)?)?;

        let mut log = dir;
        log.push(format!("time_manipulation_{}.log", cfg.test_id));

        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)?;

        writeln!(lf, "===============================================================")?;
        writeln!(lf, "TEST ID    : {}", summary.test_id)?;
        writeln!(lf, "TIMESTAMP  : {}", summary.timestamp)?;
        writeln!(lf, "MODULE     : {}", summary.module)?;
        writeln!(lf, "MITRE TTP  : {}", summary.mitre)?;
        writeln!(lf, "ATTEMPTS   : {}", summary.attempts)?;
        writeln!(lf, "SUCCESSFUL: {}", summary.successful)?;
        writeln!(lf, "RESTORED  : {}", summary.restored)?;
        writeln!(lf, "---------------- TIME ATTEMPTS ----------------")?;

        for a in attempts {
            writeln!(
                lf,
                "[{}] offset={}s → {}",
                a.timestamp,
                a.attempted_offset_seconds,
                a.result
            )?;
        }

        writeln!(lf)?;
        Ok(())
    }

    unsafe fn get_system_time() -> SYSTEMTIME {
        let mut st = unsafe { std::mem::zeroed() };
        unsafe { GetSystemTime(&mut st) };
        st
    }

    unsafe fn set_system_time(st: &SYSTEMTIME) -> bool {
        (unsafe { SetSystemTime(st) }) != 0
    }
}

impl Simulation for TimeManipulationSimulation {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("System Time Manipulation Simulation");

        if cfg.dry_run {
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("{} {}", MITRE_TTPS, MODULE_NAME),
                status: "dry-run".into(),
                details: "Time manipulation skipped".into(),
                artifact_path: None,
            };
            write_action_record(cfg, &rec)?;
            logger::action_ok();
            return Ok(());
        }

        let offsets = [-300, 300, -900, 1800];
        let mut attempts = Vec::new();
        let mut successful = 0;
        let mut restored = false;

        unsafe {
            let original = Self::get_system_time();

            for offset in offsets {
                let now = Utc::now() + Duration::seconds(offset);

                let mut new_time = original;
                new_time.wYear = now.year() as u16;
                new_time.wMonth = now.month() as u16;
                new_time.wDay = now.day() as u16;
                new_time.wHour = now.hour() as u16;
                new_time.wMinute = now.minute() as u16;
                new_time.wSecond = now.second() as u16;

                let ok = Self::set_system_time(&new_time);

                attempts.push(TimeAttempt {
                    timestamp: Utc::now().to_rfc3339(),
                    attempted_offset_seconds: offset,
                    result: if ok { "success" } else { "blocked" }.into(),
                });

                if ok {
                    successful += 1;
                }
            }

            if successful > 0 {
                restored = Self::set_system_time(&original);
            }
        }

        for a in &attempts {
            logger::info(&format!(
                "time offset {}s → {}",
                a.attempted_offset_seconds,
                a.result
            ));
        }

        let telemetry = TimeTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            mitre: MITRE_TTPS.into(),
            module: MODULE_NAME.into(),
            attempts: attempts.len(),
            successful,
            restored,
            parent: std::env::current_exe()
                .map(|x| x.display().to_string())
                .unwrap_or("<unknown>".into()),
        };

        if let Err(e) = Self::write_detailed_telemetry(cfg, &telemetry, &attempts) {
            logger::warn(&format!("telemetry write failed: {}", e));
        }

        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("{} {}", MITRE_TTPS, MODULE_NAME),
            status: if successful > 0 { "completed" } else { "blocked" }.into(),
            details: format!(
                "{} attempts, {} succeeded, restored={}",
                attempts.len(),
                successful,
                restored
            ),
            artifact_path: None,
        };

        write_action_record(cfg, &rec)?;
        logger::action_ok();
        Ok(())
    }
}
