//! Safe Named Pipe activity simulation.
//! MITRE: T1559.002 - Inter-Process Communication: Named Pipes

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::logger;
use crate::core::telemetry::{ActionRecord, write_action_record};

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use std::ptr::null_mut;

#[cfg(windows)]
use winapi::um::winbase::{
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_BYTE,
    PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES,
    FILE_FLAG_OVERLAPPED,
};

#[cfg(windows)]
use winapi::um::namedpipeapi::CreateNamedPipeW;

#[cfg(windows)]
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};

#[cfg(windows)]
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};

const MITRE_TTP: &str = "T1559.002";
const MODULE_NAME: &str = "windows::named_pipe_sim";

const PIPE_NAMES: &[&str] = &[
    r"\\.\pipe\mojo.12345.67890",
    r"\\.\pipe\PSEXESVC",
    r"\\.\pipe\status_communication",
    r"\\.\pipe\agent_telemetry",
    r"\\.\pipe\svcctl",
    r"\\.\pipe\session.pipe.test",
    r"\\.\pipe\random_task_channel",
];

#[derive(Default)]
pub struct NamedPipeSimulation;

#[derive(Serialize, Clone)]
pub struct PipeRecord {
    timestamp: String,
    pipe_name: String,
    stage: String,
    success: bool,
}

#[derive(Serialize)]
struct PipeSummary {
    test_id: String,
    timestamp: String,
    mitre: String,
    module: String,
    total_pipes: usize,
    successful: usize,
    failed: usize,
    parent: String,
}

impl NamedPipeSimulation {
    fn telemetry_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn write_telemetry(
        cfg: &Config,
        summary: &PipeSummary,
        records: &[PipeRecord],
    ) -> Result<()> {

        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine telemetry dir"))?;

        create_dir_all(&dir)?;

        let mut jsonl = dir.clone();
        jsonl.push(format!("named_pipe_{}_per_pipe.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new().create(true).append(true).open(&jsonl)?;
        for r in records {
            writeln!(jf, "{}", serde_json::to_string(r)?)?;
        }

        let mut summaryf = dir.clone();
        summaryf.push(format!("named_pipe_{}_summary.jsonl", cfg.test_id));
        let mut sf = OpenOptions::new().create(true).append(true).open(&summaryf)?;
        writeln!(sf, "{}", serde_json::to_string(summary)?)?;

        let mut logf = dir.clone();
        logf.push(format!("named_pipe_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new().create(true).append(true).open(&logf)?;

        writeln!(lf, "===============================================================")?;
        writeln!(lf, "TEST ID     : {}", summary.test_id)?;
        writeln!(lf, "TIMESTAMP   : {}", summary.timestamp)?;
        writeln!(lf, "MODULE      : {}", summary.module)?;
        writeln!(lf, "MITRE TTP   : {}", summary.mitre)?;
        writeln!(lf, "TOTAL OPS   : {}", summary.total_pipes)?;
        writeln!(lf, "SUCCESSFUL  : {}", summary.successful)?;
        writeln!(lf, "FAILED      : {}", summary.failed)?;

        writeln!(lf, "---------------- PIPE RESULTS ----------------")?;
        for r in records {
            writeln!(
                lf,
                "[{}] {} | {} | {}",
                r.timestamp, r.pipe_name, r.stage, if r.success { "OK" } else { "FAIL" }
            )?;
        }

        writeln!(lf)?;
        Ok(())
    }
}

impl Simulation for NamedPipeSimulation {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn run(&self, cfg: &Config) -> Result<()> {

        logger::action_running("\nSimulating Named Pipe server/client activity");

        if cfg.dry_run {
            logger::info("dry-run: no pipe operations executed.");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("{} - {}", MITRE_TTP, MODULE_NAME),
                status: "dry-run".into(),
                details: "Named pipe simulation skipped".into(),
                artifact_path: None,
            };
            write_action_record(cfg, &rec)?;
            logger::action_ok();
            return Ok(());
        }

        logger::info("\nCreating and connecting to test named pipes...");

        let mut records: Vec<PipeRecord> = Vec::new();

        #[cfg(windows)]
        {
            for &pipe_name in PIPE_NAMES {
                let timestamp = Utc::now().to_rfc3339();

                let wide: Vec<u16> = OsStr::new(pipe_name)
                    .encode_wide()
                    .chain(std::iter::once(0))
                    .collect();

                // SERVER: CreateNamedPipeW
                let hpipe = unsafe {
                    CreateNamedPipeW(
                        wide.as_ptr(),
                        PIPE_ACCESS_DUPLEX,
                        PIPE_TYPE_BYTE | PIPE_WAIT,
                        PIPE_UNLIMITED_INSTANCES,
                        4096,
                        4096,
                        0,
                        null_mut(),
                    )
                };

                let ok_server = hpipe != INVALID_HANDLE_VALUE;

                records.push(PipeRecord {
                    timestamp: timestamp.clone(),
                    pipe_name: pipe_name.into(),
                    stage: "create_pipe".into(),
                    success: ok_server,
                });

                logger::info(&format!(
                    "{} → create_pipe {}",
                    pipe_name,
                    if ok_server { "OK" } else { "FAIL" }
                ));

                if !ok_server {
                    continue;
                }

                // SERVER READY (no blocking connect)
                records.push(PipeRecord {
                    timestamp: timestamp.clone(),
                    pipe_name: pipe_name.into(),
                    stage: "server_ready".into(),
                    success: true,
                });

                logger::info(&format!("{} → server_ready OK", pipe_name));

                // CLIENT: CreateFileW
                let hclient = unsafe {
                    CreateFileW(
                        wide.as_ptr(),
                        winapi::um::winnt::GENERIC_READ | winapi::um::winnt::GENERIC_WRITE,
                        0,
                        null_mut(),
                        OPEN_EXISTING,
                        FILE_FLAG_OVERLAPPED,
                        null_mut(),
                    )
                };

                let ok_client = hclient != INVALID_HANDLE_VALUE;

                records.push(PipeRecord {
                    timestamp: timestamp.clone(),
                    pipe_name: pipe_name.into(),
                    stage: "client_connect".into(),
                    success: ok_client,
                });

                logger::info(&format!(
                    "{} → client_connect {}",
                    pipe_name,
                    if ok_client { "OK" } else { "FAIL" }
                ));

                unsafe {
                    CloseHandle(hpipe);
                    if ok_client {
                        CloseHandle(hclient);
                    }
                }
            }

            let successful = records.iter().filter(|r| r.success).count();
            let total = records.len();
            let failed = total - successful;

            logger::info(&format!("Named pipe simulation: {} ok, {} failed", successful, failed));

            let summary = PipeSummary {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                mitre: MITRE_TTP.into(),
                module: MODULE_NAME.into(),
                total_pipes: total,
                successful,
                failed,
                parent: std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or("<unknown>".into()),
            };

            let _ = Self::write_telemetry(cfg, &summary, &records);

            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("{} - {}", MITRE_TTP, MODULE_NAME),
                status: "completed".into(),
                details: format!("{} ok, {} failed pipe operations", successful, failed),
                artifact_path: None,
            };

            let _ = write_action_record(cfg, &rec);

            logger::action_ok();
        }

        Ok(())
    }
}
