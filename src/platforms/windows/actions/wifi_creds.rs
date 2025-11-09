use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::logger;
use crate::core::telemetry::{write_action_record, ActionRecord};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use dirs::home_dir;
use hostname;

/// Wi-Fi credential extraction (PowerShell-equivalent)
///
/// WARNING: This collects *real* Wi-Fi keys. Only run on machines you own
/// or are explicitly authorized to test. It will NOT print passwords to the CLI;
/// passwords are written only to telemetry files under Documents\MagnetTelemetry.
#[derive(Default)]
pub struct WifiCreds;

#[derive(Serialize)]
struct WifiEntry {
    profile: String,
    password: String, // "N/A" if not present or extraction failed
}

#[derive(Serialize)]
struct WifiRecord {
    test_id: String,
    timestamp: String,
    host: String,
    entries: Vec<WifiEntry>,
    parent: String,
}

impl WifiCreds {
    /// Run `netsh wlan show profiles` and parse profile names similar to the PowerShell script.
    /// This is robust: case-insensitive, trims names, and deduplicates.
    fn list_profiles() -> Result<Vec<String>> {
        // Run the netsh command (via cmd /C to match PowerShell behavior)
        let out = Command::new("cmd")
            .args(["/C", "netsh wlan show profiles"])
            .output()
            .context("failed to run 'netsh wlan show profiles'")?;

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();

        // Try regex that matches lines like:
        //    All User Profile     : MyWifiName
        // Case-insensitive
        let re = Regex::new(r"(?i)All User Profile\s*:\s*(?P<name>.+)$").unwrap();

        let mut names = Vec::new();
        for line in stdout.lines() {
            if let Some(cap) = re.captures(line) {
                if let Some(m) = cap.name("name") {
                    let name = m.as_str().trim().to_string();
                    if !name.is_empty() {
                        names.push(name);
                    }
                }
            }
        }

        // Fallback: some locales or netsh versions may list profiles differently.
        // Look for lines that contain ":" and appear to be profile lines (heuristic)
        if names.is_empty() {
            let alt_re = Regex::new(r"(?i)Profile\s*:\s*(?P<name>.+)$").unwrap();
            for line in stdout.lines() {
                if let Some(cap) = alt_re.captures(line) {
                    if let Some(m) = cap.name("name") {
                        let name = m.as_str().trim().to_string();
                        if !name.is_empty() {
                            names.push(name);
                        }
                    }
                }
            }
        }

        // Deduplicate while preserving order
        let mut seen = HashSet::new();
        let mut dedup = Vec::new();
        for n in names {
            if seen.insert(n.clone()) {
                dedup.push(n);
            }
        }

        Ok(dedup)
    }

    /// For a single profile, run `netsh wlan show profile name="<profile>" key=clear`
    /// and extract a `Key Content : <password>` line if present.
    fn get_profile_password(profile: &str) -> Result<String> {
        // Build a command similar to PowerShell's use of quotes
        let safe_profile = profile.replace('"', r#"\""#);
        let cmd = format!(r#"netsh wlan show profile name="{}" key=clear"#, safe_profile);

        let out = Command::new("cmd")
            .args(["/C", &cmd])
            .output()
            .with_context(|| format!("failed to run netsh for profile '{}'", profile))?;

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();

        // Regex: "Key Content            : <password>"
        // Use case-insensitive and trim
        let re = Regex::new(r"(?i)Key Content\s*:\s*(?P<pw>.+)$").unwrap();
        for line in stdout.lines() {
            if let Some(cap) = re.captures(line) {
                if let Some(m) = cap.name("pw") {
                    return Ok(m.as_str().trim().to_string());
                }
            }
        }

        // Some systems may report "Key Index" etc.; if not found, return "N/A"
        Ok("N/A".to_string())
    }

    fn telemetry_dir() -> Option<PathBuf> {
        if let Some(mut p) = home_dir() {
            p.push("Documents");
            p.push("MagnetTelemetry");
            Some(p)
        } else {
            None
        }
    }

    /// Write JSONL and human-readable log (this log WILL contain passwords per W3).
    fn write_telemetry(cfg: &Config, rec: &WifiRecord) -> Result<()> {
        let dir = Self::telemetry_dir().ok_or_else(|| anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir).with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        // JSONL
        let mut jsonl = dir.clone();
        jsonl.push(format!("wifi_credentials_{}.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl)
            .with_context(|| format!("opening telemetry file {}", jsonl.display()))?;
        let j = serde_json::to_string(rec)?;
        writeln!(jf, "{}", j)?;

        // Human log (passwords included)
        let mut log = dir;
        log.push(format!("wifi_credentials_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .with_context(|| format!("opening human log {}", log.display()))?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", rec.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
        writeln!(lf, "HOST      : {}", rec.host)?;
        writeln!(lf, "PARENT    : {}", rec.parent)?;
        writeln!(lf, "----------------------------------------------------------------")?;
        for e in &rec.entries {
            writeln!(lf, "Profile : {}", e.profile)?;
            writeln!(lf, "Password: {}", e.password)?;
            writeln!(lf, "----------------------------------------------------------------")?;
        }
        writeln!(lf)?;

        Ok(())
    }
}

impl Simulation for WifiCreds {
    fn name(&self) -> &'static str {
        "windows::wifi_creds"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        // Minimal console output only (no passwords)
        logger::action_running("Enumerating Wi-Fi profiles (passwords go to telemetry)");

        if cfg.dry_run {
            // write central action record
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "wifi_creds".into(),
                status: "dry-run".into(),
                details: "dry-run: no profiles extracted".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // List profiles (PowerShell equivalent)
        let profiles = match Self::list_profiles() {
            Ok(p) => p,
            Err(e) => {
                logger::action_fail("failed to list Wi-Fi profiles");
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: "wifi_creds".into(),
                    status: "failed".into(),
                    details: format!("list error: {}", e),
                    artifact_path: None,
                };
                let _ = write_action_record(cfg, &rec);
                return Err(e);
            }
        };

        // If none found, still write an action record and exit gracefully
        if profiles.is_empty() {
            logger::warn("no Wi-Fi profiles found");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "wifi_creds".into(),
                status: "no-profiles".into(),
                details: "no Wi-Fi profiles detected on this host".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // Extract password for each profile
        let mut entries = Vec::new();
        for profile in &profiles {
            match Self::get_profile_password(profile) {
                Ok(pw) => {
                    entries.push(WifiEntry {
                        profile: profile.clone(),
                        password: pw,
                    });
                }
                Err(e) => {
                    // On error, push N/A and continue
                    entries.push(WifiEntry {
                        profile: profile.clone(),
                        password: "N/A".to_string(),
                    });
                    logger::warn(&format!("failed to extract profile '{}': {}", profile, e));
                }
            }
        }

        // Compose WifiRecord
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());
        let host = hostname::get()
            .map(|h| h.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "<unknown>".into());

        let record = WifiRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            host,
            entries,
            parent,
        };

        // Write telemetry files (JSONL + human log)
        match Self::write_telemetry(cfg, &record) {
            Ok(_) => {
                // Also write a central action record (no sensitive data there)
                let act = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: "wifi_creds".into(),
                    status: "written".into(),
                    details: format!("Wrote {} profiles to wifi_credentials_{}.jsonl", record.entries.len(), cfg.test_id),
                    artifact_path: Some(format!("wifi_credentials_{}.jsonl", cfg.test_id)),
                };
                let _ = write_action_record(cfg, &act);

                logger::action_ok();
                Ok(())
            }
            Err(e) => {
                logger::action_fail("failed to write telemetry");
                let act = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: "wifi_creds".into(),
                    status: "failed".into(),
                    details: format!("telemetry error: {}", e),
                    artifact_path: None,
                };
                let _ = write_action_record(cfg, &act);
                Err(e)
            }
        }
    }
}
