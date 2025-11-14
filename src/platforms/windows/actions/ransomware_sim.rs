//! Simulates realistic ransomware behavior for purple-team testing.

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;
use anyhow::{Context, Result};
use chrono::Utc;
use dirs::desktop_dir;
use dirs::home_dir;
use serde::Serialize;
use std::fs::{create_dir_all, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use std::process::{Command, Stdio};

/// Number of test files to create in the repo (tuneable).
const DEFAULT_NUM_FILES: usize = 10000;
/// Per-file size in bytes (simple small content); files will include textual headers.
const PER_FILE_SIZE: usize = 512;
/// XOR key used to "encrypt" files (reversible).
const XOR_KEY: u8 = 0xAA;

/// Create a realistic but safe ransomware simulation:
/// - create a test repo and N files
/// - encrypt those files (XOR) in-place (only within the repo)
/// - Delete the oldest shadow copy of C:
/// - finally create the ransom note on the Desktop
#[derive(Default)]
pub struct RansomSimulation;

#[derive(Serialize)]
struct RansomTelemetry {
    test_id: String,
    timestamp: String,
    repo_path: String,
    files_created: usize,
    files_encrypted: usize,
    shadow_action: String,
    elapsed_ms: u128,
    parent: String,
}

impl RansomSimulation {
    fn build_note_content(test_id: &str) -> String {
        let now = Utc::now().to_rfc3339();
        let lines = vec![
            "=== MAGNET RANSOM-NOTE SIMULATION ===".to_string(),
            "".to_string(),
            "THIS IS A BENIGN TEST ARTIFACT CREATED BY THE MAGNET TOOL.".to_string(),
            "DO NOT RESPOND — this file is safe and created for purple-team testing.".to_string(),
            "".to_string(),
            format!("MAGNET-TEST-ID: {}", test_id),
            format!("TIMESTAMP: {}", now),
            "".to_string(),
            "To the SOC: This artifact is used to validate detection, ingestion and response.".to_string(),
            "".to_string(),
            "=== END OF NOTE ===".to_string(),
        ];
        lines.join("\r\n")
    }

    fn desktop_path() -> Option<PathBuf> {
        desktop_dir()
    }

    fn note_path(desktop: &Path) -> PathBuf {
        desktop.join("RANSOM_NOTE.txt")
    }

    /// Telemetry dir: %USERPROFILE%\Documents\MagnetTelemetry
    fn telemetry_dir() -> Option<PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn make_repo_path(cfg: &Config) -> Option<PathBuf> {
        Self::telemetry_dir().map(|mut p| {
            p.push(format!("MagnetRepo_{}", cfg.test_id));
            p
        })
    }

    /// Create N simple files in `repo` with predictable content.
    fn create_test_files(repo: &Path, n: usize) -> Result<Vec<PathBuf>> {
        create_dir_all(repo).with_context(|| format!("creating repo dir {}", repo.display()))?;
        let mut paths = Vec::with_capacity(n);

        for i in 0..n {
            if i % 500 == 0 {
                logger::info(&format!("  → creating files... {}/{}", i, n));
            }

            let filename = format!("file_{:06}.txt", i + 1);
            let mut path = repo.to_path_buf();
            path.push(filename);

            let mut file = File::create(&path)
                .with_context(|| format!("creating file {}", path.display()))?;

            let header = format!("MAGNET-TEST-FILE\nIndex: {}\n\n", i + 1);
            let mut content = header.into_bytes();

            while content.len() < PER_FILE_SIZE {
                content.extend_from_slice(b"The quick brown fox jumps over the lazy dog.\n");
            }
            content.truncate(PER_FILE_SIZE);

            file.write_all(&content)
                .with_context(|| format!("writing to file {}", path.display()))?;

            paths.push(path);
        }

        Ok(paths)
    }

    /// Simple in-place "encryption" using XOR key. Overwrites the file content.
    fn encrypt_file_inplace(path: &Path) -> Result<()> {
        let mut buf = Vec::new();
        {
            let mut f = File::open(path).with_context(|| format!("opening for read: {}", path.display()))?;
            f.read_to_end(&mut buf)
                .with_context(|| format!("reading file {}", path.display()))?;
        }

        for b in &mut buf {
            *b ^= XOR_KEY;
        }

        let mut f = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .with_context(|| format!("opening for write: {}", path.display()))?;
        f.write_all(&buf)
            .with_context(|| format!("writing encrypted file {}", path.display()))?;

        Ok(())
    }

    fn simulate_shadow_delete(_cfg: &Config) -> Result<String> {
        let volume = "C:".to_string();
        logger::info(&format!("deleting oldest shadow copy on volume {}...", volume));

        let output = Command::new("vssadmin")
            .args(["delete", "shadows", &format!("/for={}", volume), "/oldest", "/quiet"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()?;

        if output.status.success() {
            Ok(format!("Successfully deleted the oldest shadow copy on volume {}.", volume))
        } else {
            let err_msg = String::from_utf8_lossy(&output.stderr);
            Ok(format!("Failed to delete shadow copy on {}: {}", volume, err_msg))
        }
    }

    fn write_detailed_telemetry(cfg: &Config, rec: &RansomTelemetry) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir)
            .with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        let mut jsonl = dir.clone();
        jsonl.push(format!("ransom_sim_{}.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl)
            .with_context(|| format!("opening telemetry file {}", jsonl.display()))?;
        writeln!(jf, "{}", serde_json::to_string(rec)?)?;

        let mut log = dir;
        log.push(format!("ransom_sim_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .with_context(|| format!("opening human log {}", log.display()))?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", rec.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
        writeln!(lf, "REPO      : {}", rec.repo_path)?;
        writeln!(lf, "FILES     : created={}, encrypted={}", rec.files_created, rec.files_encrypted)?;
        writeln!(lf, "SHADOW    : {}", rec.shadow_action)?;
        writeln!(lf, "PARENT    : {}", rec.parent)?;
        writeln!(lf, "ELAPSED_MS: {}", rec.elapsed_ms)?;
        writeln!(lf)?;

        Ok(())
    }
}

impl Simulation for RansomSimulation {
    fn name(&self) -> &'static str {
        "windows::ransomware_sim"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();
        let test_id = &cfg.test_id;
        let note_content = Self::build_note_content(test_id);

        let desktop = Self::desktop_path().context("could not determine Desktop path")?;
        let note_path = Self::note_path(&desktop);

        logger::action_running(
            "Simulating ransomware: create repo, encrypt files, oldest sc deletion, drop note",
        );

        if cfg.dry_run {
            logger::info("dry-run: would create repo and encrypt files");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "ransomware_sim".into(),
                status: "dry-run".into(),
                details: "dry-run: no repo created, no files encrypted".into(),
                artifact_path: Some(note_path.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // -----------------------------------------------------
        // 1) Create repo + files
        // -----------------------------------------------------
        logger::info("\ncreating test repository and files...");
        let repo = Self::make_repo_path(cfg)
            .ok_or_else(|| anyhow::anyhow!("could not determine repo path"))?;

        let files = match Self::create_test_files(&repo, DEFAULT_NUM_FILES) {
            Ok(paths) => {
                logger::info("file creation complete.");
                paths
            }
            Err(e) => {
                logger::action_fail("failed to create repo files");
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: "ransomware_sim".into(),
                    status: "failed".into(),
                    details: format!("create files error: {}", e),
                    artifact_path: Some(repo.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);
                return Err(e);
            }
        };

        // -----------------------------------------------------
        // 2) Encrypt created files
        // -----------------------------------------------------
        logger::info("encrypting files in-place...");
        let mut encrypted = 0usize;

        for (idx, p) in files.iter().enumerate() {
            if idx % 500 == 0 {
                logger::info(&format!("  → encrypting... {}/{}", idx, files.len()));
            }

            if let Err(e) = Self::encrypt_file_inplace(p) {
                logger::warn(&format!("encryption failed for {}: {}", p.display(), e));
            } else {
                encrypted += 1;
            }
        }

        logger::info("encryption complete.");

        // -----------------------------------------------------
        // 3) Delete oldest shadow copy
        // -----------------------------------------------------
        let shadow_action = match Self::simulate_shadow_delete(cfg) {
            Ok(s) => s,
            Err(e) => {
                logger::warn(&format!("shadow-sim failed: {}", e));
                format!("shadow_sim_failed:{}", cfg.test_id)
            }
        };

        // -----------------------------------------------------
        // 4) Write ransom note
        // -----------------------------------------------------
        logger::info("writing ransom note to Desktop...");

        match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&note_path)
            .with_context(|| format!("failed to open file {}", note_path.display()))
        {
            Ok(mut nf) => {
                nf.write_all(note_content.as_bytes())
                    .with_context(|| format!("failed to write to {}", note_path.display()))?;
            }
            Err(e) => {
                logger::action_fail("failed to write ransom note");
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: "ransomware_sim".into(),
                    status: "failed".into(),
                    details: format!("note write error: {}", e),
                    artifact_path: Some(note_path.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);
                return Err(e);
            }
        }

        // -----------------------------------------------------
        // 5) Telemetry
        // -----------------------------------------------------
        logger::info("writing simulation telemetry...");

        let elapsed = start.elapsed();
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        let t = RansomTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            repo_path: repo.display().to_string(),
            files_created: files.len(),
            files_encrypted: encrypted,
            shadow_action,
            elapsed_ms: elapsed.as_millis(),
            parent,
        };

        if let Err(e) = Self::write_detailed_telemetry(cfg, &t) {
            logger::warn(&format!("failed to write detailed telemetry: {}", e));
        }

        // Action record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: "ransomware_sim".into(),
            status: "written".into(),
            details: format!("Repo: {} created; {} files encrypted", repo.display(), encrypted),
            artifact_path: Some(note_path.display().to_string()),
        };
        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
