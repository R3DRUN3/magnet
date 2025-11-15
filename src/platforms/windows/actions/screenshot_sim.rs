//! Simulates a program that takes screenshots (T1113).  

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;

use anyhow::{Context, Result};
use chrono::Utc;
use dirs::home_dir;
use serde::Serialize;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::{PathBuf};
use std::time::Instant;

/// ScreenshotSimulation: benign module structure (no actual capture in this template)
#[derive(Default)]
pub struct ScreenshotSimulation;

#[derive(Serialize)]
struct ScreenshotTelemetry {
    test_id: String,
    timestamp: String,
    screenshot_path: String,
    elapsed_ms: u128,
    parent: String,
}

impl ScreenshotSimulation {
    /// Determine telemetry directory (Documents\MagnetTelemetry)
    fn telemetry_dir() -> Option<PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn capture_screenshot(_cfg: &Config, out_path: &PathBuf) -> Result<()> {
        use image::{ImageBuffer, Rgba};
        use chrono::Local;
        use std::{thread::sleep, time::Duration};

        // You can tune how many frames and delay between them
        let total_frames = 10;
        let delay = Duration::from_secs(2);

        // Parent directory
        if let Some(parent) = out_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating dir {}", parent.display()))?;
        }

        for i in 0..total_frames {
            let width = 400;
            let height = 200;
            let mut img = ImageBuffer::<Rgba<u8>, Vec<u8>>::new(width, height);

            // Fill with a pattern that changes each frame
            for (x, y, pixel) in img.enumerate_pixels_mut() {
                let v = ((x + y + i * 10) % 255) as u8;
                *pixel = Rgba([v, 180, 220, 255]);
            }

            let now = Local::now();
            let msg = format!(
                "Simulated Screenshot #{}\n{}",
                i + 1,
                now.to_rfc3339()
            );
            for (n, b) in msg.as_bytes().iter().enumerate() {
                let x = 20 + (n as u32 % (width - 40));
                let y = 50 + (n as u32 / (width - 40)) * 10;
                if y < height - 1 {
                    img.put_pixel(x, y, Rgba([50, *b, 150, 255]));
                }
            }

            let mut file_path = out_path.clone();
            file_path.set_file_name(format!(
                "screenshot_{}_{}.png",
                now.format("%Y%m%dT%H%M%S"),
                i + 1
            ));

            img.save(&file_path)
                .with_context(|| format!("saving simulated screenshot {}", file_path.display()))?;

            println!("    captured synthetic frame {}", i + 1);
            sleep(delay);
        }

        Ok(())
    }



    /// Write telemetry JSON and a short human log.
    fn write_telemetry(cfg: &Config, rec: &ScreenshotTelemetry) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir)
            .with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        // JSONL
        let mut jsonl = dir.clone();
        jsonl.push(format!("screenshot_{}.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl)
            .with_context(|| format!("opening telemetry file {}", jsonl.display()))?;
        let j = serde_json::to_string(rec)?;
        writeln!(jf, "{}", j)?;

        // Human log
        let mut log = dir;
        log.push(format!("screenshot_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .with_context(|| format!("opening human log {}", log.display()))?;
        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", rec.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
        writeln!(lf, "PATH      : {}", rec.screenshot_path)?;
        writeln!(lf, "ELAPSED_MS: {}", rec.elapsed_ms)?;
        writeln!(lf, "PARENT    : {}", rec.parent)?;
        writeln!(lf)?;

        Ok(())
    }
}

impl Simulation for ScreenshotSimulation {
    fn name(&self) -> &'static str {
        "windows::screenshot"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();

        logger::action_running("Capturing screenshot ");

        let dir = ScreenshotSimulation::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir)
            .with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        let mut shot_path = dir.clone();
        shot_path.push(format!("screenshot_{}.png", cfg.test_id));

        // Dry-run: skip actual capture
        if cfg.dry_run {
            logger::info(&format!(
                "dry-run: would capture screenshot to {}",
                shot_path.display()
            ));
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1113 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: screenshot not captured".into(),
                artifact_path: Some(shot_path.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // Actual capture placeholder
        match Self::capture_screenshot(cfg, &shot_path) {
            Ok(_) => {
                let elapsed = start.elapsed();
                let parent = std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "<unknown>".to_string());

                let t = ScreenshotTelemetry {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    screenshot_path: shot_path.display().to_string(),
                    elapsed_ms: elapsed.as_millis(),
                    parent,
                };
                if let Err(e) = Self::write_telemetry(cfg, &t) {
                    logger::warn(&format!("failed to write telemetry: {}", e));
                }

                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1113 - {}", self.name()),
                    status: "written".into(),
                    details: "screenshot capture completed".into(),
                    artifact_path: Some(shot_path.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);

                logger::action_ok();
                Ok(())
            }
            Err(e) => {
                logger::action_fail("screenshot capture failed");
                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1113 - {}", self.name()),
                    status: "failed".into(),
                    details: format!("capture error: {}", e),
                    artifact_path: Some(shot_path.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);
                Err(e)
            }
        }
    }
}
