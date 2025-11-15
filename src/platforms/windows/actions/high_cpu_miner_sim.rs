//! Simulates a short-lived high-CPU miner workload (T1496.001).  

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
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

/// Duration of the CPU burn (seconds)
const BURN_DURATION_SECS: u64 = 30;

/// How many worker threads to spawn. Default: number of logical CPUs.
fn default_worker_count() -> usize {
    num_cpus::get()
}

#[derive(Default)]
pub struct HighCpuMinerSimulation;

#[derive(Serialize)]
struct HighCpuTelemetry {
    test_id: String,
    timestamp: String,
    duration_s: u64,
    worker_threads: usize,
    total_iterations: u128,
    avg_iterations_per_thread: f64,
    elapsed_ms: u128,
    parent: String,
}

impl HighCpuMinerSimulation {
    fn telemetry_dir() -> Option<PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn write_detailed_telemetry(cfg: &Config, rec: &HighCpuTelemetry) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir)
            .with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        // jsonl
        let mut jsonl = dir.clone();
        jsonl.push(format!("high_cpu_sim_{}.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl)
            .with_context(|| format!("opening telemetry file {}", jsonl.display()))?;
        let j = serde_json::to_string(rec)?;
        writeln!(jf, "{}", j)?;

        // human-readable log
        let mut log = dir;
        log.push(format!("high_cpu_sim_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .with_context(|| format!("opening human log {}", log.display()))?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", rec.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
        writeln!(lf, "DURATION  : {}s", rec.duration_s)?;
        writeln!(lf, "WORKERS   : {}", rec.worker_threads)?;
        writeln!(lf, "ITER TOTAL: {}", rec.total_iterations)?;
        writeln!(lf, "ITER/THRD : {:.2}", rec.avg_iterations_per_thread)?;
        writeln!(lf, "PARENT    : {}", rec.parent)?;
        writeln!(lf, "ELAPSED_MS: {}", rec.elapsed_ms)?;
        writeln!(lf)?;
        Ok(())
    }
}

/// A safe, short-lived CPU burner used for resource-usage detection/tuning.
/// - Spawns one worker per logical CPU (configurable)
/// - Each worker performs a tight arithmetic loop for BURN_DURATION_SECS seconds
/// - Records total loop iterations as an observable metric (deterministic, synthetic)
impl Simulation for HighCpuMinerSimulation {
    fn name(&self) -> &'static str {
        "windows::high_cpu_miner_sim"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();
        logger::action_running(&format!("Simulating high CPU miner for {} seconds", BURN_DURATION_SECS));

        // Dry-run: report intention and write action record only
        if cfg.dry_run {
            logger::info(&format!("dry-run: would spawn {} worker threads for {}s CPU burn",
                                  default_worker_count(), BURN_DURATION_SECS));
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1496.001 - {}", self.name()), 
                status: "dry-run".into(),
                details: format!("dry-run: no CPU load; intended duration {}s; workers {}", BURN_DURATION_SECS, default_worker_count()),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // Spawn workers
        let workers = default_worker_count();
        let duration = Duration::from_secs(BURN_DURATION_SECS);
        let end_time = Instant::now() + duration;

        // Vector to collect thread join handles and per-thread iteration counts
        let mut handles = Vec::with_capacity(workers);

        for idx in 0..workers {
            let thread_end = end_time;
            // Each thread returns its iteration count (u128)
            let handle = thread::spawn(move || -> u128 {
                // a simple pseudo-work: arithmetic operations to keep CPU busy
                let mut iterations: u128 = 0;
                let mut acc: u128 = 0xDEADBEEF_u128;

                while Instant::now() < thread_end {
                    // perform small block of arithmetic to avoid being optimized away
                    for _ in 0..1024 {
                        // mix operations
                        acc = acc.wrapping_mul(6364136223846793005u128).wrapping_add(1442695040888963407u128);
                        acc ^= iterations;
                        iterations = iterations.wrapping_add((acc & 0xFFFF) as u128);
                    }
                    // keep the compiler from optimizing away acc
                    std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
                }

                // return iterations as a rough workload metric
                iterations
            });
            logger::info(&format!("spawned worker #{:03}", idx + 1));
            handles.push(handle);
        }

        // Join threads and aggregate iterations
        let mut total_iterations: u128 = 0;
        for (i, h) in handles.into_iter().enumerate() {
            match h.join() {
                Ok(count) => {
                    logger::info(&format!("worker #{:03} finished iterations={}", i + 1, count));
                    total_iterations = total_iterations.saturating_add(count);
                }
                Err(_) => {
                    logger::warn(&format!("worker #{:03} panicked or could not be joined", i + 1));
                }
            }
        }

        let elapsed = start.elapsed();

        // Telemetry
        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        let avg_per_thread = if default_worker_count() > 0 {
            total_iterations as f64 / default_worker_count() as f64
        } else {
            0.0
        };

        let telemetry = HighCpuTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            duration_s: BURN_DURATION_SECS,
            worker_threads: default_worker_count(),
            total_iterations,
            avg_iterations_per_thread: avg_per_thread,
            elapsed_ms: elapsed.as_millis(),
            parent,
        };

        if let Err(e) = Self::write_detailed_telemetry(cfg, &telemetry) {
            logger::warn(&format!("failed to write detailed telemetry: {}", e));
        }

        // Action record summary
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1496.001 - {}", self.name()), 
            status: "written".into(),
            details: format!("CPU burn for {}s on {} workers; total iterations {}", BURN_DURATION_SECS, telemetry.worker_threads, telemetry.total_iterations),
            artifact_path: None,
        };

        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
