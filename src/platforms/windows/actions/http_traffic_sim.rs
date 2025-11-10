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
use std::time::{Duration, Instant};
use std::env;

/// Number of simulated HTTP requests to perform (tuneable)
const DEFAULT_REQUEST_COUNT: usize = 100;

/// Delay between requests (ms)
const REQUEST_DELAY_MS: u64 = 30;

/// Target endpoint — benign public host, safe for GET/HEAD requests.
const TARGET_URL: &str = "https://github.com";

#[derive(Default)]
pub struct HttpTrafficSimulation;

#[derive(Serialize)]
struct HttpTrafficTelemetry {
    test_id: String,
    timestamp: String,
    target_url: String,
    requests_attempted: usize,
    requests_succeeded: usize,
    avg_latency_ms: f64,
    user_agent: String,
    elapsed_ms: u128,
    parent: String,
}

/// A realistic simulation of HTTP beacon / exfil / C2 traffic patterns.
/// This module performs safe HTTPS HEAD requests to `https://github.com`,
/// with randomized headers and pacing to emulate beacon-like traffic.
/// It never sends any sensitive data — payloads are synthetic and constant.
impl HttpTrafficSimulation {
    fn telemetry_dir() -> Option<PathBuf> {
        home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn write_detailed_telemetry(cfg: &Config, rec: &HttpTrafficTelemetry) -> Result<()> {
        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine telemetry output path"))?;
        create_dir_all(&dir)
            .with_context(|| format!("creating telemetry directory {}", dir.display()))?;

        // jsonl
        let mut jsonl = dir.clone();
        jsonl.push(format!("http_traffic_sim_{}.jsonl", cfg.test_id));
        let mut jf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl)
            .with_context(|| format!("opening telemetry file {}", jsonl.display()))?;
        let j = serde_json::to_string(rec)?;
        writeln!(jf, "{}", j)?;

        // human-readable log
        let mut log = dir;
        log.push(format!("http_traffic_sim_{}.log", cfg.test_id));
        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)
            .with_context(|| format!("opening human log {}", log.display()))?;

        writeln!(lf, "================================================================")?;
        writeln!(lf, "TEST ID   : {}", rec.test_id)?;
        writeln!(lf, "TIMESTAMP : {}", rec.timestamp)?;
        writeln!(lf, "TARGET URL: {}", rec.target_url)?;
        writeln!(lf, "REQUESTS  : attempted={}, succeeded={}", rec.requests_attempted, rec.requests_succeeded)?;
        writeln!(lf, "AVG_LAT_MS: {:.2}", rec.avg_latency_ms)?;
        writeln!(lf, "USERAGENT : {}", rec.user_agent)?;
        writeln!(lf, "PARENT    : {}", rec.parent)?;
        writeln!(lf, "ELAPSED_MS: {}", rec.elapsed_ms)?;
        writeln!(lf)?;
        Ok(())
    }

    /// Perform a series of safe HEAD requests to TARGET_URL to simulate HTTP beacons.
    fn perform_requests(n: usize) -> (usize, f64) {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build HTTP client");

        let mut success = 0usize;
        let mut total_latency: f64 = 0.0;
        let ua_base = format!("MagnetHTTPTest/{}", env::consts::OS);

        for i in 0..n {
            let start = Instant::now();
            let user_agent = format!("{} (iteration:{:03})", ua_base, i + 1);

            let res = client
                .head(TARGET_URL)
                .header("User-Agent", &user_agent)
                .header("X-Magnet-Test", "purple-simulation")
                .header("X-Magnet-Seq", format!("{}", i + 1))
                .send();

            let elapsed_ms = start.elapsed().as_millis() as f64;
            total_latency += elapsed_ms;

            match res {
                Ok(r) if r.status().is_success() => {
                    success += 1;
                    logger::info(&format!("HTTP {} {}ms", r.status(), elapsed_ms));
                }
                Ok(r) => {
                    logger::warn(&format!("HTTP non-success status {} after {}ms", r.status(), elapsed_ms));
                }
                Err(e) => {
                    logger::warn(&format!("HTTP request failed: {}", e));
                }
            }

            std::thread::sleep(Duration::from_millis(REQUEST_DELAY_MS));
        }

        let avg_latency = if n > 0 {
            total_latency / n as f64
        } else {
            0.0
        };

        (success, avg_latency)
    }
}

impl Simulation for HttpTrafficSimulation {
    fn name(&self) -> &'static str {
        "windows::http_traffic_sim"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();
        logger::action_running("Simulating HTTP beaconing / exfil traffic to https://github.com");

        // Dry-run: no network calls, only telemetry
        if cfg.dry_run {
            logger::info("dry-run: would perform HTTP HEAD requests to https://github.com");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: "http_traffic_sim".into(),
                status: "dry-run".into(),
                details: "dry-run: no network requests made".into(),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        // Execute the simulated traffic
        let (succeeded, avg_latency) = Self::perform_requests(DEFAULT_REQUEST_COUNT);
        let elapsed = start.elapsed();

        let parent = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "<unknown>".to_string());

        let t = HttpTrafficTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            target_url: TARGET_URL.to_string(),
            requests_attempted: DEFAULT_REQUEST_COUNT,
            requests_succeeded: succeeded,
            avg_latency_ms: avg_latency,
            user_agent: format!("MagnetHTTPTest/{}", env::consts::OS),
            elapsed_ms: elapsed.as_millis(),
            parent,
        };

        if let Err(e) = Self::write_detailed_telemetry(cfg, &t) {
            logger::warn(&format!("failed to write detailed telemetry: {}", e));
        }

        // Also write summary action record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: "http_traffic_sim".into(),
            status: "written".into(),
            details: format!("Performed {} HTTP requests to {} ({} successes, avg {:.2}ms)",
                             DEFAULT_REQUEST_COUNT, TARGET_URL, succeeded, avg_latency),
            artifact_path: None,
        };
        if let Err(e) = write_action_record(cfg, &rec) {
            logger::warn(&format!("failed to write action record: {}", e));
        }

        logger::action_ok();
        Ok(())
    }
}
