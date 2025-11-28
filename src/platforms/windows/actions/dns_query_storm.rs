//! Parallel DNS query storm with per-domain telemetry.
//! MITRE: T1071.004 - Application Layer Protocol: DNS

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;

use rayon::prelude::*;

use std::net::ToSocketAddrs;
use std::time::{Instant, Duration};
use std::thread;
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;

const TOTAL_QUERIES: usize = 40;
const MIN_JITTER_MS: u64 = 10;
const MAX_JITTER_MS: u64 = 80;

const MITRE_TTP: &str = "T1071.004";
const MODULE_NAME: &str = "windows::dns_query_storm";

/// Safe domain list
const DOMAINS: &[&str] = &[
    "example.com",
    "example.net",
    "iana.org",
    "localhost",
    "test.example.com",
    "safe.test",
    "internal.test",
    "microsoft.com",
    "windows.com",
    "office.com",
    "live.com",
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "openai.com",
    "cloudflare.com",
    "google.com",
    "gstatic.com",
    "googleapis.com",
    "aws.amazon.com",
    "azure.com",
    "oracle.com",
    "apple.com",
    "cdn.jsdelivr.net",
    "fastly.net",
    "akamai.net",
    "edgesuite.net",
    // NXDOMAIN-ish
    "aj39dksl.test",
    "randomsub1.safe.test",
    "rnd-2398.example.com",
    "ds98rtfxsmn.m1cr0soft.com",
];

#[derive(Default)]
pub struct DnsQueryStormSimulation;

/// Per-domain record (one per lookup)
#[derive(Serialize, Clone)]
pub struct DomainResult {
    timestamp: String,
    domain: String,
    success: bool,
    ip: Option<String>,
}

#[derive(Serialize)]
struct StormTelemetry {
    test_id: String,
    timestamp: String,
    mitre: String,
    module: String,
    total_queries: usize,
    successful: usize,
    failed: usize,
    elapsed_ms: u128,
    parent: String,
}

impl DnsQueryStormSimulation {

    fn telemetry_dir() -> Option<PathBuf> {
        dirs::home_dir().map(|mut p| {
            p.push("Documents");
            p.push("MagnetTelemetry");
            p
        })
    }

    fn write_detailed_telemetry(
        cfg: &Config,
        storm: &StormTelemetry,
        per_domain: &[DomainResult],
    ) -> Result<()> {

        let dir = Self::telemetry_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine telemetry dir"))?;

        create_dir_all(&dir)?;

        // JSONL per-domain
        let mut jsonl = dir.clone();
        jsonl.push(format!("dns_storm_{}_per_query.jsonl", cfg.test_id));

        let mut jf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&jsonl)?;

        for d in per_domain {
            writeln!(jf, "{}", serde_json::to_string(d)?)?;
        }

        // Summary JSONL
        let mut summary = dir.clone();
        summary.push(format!("dns_storm_{}_summary.jsonl", cfg.test_id));

        let mut sf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&summary)?;

        writeln!(sf, "{}", serde_json::to_string(storm)?)?;

        // Human-readable log
        let mut log = dir;
        log.push(format!("dns_storm_{}.log", cfg.test_id));

        let mut lf = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log)?;

        writeln!(lf, "===============================================================")?;
        writeln!(lf, "TEST ID       : {}", storm.test_id)?;
        writeln!(lf, "TIMESTAMP     : {}", storm.timestamp)?;
        writeln!(lf, "MODULE        : {}", storm.module)?;
        writeln!(lf, "MITRE TTP     : {}", storm.mitre)?;
        writeln!(lf, "TOTAL QUERIES : {}", storm.total_queries)?;
        writeln!(lf, "SUCCESSFUL    : {}", storm.successful)?;
        writeln!(lf, "FAILED        : {}", storm.failed)?;
        writeln!(lf, "ELAPSED_MS    : {}", storm.elapsed_ms)?;
        writeln!(lf, "---------------- DOMAIN RESULTS ----------------")?;

        for d in per_domain {
            writeln!(
                lf,
                "[{}] {} → {}{}",
                d.timestamp,
                d.domain,
                if d.success { "OK" } else { "FAIL" },
                d.ip.as_ref().map(|ip| format!(" ({})", ip)).unwrap_or_default()
            )?;
        }

        writeln!(lf)?;
        Ok(())
    }
}

impl Simulation for DnsQueryStormSimulation {
    fn name(&self) -> &'static str {
        MODULE_NAME
    }

    fn run(&self, cfg: &Config) -> Result<()> {

        let start = Instant::now();

        logger::action_running("Parallel DNS Query Storm");

        if cfg.dry_run {
            logger::info("dry-run: no DNS lookups executed.");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("{} - {}", MITRE_TTP, MODULE_NAME),
                status: "dry-run".into(),
                details: "DNS storm skipped".into(),
                artifact_path: None,
            };
            write_action_record(cfg, &rec)?;
            logger::action_ok();
            return Ok(());
        }

        logger::info(&format!(
            "Launching {} parallel DNS queries...",
            TOTAL_QUERIES
        ));

        // ----------------------------------------------------------
        // PARALLEL DNS LOOKUPS + per-domain logging
        // ----------------------------------------------------------
        let per_domain: Vec<DomainResult> = (0..TOTAL_QUERIES)
            .into_par_iter()
            .map(|i| {
                let domain = DOMAINS[i % DOMAINS.len()].to_string();

                let jitter = fastrand::u64(MIN_JITTER_MS..MAX_JITTER_MS);
                thread::sleep(Duration::from_millis(jitter));

                let lookup = format!("{}:80", domain);
                let timestamp = Utc::now().to_rfc3339();

                match lookup.to_socket_addrs() {
                    Ok(mut addrs) => {
                        if let Some(addr) = addrs.next() {
                            DomainResult {
                                timestamp,
                                domain,
                                success: true,
                                ip: Some(addr.ip().to_string()),
                            }
                        } else {
                            DomainResult {
                                timestamp,
                                domain,
                                success: false,
                                ip: None,
                            }
                        }
                    }
                    Err(_) => DomainResult {
                        timestamp,
                        domain,
                        success: false,
                        ip: None,
                    },
                }
            })
            .collect();

        // ----------------------------------------------------------
        // STDOUT LOGGING (per-domain)
        // ----------------------------------------------------------
        for d in &per_domain {
            if d.success {
                logger::info(&format!("{} → OK ({})", d.domain, d.ip.as_ref().unwrap()));
            } else {
                logger::info(&format!("{} → FAIL", d.domain));
            }
        }

        let successful = per_domain.iter().filter(|r| r.success).count();
        let failed = TOTAL_QUERIES - successful;

        let elapsed = start.elapsed();
        logger::info(&format!(
            "DNS Storm completed: {} ok, {} failed, {} ms",
            successful,
            failed,
            elapsed.as_millis()
        ));

        // ----------------------------------------------------------
        // SUMMARY TELEMETRY STRUCT
        // ----------------------------------------------------------
        let summary = StormTelemetry {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            mitre: MITRE_TTP.into(),
            module: MODULE_NAME.into(),
            total_queries: TOTAL_QUERIES,
            successful,
            failed,
            elapsed_ms: elapsed.as_millis(),
            parent: std::env::current_exe()
                .map(|x| x.display().to_string())
                .unwrap_or("<unknown>".into()),
        };

        // write telemetry (summary + per-domain)
        if let Err(e) = Self::write_detailed_telemetry(cfg, &summary, &per_domain) {
            logger::warn(&format!("telemetry write failed: {}", e));
        }

        // write action record
        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("{} - {}", MITRE_TTP, MODULE_NAME),
            status: "completed".into(),
            details: format!("{} ok, {} failed DNS lookups.", successful, failed),
            artifact_path: None,
        };
        let _ = write_action_record(cfg, &rec);

        logger::action_ok();
        Ok(())
    }
}
