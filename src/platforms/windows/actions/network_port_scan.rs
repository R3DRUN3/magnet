//! Network port scanning simulation: detect local IPv4, find the first alive host,
//! then port-scan that host (T1046).

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record, telemetry_dir};
use crate::core::logger;

use anyhow::{Context, Result};
use chrono::Utc;
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use tokio::net::TcpStream;
use tokio::process::Command;
use get_if_addrs::get_if_addrs;

/// Ports scanned
const PORTS: &[u16] = &[21, 22, 25, 53, 80, 88, 135, 443, 445, 3306, 3389];

#[derive(Default)]
pub struct NetworkPortScanSimulation;

#[derive(Serialize)]
struct NetworkPortScanTelemetry {
    test_id: String,
    timestamp: String,

    local_ipv4: String,
    first_alive_host: Option<String>,

    scanned_ports: Vec<u16>,
    open_ports: Vec<u16>,

    elapsed_ms: u128,
    parent: String,
}

impl NetworkPortScanSimulation {
    // Detect local IPv4 (non-loopback)
    fn find_local_ipv4() -> Option<Ipv4Addr> {
        for iface in get_if_addrs().ok()? {
            if iface.is_loopback() {
                continue;
            }
            if let IpAddr::V4(v4) = iface.addr.ip() {
                return Some(v4);
            }
        }
        None
    }

    async fn ping_host(ip: IpAddr) -> bool {
        let output = Command::new("ping")
            .arg("-n").arg("1")
            .arg("-w").arg("150")
            .arg(ip.to_string())
            .output()
            .await;

        matches!(output, Ok(out) if out.status.success())
    }

    async fn check_port(ip: IpAddr, port: u16) -> bool {
        TcpStream::connect(SocketAddr::new(ip, port)).await.is_ok()
    }
}

impl Simulation for NetworkPortScanSimulation {
    fn name(&self) -> &'static str {
        "windows::network_port_scan"
    }

    fn run(&self, cfg: &Config) -> Result<()> {

        // Create Tokio runtime for async scanning
        let rt = tokio::runtime::Runtime::new().context("creating tokio runtime")?;
        rt.block_on(async {
            let start = Instant::now();

            // =========================================================================
            // STEP 1 — Detect Local IPv4
            // =========================================================================
            logger::action_running("Detecting local IPv4");

            let local = match Self::find_local_ipv4() {
                Some(ip) => {
                    logger::action_ok();
                    logger::info(&format!("Local IPv4 detected: {}", ip));
                    ip
                }
                None => {
                    logger::action_fail("Could not detect local IPv4");
                    let rec = ActionRecord {
                        test_id: cfg.test_id.clone(),
                        timestamp: Utc::now().to_rfc3339(),
                        action: format!("T1046 - {}", self.name()),
                        status: "failed".into(),
                        details: "No local IPv4 detected".into(),
                        artifact_path: None,
                    };
                    let _ = write_action_record(cfg, &rec);
                    return Err(anyhow::anyhow!("no local IPv4"));
                }
            };

            let oct = local.octets();

            if cfg.dry_run {
                logger::info(&format!(
                    "dry-run: would scan subnet {}.{}.{}.*",
                    oct[0], oct[1], oct[2]
                ));
                logger::info("dry-run: no scanning performed");

                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1046 - {}", self.name()),
                    status: "dry-run".into(),
                    details: "dry-run: local-ip-only".into(),
                    artifact_path: None,
                };
                let _ = write_action_record(cfg, &rec);

                logger::action_ok();
                return Ok(());
            }

            // =========================================================================
            // STEP 2 — Find First Alive Host
            // =========================================================================
            logger::action_running("Scanning subnet for first alive host");

            let mut first_alive: Option<IpAddr> = None;

            for i in 1..=254 {
                let ip = IpAddr::V4(Ipv4Addr::new(oct[0], oct[1], oct[2], i));

                if Self::ping_host(ip).await {
                    first_alive = Some(ip);
                    break;
                }
            }

            let host = match first_alive {
                Some(ip) => {
                    logger::action_ok();
                    logger::info(&format!("First alive host: {}", ip));
                    ip
                }
                None => {
                    logger::action_fail("No alive hosts found");
                    let rec = ActionRecord {
                        test_id: cfg.test_id.clone(),
                        timestamp: Utc::now().to_rfc3339(),
                        action: format!("T1046 - {}", self.name()),
                        status: "failed".into(),
                        details: "no alive hosts detected".into(),
                        artifact_path: None,
                    };
                    let _ = write_action_record(cfg, &rec);
                    return Err(anyhow::anyhow!("no alive hosts"));
                }
            };

            // =========================================================================
            // STEP 3 — Scan Selected Ports
            // =========================================================================
            logger::action_running("Scanning selected ports");

            let mut open_ports = Vec::new();

            for &port in PORTS {
                if Self::check_port(host, port).await {
                    open_ports.push(port);
                }
            }

            logger::action_ok();
            logger::info(&format!("Open ports: {:?}", open_ports));

            // =========================================================================
            // TELEMETRY WRITING
            // =========================================================================
            let elapsed = start.elapsed();
            let parent = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unknown>".into());

            let t = NetworkPortScanTelemetry {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),

                local_ipv4: local.to_string(),
                first_alive_host: Some(host.to_string()),

                scanned_ports: PORTS.to_vec(),
                open_ports: open_ports.clone(),

                elapsed_ms: elapsed.as_millis(),
                parent,
            };

            // Write JSONL + human log
            if let Some(dir) = telemetry_dir() {
                use std::fs::{create_dir_all, OpenOptions};
                use std::io::Write;

                if create_dir_all(&dir).is_ok() {
                    // JSONL
                    let mut jsonl = dir.clone();
                    jsonl.push(format!("network_scan_{}.jsonl", cfg.test_id));
                    if let Ok(mut jf) = OpenOptions::new().create(true).append(true).open(&jsonl) {
                        if let Ok(j) = serde_json::to_string(&t) {
                            let _ = writeln!(jf, "{}", j);
                        }
                    }

                    // LOG
                    let mut log = dir.clone();
                    log.push(format!("network_scan_{}.log", cfg.test_id));
                    if let Ok(mut lf) = OpenOptions::new().create(true).append(true).open(&log) {
                        let _ = writeln!(lf, "=============================");
                        let _ = writeln!(lf, "TEST ID       : {}", t.test_id);
                        let _ = writeln!(lf, "TIMESTAMP     : {}", t.timestamp);
                        let _ = writeln!(lf, "LOCAL IPV4    : {}", t.local_ipv4);
                        let _ = writeln!(lf, "ALIVE HOST    : {:?}", t.first_alive_host);
                        let _ = writeln!(lf, "OPEN PORTS    : {:?}", t.open_ports);
                        let _ = writeln!(lf, "ELAPSED (ms)  : {}", t.elapsed_ms);
                        let _ = writeln!(lf, "");
                    }
                }
            }

            // Final action record
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1046 - {}", self.name()),
                status: "written".into(),
                details: format!(
                    "Local IP: {}; Host: {}; Open ports: {:?}",
                    local, host, open_ports
                ),
                artifact_path: None,
            };
            let _ = write_action_record(cfg, &rec);

            logger::action_ok();
            Ok(())
        })
    }
}
