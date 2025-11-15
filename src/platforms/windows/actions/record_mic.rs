//! Records 10 seconds of audio from the system microphone and writes recorded.wav
//! in the telemetry directory as a benign test artifact (T1123). 

use anyhow::{Context, Result};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use chrono::Utc;

use crate::core::config::Config;
use crate::core::simulation::Simulation;
use crate::core::telemetry::{ActionRecord, write_action_record};
use crate::core::logger;

use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::sync::mpsc::sync_channel;

use hound;

/// Name of the produced WAV file.
const OUT_FILENAME: &str = "recorded.wav";

/// Path: %USERPROFILE%\Documents\MagnetTelemetry\recorded.wav
fn output_path() -> Option<PathBuf> {
    crate::core::telemetry::telemetry_dir().map(|mut p| {
        p.push(OUT_FILENAME);
        p
    })
}

/// Simulation wrapper for microphone recording.
#[derive(Default)]
pub struct RecordMicSim;

impl RecordMicSim {
    /// Performs the actual recording.
    fn record_wav(out: &PathBuf) -> Result<()> {
        let host = cpal::default_host();

        let device = host
            .default_input_device()
            .ok_or_else(|| anyhow::anyhow!("no input device available"))?;

        let default_cfg = device.default_input_config()
            .context("could not retrieve default audio input config")?;

        let config = cpal::StreamConfig {
            channels: default_cfg.channels(),
            sample_rate: default_cfg.sample_rate(),
            buffer_size: cpal::BufferSize::Default,
        };

        let (tx, rx) = sync_channel::<i16>(4096);

        let spec = hound::WavSpec {
            channels: config.channels as u16,
            sample_rate: config.sample_rate.0,
            bits_per_sample: 16,
            sample_format: hound::SampleFormat::Int,
        };

        let mut writer = hound::WavWriter::create(out, spec)
            .with_context(|| format!("creating WAV writer at {}", out.display()))?;

        let stream = match default_cfg.sample_format() {
            cpal::SampleFormat::I16 => device.build_input_stream(
                &config,
                move |data: &[i16], _| {
                    for &s in data {
                        let _ = tx.send(s);
                    }
                },
                |e| eprintln!("mic error: {e}"),
                None,
            )?,
            cpal::SampleFormat::U16 => device.build_input_stream(
                &config,
                move |data: &[u16], _| {
                    for &s in data {
                        let _ = tx.send((s as i32 - 32768) as i16);
                    }
                },
                |e| eprintln!("mic error: {e}"),
                None,
            )?,
            cpal::SampleFormat::F32 => device.build_input_stream(
                &config,
                move |data: &[f32], _| {
                    for &s in data {
                        let _ = tx.send((s * i16::MAX as f32) as i16);
                    }
                },
                |e| eprintln!("mic error: {e}"),
                None,
            )?,
            _ => return Err(anyhow::anyhow!("unsupported audio sample format")),
        };

        stream.play()?;
        logger::info("Recording 10 seconds of microphone audio...");

        let end = Instant::now() + Duration::from_secs(10);
        while Instant::now() < end {
            if let Ok(sample) = rx.recv_timeout(Duration::from_millis(100)) {
                writer.write_sample(sample)?;
            }
        }

        writer.finalize()?;

        logger::info("Audio recording complete.");
        Ok(())
    }
}

impl Simulation for RecordMicSim {
    fn name(&self) -> &'static str {
        "windows::record_mic"
    }

    fn run(&self, cfg: &Config) -> Result<()> {
        let start = Instant::now();

        logger::action_running("Recording microphone input (10 seconds)");

        let out = output_path()
            .ok_or_else(|| anyhow::anyhow!("could not resolve telemetry directory"))?;

        if cfg.dry_run {
            logger::info("dry-run: would record microphone audio");
            let rec = ActionRecord {
                test_id: cfg.test_id.clone(),
                timestamp: Utc::now().to_rfc3339(),
                action: format!("T1123 - {}", self.name()),
                status: "dry-run".into(),
                details: "dry-run: microphone not accessed".into(),
                artifact_path: Some(out.display().to_string()),
            };
            let _ = write_action_record(cfg, &rec);
            logger::action_ok();
            return Ok(());
        }

        match Self::record_wav(&out) {
            Ok(()) => {
                let elapsed = start.elapsed();

                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1123 - {}", self.name()),
                    status: "written".into(),
                    details: format!(
                        "Recorded microphone audio to {} in {} ms",
                        out.display(),
                        elapsed.as_millis()
                    ),
                    artifact_path: Some(out.display().to_string()),
                };
                let _ = write_action_record(cfg, &rec);

                logger::action_ok();
                Ok(())
            }
            Err(e) => {
                logger::action_fail("microphone recording failed");

                let rec = ActionRecord {
                    test_id: cfg.test_id.clone(),
                    timestamp: Utc::now().to_rfc3339(),
                    action: format!("T1123 - {}", self.name()),
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
