//! magnet - entrypoint
//! IMPORTANT: run only on systems you are authorized to test.

mod core;
mod platforms;
use anyhow::Result;
use core::config::Config;
use core::runner::Runner;
use core::logger;
use colored::Colorize;
use std::time::Instant;

fn main() -> Result<()> {
    // Initialize logger & print header
    logger::init();
    logger::header(env!("CARGO_PKG_VERSION")); // ✅ pretty header

    // Start timer
    let start_time = Instant::now();

    // Load config (defaults if missing)
    let config = Config::load().unwrap_or_default();

    // Show important output paths
    #[cfg(target_os = "windows")]
    {
        if let Some(path) = dirs::desktop_dir() {
            println!("{} {}", "📁 Desktop:".bright_cyan(), path.display());
        }

        if let Some(mut telemetry) = dirs::home_dir() {
            telemetry.push("Documents");
            telemetry.push("MagnetTelemetry");
            println!("{} {}", "🧪 Telemetry:".bright_cyan(), telemetry.display());
        }
    }

    // Create runner
    let mut runner = Runner::new(config);

    // Register Windows modules
    #[cfg(target_os = "windows")]
    {
        use platforms::windows::actions::ransom_note::RansomNote;
        use platforms::windows::actions::discovery_sim::DiscoverySim;

        runner.register(Box::new(RansomNote::default()));
        runner.register(Box::new(DiscoverySim::default()));
    }

    println!();
    println!("{}", "▶ Running simulations...".bright_green().bold());

    // Run
    runner.run_all()?; // (Old plain prints inside Runner remain for now)

    // End
    let elapsed = start_time.elapsed();
    logger::summary(elapsed); // ✅ fancy summary footer

    Ok(())
}
