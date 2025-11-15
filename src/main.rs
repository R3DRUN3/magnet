//! magnet - entrypoint
//! IMPORTANT: run only on systems you are authorized to test.

mod core;
mod platforms;

use anyhow::Result;
use clap::{Parser, Subcommand, CommandFactory};
use colored::Colorize;
use core::config::Config;
use core::logger;
use core::runner::Runner;
use std::time::Instant;

/// CLI definition using clap (OS-namespaced subcommands)
#[derive(Debug, Parser)]
#[command(name = "magnet")]
#[command(about = "Magnet — cross-platform purple-team simulation toolkit", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// List available modules (optionally filter by OS)
    List {
        /// OS namespace to filter by (e.g. windows, linux)
        #[arg(long, short)]
        os: Option<String>,
    },

    /// Run modules. Usage: `magnet run windows all` or `magnet run windows ransom_note discovery_sim`
    Run {
        /// OS namespace to run under (e.g. windows)
        os: String,

        /// Modules to run (module short name like `ransom_note` or full `windows::ransom_note`). Use `all` to run every module under the OS.
        modules: Vec<String>,
    },
}

fn main() -> Result<()> {
    // init logger & header
    logger::init();
    logger::header(env!("CARGO_PKG_VERSION"));

    // parse CLI
    let cli = Cli::parse();
    // If no command provided, print help and exit (don't run anything)
    if cli.command.is_none() {
        println!();
        Cli::command().print_help().ok();
        println!();
        return Ok(());
    }


    // start timer (we still measure overall execution when running)
    let start_time = Instant::now();

    // load config
    let config = Config::load().unwrap_or_default();

    // show common paths (Windows only)
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

    // build runner and register modules
    let mut runner = Runner::new(config);

   #[cfg(target_os = "windows")]
    {
        use platforms::windows::actions::{
            ps_defender_exclusions::PsDefenderExclusions,
            install_python::InstallPythonSimulation,
            pwd_guessing::PwdGuessingSim,
            discovery_sim::DiscoverySim,
            ps_elev_whoami::PsElevWhoami,
            wifi_creds::WifiCreds,
            browser_pwd::BrowserPwdSimulation,
            screenshot_sim::ScreenshotSimulation,
            ransomware_sim::RansomSimulation,
            minidump_proc::MinidumpProc,
            http_traffic_sim::HttpTrafficSimulation,
            open_many_windows::OpenManyWindowsSimulation,
            network_port_scan::NetworkPortScanSimulation,
            share_enum::ShareEnumSimulation,
            high_cpu_miner_sim::HighCpuMinerSimulation,
            startup_exec::StartupExecSim,
            scheduled_task_sim::ScheduledTaskSim,
            registry_persistence::RegistryPersistenceSim,
            add_admin_user::AdminUserAddSimulation,
            enable_ssh::EnableSshSimulation,
            enable_winrm::EnableWinRMSimulation,
            enable_rdp::EnableRdpSimulation,
            keylogger_sim::KeyloggerSim,
            record_mic::RecordMicSim,
            create_proc::CreateProcSim,
            proc_inj::ProcInjSim,

        };

        register_windows_actions!(
            runner,
            PsDefenderExclusions,
            InstallPythonSimulation,
            PwdGuessingSim,
            DiscoverySim,
            PsElevWhoami,
            WifiCreds,
            BrowserPwdSimulation,
            ScreenshotSimulation,
            RansomSimulation,
            MinidumpProc,
            HttpTrafficSimulation,
            OpenManyWindowsSimulation,
            NetworkPortScanSimulation,
            ShareEnumSimulation,
            HighCpuMinerSimulation,
            StartupExecSim,
            ScheduledTaskSim,
            RegistryPersistenceSim,
            AdminUserAddSimulation,
            EnableSshSimulation,
            EnableWinRMSimulation,
            EnableRdpSimulation,
            KeyloggerSim,
            RecordMicSim,
            CreateProcSim,
            ProcInjSim,   
        );
    }


    // Helper: collect modules grouped by OS
    let modules_by_os = collect_modules_by_os(&runner);

    // Decide command:
    match cli.command {
        Some(Commands::List { os }) => {
            if let Some(os) = os {
                list_modules_for_os(&modules_by_os, &os);
            } else {
                list_all_modules(&modules_by_os);
            }
        }

        Some(Commands::Run { os, modules }) => {
            // If user passed no modules, treat as 'all'
            let requested = if modules.is_empty() {
                vec!["all".to_string()]
            } else {
                modules
            };
            run_selected(&mut runner, &modules_by_os, &os, &requested)?;
        }

        None => {
            // default behavior: run all modules for current OS (Windows)
            #[cfg(target_os = "windows")]
            {
                println!();
                println!("{}", "▶ Running simulations...".bright_green().bold());
                run_selected(
                    &mut runner,
                    &modules_by_os,
                    "windows",
                    &vec!["all".to_string()],
                )?;
            }

            #[cfg(not(target_os = "windows"))]
            {
                println!("No command provided. Use `magnet --help` to see usage.");
            }
        }
    }

    // summary
    let elapsed = start_time.elapsed();
    logger::summary(elapsed);

    Ok(())
}

/// Build a map of OS -> Vec<module_full_name>
fn collect_modules_by_os(runner: &Runner) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut map: std::collections::BTreeMap<String, Vec<String>> = Default::default();

    for sim in &runner.simulations {
        let full = sim.name().to_string(); // e.g. "windows::ransom_note"
        let parts: Vec<&str> = full.split("::").collect();
        let os = parts.get(0).map(|s| s.to_string()).unwrap_or_else(|| "unknown".into());

        map.entry(os).or_default().push(full);
    }

    map
}

/// Print all modules grouped by OS
fn list_all_modules(map: &std::collections::BTreeMap<String, Vec<String>>) {
    println!();
    println!("{}", "Available modules:".bright_cyan().bold());
    for (os, mods) in map {
        println!("  {}:", os.bright_magenta());
        for m in mods {
            // print short name and full name
            let short = m.split("::").last().unwrap_or(m);
            println!("    - {} ({})", short.bright_white(), m.dimmed());
        }
    }
}

/// Print modules for a single OS
fn list_modules_for_os(map: &std::collections::BTreeMap<String, Vec<String>>, os: &str) {
    println!();
    match map.get(&os.to_string()) {
        Some(mods) => {
            println!("Modules for {}:", os.bright_magenta());
            for m in mods {
                let short = m.split("::").last().unwrap_or(m);
                println!("  - {} ({})", short.bright_white(), m.dimmed());
            }
        }
        None => {
            println!("{}", format!("No modules found for OS '{}'", os).bright_yellow());
        }
    }
}

/// Run selected modules for the given OS. requested may contain short names, full names, or "all".
fn run_selected(
    runner: &mut Runner,
    modules_by_os: &std::collections::BTreeMap<String, Vec<String>>,
    os: &str,
    requested: &Vec<String>,
) -> Result<()> {
    let os_key = os.to_string();

    let available = match modules_by_os.get(&os_key) {
        Some(v) => v.clone(),
        None => {
            println!("{}", format!("No modules available for OS '{}'", os).bright_red());
            return Ok(());
        }
    };

    // determine which modules were requested
    let mut to_run: Vec<String> = Vec::new();
    if requested.iter().any(|r| r.eq_ignore_ascii_case("all")) {
        to_run = available.clone();
    } else {
        for r in requested {
            // match full name or short name
            let matches: Vec<String> = available
                .iter()
                .filter(|m| {
                    m.eq_ignore_ascii_case(r)
                        || m.split("::").last().map(|s| s.eq_ignore_ascii_case(r)).unwrap_or(false)
                })
                .cloned()
                .collect();

            if matches.is_empty() {
                println!(
                    "{} {}",
                    "⚠".bright_yellow(),
                    format!("Module '{}' not found under {}", r, os).bright_yellow()
                );
            } else {
                to_run.extend(matches);
            }
        }
    }

    if to_run.is_empty() {
        println!("{}", "No modules to run.".bright_yellow());
        return Ok(());
    }

    // Print selected modules
    println!();
    println!(
        "{} {}",
        "▶ Selected modules:".bright_green().bold(),
        to_run.join(", ").dimmed()
    );

    // Execute each selected module in order (use logger's module_start for headers)
    for module_full in to_run {
        logger::module_start(&module_full);

        // find the simulation instance by full name and execute it
        let found = runner
            .simulations
            .iter()
            .find(|s| s.name().eq_ignore_ascii_case(&module_full));

        if let Some(sim) = found {
            // run simulation; runner.config is Arc<Config>, so deref to &Config
            if let Err(e) = sim.run(&*runner.config) {
                logger::error(&format!("module '{}' failed: {}", module_full, e));
            }
        } else {
            // fallback — shouldn't happen because we built 'available' earlier
            logger::warn(&format!("simulation implementation for '{}' not found", module_full));
        }
    }

    Ok(())
}
