use colored::*;
use std::time::Duration;

/// Small logger helper for Magnet (Neo-Offensive / A2 theme)
///
/// Provides a handful of convenient functions that modules call
/// to print consistent, colorful output.
pub fn init() {
    // If the terminal doesn't support colors, users can override via env.
    // colored crate tries to detect; we don't force anything here.
}

/// Print the app header
pub fn header(version: &str) {
    let crown = "🧲".bright_red();
    let title = format!(" MAGNET — Purple Simulation Framework v{}", version)
        .bold()
        .on_bright_magenta()
        .white();
    let line = "══════════════════════════════════════════════════════════════════════════";
    println!("{}  {}", crown, title);
    println!("{}", line.bright_black());
}

/// Print a section header for a module
pub fn module_start(name: &str) {
    let left = "⟦".bright_cyan();
    let right = "⟧".bright_cyan();
    let nm = format!(" {} ", name).bold().bright_white();
    println!();
    println!("{}{}{}", left, nm, right);
}

/// Print an action in a tidy single line (action -> result)
pub fn action_running(action: &str) {
    let arrow = "  →".bright_black();
    let act = format!(" {}", action).white();
    print!("{}{}", arrow, act);
    // leave cursor — module should print status via action_ok or action_fail
}

/// Print that the action succeeded (completes the prior line)
pub fn action_ok() {
    let ok = " ✅".bright_green().bold();
    println!("   {}", ok);
}

/// Print that the action failed with a message
pub fn action_fail(msg: &str) {
    let fail = " ❌".bright_red().bold();
    println!("   {} {}", fail, msg.bright_red());
}

/// Print an info line (used for details)
pub fn info(msg: &str) {
    println!("   {}", msg.dimmed());
}

/// Print a warning
pub fn warn(msg: &str) {
    let w = "⚠".yellow();
    println!("{} {}", w, msg.yellow());
}

/// Print an error
pub fn error(msg: &str) {
    let e = "✖".red();
    println!("{} {}", e, msg.red().bold());
}

/// Print the final summary footer with elapsed time (Duration)
pub fn summary(elapsed: Duration) {
    let trophy = "🏁".bright_magenta();
    let secs = elapsed.as_secs_f64();
    let footer = format!("Finished — {:.3}s", secs).bold().bright_white();
    println!();
    println!("{} {}", trophy, footer.on_bright_black());
}
