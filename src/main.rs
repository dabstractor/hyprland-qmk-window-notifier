mod core;
mod platforms;

use std::error::Error;
use std::process;

fn main() {
    if let Err(e) = run() {
        eprintln!("Application error: {}", e);
        process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let verbose = std::env::args().any(|arg| arg == "-v");
    // Create the appropriate monitor for the current platform
    let mut monitor = platforms::create_monitor(verbose)?;
    println!("QMK Window Notifier started");
    if verbose {
        println!("Verbose logging enabled");
        println!("Using platform: {}", monitor.platform_name());
    }

    // Set up signal handling for immediate exit
    ctrlc::set_handler(move || {
        println!("\nReceived Ctrl+C, shutting down...");
        // Force immediate exit - no waiting or additional complexity
        process::exit(0);
    })?;

    // Start the monitor in the current thread
    if let Err(e) = monitor.start() {
        eprintln!("Monitor error: {}", e);
    }

    // If we reach here, the monitor stopped on its own
    println!("Monitor stopped, exiting.");

    // Clean exit
    Ok(())
}
