#![cfg(all(target_os = "linux", feature = "hyprland"))]
use crate::core::notifier;
use crate::core::types::WindowInfo;
use crate::platforms::WindowMonitor;
#[cfg(all(target_os = "linux", feature = "hyprland"))]
use hyprland::{
    data::Client,
    event_listener::{EventListener, WindowEventData},
    shared::HyprData,
    shared::HyprDataActiveOptional,
};
use std::error::Error;

pub struct HyprlandMonitor {
    #[cfg(all(target_os = "linux", feature = "hyprland"))]
    event_listener: Option<EventListener>,
    verbose: bool,
}

impl HyprlandMonitor {
    pub fn new(verbose: bool) -> Self {
        Self {
            #[cfg(all(target_os = "linux", feature = "hyprland"))]
            event_listener: None,
            verbose,
        }
    }
}

impl WindowMonitor for HyprlandMonitor {
    fn platform_name(&self) -> &str {
        "Hyprland"
    }

    fn start(&mut self) -> Result<(), Box<dyn Error>> {
        // Check if we're running in Hyprland
        if !is_hyprland_running() {
            return Err("Not running in Hyprland environment".into());
        }

        if self.verbose {
            println!("Starting Hyprland window monitor");
        }

        #[cfg(all(target_os = "linux", feature = "hyprland"))]
        {
            // Create a new event listener
            let mut listener = EventListener::new();
            let verbose = self.verbose;

            // Set up the window change handler
            listener.add_active_window_changed_handler(move |window_event| {
                if let Err(err) = handle_active_window_change(window_event, verbose) {
                    eprintln!("Error handling window change: {}", err);
                }
            });

            // Verify we can connect to Hyprland
            if let Err(e) = hyprland::data::Monitors::get() {
                return Err(format!("Failed to connect to Hyprland: {}", e).into());
            }

            // Start the listener with exponential backoff retry
            let max_retries = 10;
            let mut retry_count = 0;
            let mut delay_ms = 100;

            loop {
                match listener.start_listener() {
                    Ok(_) => {
                        self.event_listener = Some(listener);
                        return Ok(());
                    }
                    Err(e) => {
                        retry_count += 1;
                        if retry_count > max_retries {
                            return Err(format!(
                                "Failed to start event listener after {} retries: {}",
                                max_retries, e
                            )
                            .into());
                        }

                        if self.verbose {
                            println!(
                                "Failed to start event listener (attempt {}/{}), retrying in {}ms: {}", 
                                retry_count, max_retries, delay_ms, e
                            );
                        }

                        // Sleep with exponential backoff
                        std::thread::sleep(std::time::Duration::from_millis(delay_ms));

                        // Exponential backoff with jitter
                        delay_ms = std::cmp::min(delay_ms * 2, 10000); // Cap at 10 seconds
                    }
                }
            }
        }

        #[cfg(not(all(target_os = "linux", feature = "hyprland")))]
        Err("Hyprland support not compiled in this build".into())
    }

    fn stop(&mut self) -> Result<(), Box<dyn Error>> {
        #[cfg(all(target_os = "linux", feature = "hyprland"))]
        {
            self.event_listener = None;
        }
        Ok(())
    }
}

pub fn is_hyprland_running() -> bool {
    std::env::var("HYPRLAND_INSTANCE_SIGNATURE").is_ok()
}

#[cfg(all(target_os = "linux", feature = "hyprland"))]
fn handle_active_window_change(
    _window_event: Option<WindowEventData>,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    match Client::get_active() {
        Ok(Some(active_window)) => {
            let window_info = WindowInfo::new(
                active_window.initial_class.clone(),
                active_window.title.clone(),
            );

            notifier::notify_qmk(&window_info, verbose)?;
        }
        Ok(None) => {
            if verbose {
                println!("No active window found");
            }
        }
        Err(err) => {
            eprintln!("Failed to get active window info: {}", err);
        }
    }

    Ok(())
}
