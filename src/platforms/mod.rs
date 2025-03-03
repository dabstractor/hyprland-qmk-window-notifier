mod hyprland;
mod macos;

use std::error::Error;

pub trait WindowMonitor {
    fn platform_name(&self) -> &str;
    fn start(&mut self) -> Result<(), Box<dyn Error>>;
    #[allow(dead_code)]
    fn stop(&mut self) -> Result<(), Box<dyn Error>>;
}

pub fn create_monitor(verbose: bool) -> Result<Box<dyn WindowMonitor>, Box<dyn Error>> {
    // Use a let-else pattern to avoid multiple returns with early detection
    #[cfg(target_os = "macos")]
    {
        return Ok(Box::new(macos::MacOSMonitor::new(verbose)));
    }

    #[cfg(all(target_os = "linux", feature = "hyprland"))]
    {
        // For Linux, we need to detect the specific desktop environment
        if hyprland::is_hyprland_running() {
            return Ok(Box::new(hyprland::HyprlandMonitor::new(verbose)));
        } else {
            return Err("Hyprland is not running".into());
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // If we can't detect a supported platform
        Err("Unsupported platform or desktop environment".into())
    }
}
