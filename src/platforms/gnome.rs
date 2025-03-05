// use crate::core::notifier;
// use crate::core::types::WindowInfo;
// use crate::platforms::WindowMonitor;
// use std::error::Error;
// use std::sync::{Arc, Mutex};
// use std::thread;
// use std::time::Duration;
// use std::process::Command;

// pub struct GnomeMonitor {
//     verbose: bool,
//     running: Arc<Mutex<bool>>,
// }

// impl GnomeMonitor {
//     pub fn new(verbose: bool) -> Self {
//         Self {
//             verbose,
//             running: Arc::new(Mutex::new(false)),
//         }
//     }
// }

// impl WindowMonitor for GnomeMonitor {
//     fn platform_name(&self) -> &str {
//         "GNOME"
//     }

//     fn start(&mut self) -> Result<(), Box<dyn Error>> {
//         if !is_gnome_running() {
//             return Err("Not running in GNOME environment".into());
//         }

//         if self.verbose {
//             println!("Starting GNOME window monitor");
//         }

//         #[cfg(all(target_os = "linux", feature = "gnome"))]
//         {
//             let running = self.running.clone();
//             *running.lock().unwrap() = true;
//             let verbose = self.verbose;

//             // Start a thread to poll for window changes
//             thread::spawn(move || {
//                 let mut last_title = String::new();
//                 let mut last_class = String::new();

//                 while *running.lock().unwrap() {
//                     // Using gdbus command as a simpler alternative to async zbus
//                     if let Ok(info) = get_active_window_info() {
//                         // Only notify if the window info has changed
//                         if info.app_class != last_class || info.title != last_title {
//                             if verbose {
//                                 println!("Window changed: {} - {}", info.app_class, info.title);
//                             }

//                             last_class = info.app_class.clone();
//                             last_title = info.title.clone();

//                             if let Err(e) = notifier::notify_qmk(&info, verbose) {
//                                 eprintln!("Failed to notify QMK: {}", e);
//                             }
//                         }
//                     }

//                     // Sleep to avoid high CPU usage
//                     thread::sleep(Duration::from_millis(300));
//                 }
//             });

//             Ok(())
//         }

//         #[cfg(not(all(target_os = "linux", feature = "gnome")))]
//         Err("GNOME platform support not compiled in this build".into())
//     }

//     fn stop(&mut self) -> Result<(), Box<dyn Error>> {
//         if let Ok(mut running) = self.running.lock() {
//             *running = false;
//         }
//         Ok(())
//     }
// }

// pub fn is_gnome_running() -> bool {
//     std::env::var("GNOME_DESKTOP_SESSION_ID").is_ok()
//         || std::env::var("DESKTOP_SESSION")
//             .map(|s| s.contains("gnome"))
//             .unwrap_or(false)
// }

// #[cfg(all(target_os = "linux", feature = "gnome"))]
// fn get_active_window_info() -> Result<WindowInfo, Box<dyn Error>> {
//     // Using gdbus to query active window info
//     let output = Command::new("gdbus")
//         .args(&[
//             "call", 
//             "--session", 
//             "--dest", "org.gnome.Shell", 
//             "--object-path", "/org/gnome/Shell", 
//             "--method", "org.gnome.Shell.Eval",
//             "let activeWindow = global.display.focus_window; \
//              let app = activeWindow ? activeWindow.get_wm_class_instance() || 'Unknown' : 'None'; \
//              let title = activeWindow ? activeWindow.title || 'Unknown' : 'None'; \
//              JSON.stringify({app: app, title: title});"
//         ])
//         .output()?;
    
//     let stdout = String::from_utf8(output.stdout)?;
    
//     // Parse the gdbus output
//     // Format is typically "(true, 'JSON_STRING')"
//     if let Some(json_str) = stdout.split("'").nth(1) {
//         let parsed: serde_json::Value = serde_json::from_str(json_str)?;
        
//         let app_class = parsed["app"].as_str().unwrap_or("Unknown").to_string();
//         let title = parsed["title"].as_str().unwrap_or("Unknown").to_string();
        
//         Ok(WindowInfo::new(app_class, title))
//     } else {
//         Ok(WindowInfo::new("Unknown".to_string(), "Unknown".to_string()))
//     }
// }

