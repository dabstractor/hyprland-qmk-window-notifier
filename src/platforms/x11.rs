#[cfg(all(target_os = "linux", feature = "x11"))]
use crate::core::notifier;
#[cfg(all(target_os = "linux", feature = "x11"))]
use crate::core::types::WindowInfo;
#[cfg(all(target_os = "linux", feature = "x11"))]
use crate::platforms::WindowMonitor;
#[cfg(all(target_os = "linux", feature = "x11"))]
use std::error::Error;
#[cfg(all(target_os = "linux", feature = "x11"))]
use std::sync::{Arc, Mutex};
#[cfg(all(target_os = "linux", feature = "x11"))]
use std::thread;
#[cfg(all(target_os = "linux", feature = "x11"))]
use std::time::Duration;
#[cfg(all(target_os = "linux", feature = "x11"))]
use x11rb::protocol::Event;
#[cfg(all(target_os = "linux", feature = "x11"))]
use x11rb::connection::Connection;
#[cfg(all(target_os = "linux", feature = "x11"))]
use x11rb::protocol::xproto::*;
#[cfg(all(target_os = "linux", feature = "x11"))]
use x11rb::rust_connection::RustConnection;

#[cfg(all(target_os = "linux", feature = "x11"))]
pub struct X11Monitor {
    verbose: bool,
    running: Arc<Mutex<bool>>,
}

#[cfg(all(target_os = "linux", feature = "x11"))]
impl X11Monitor {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            running: Arc::new(Mutex::new(false)),
        }
    }
}

#[cfg(all(target_os = "linux", feature = "x11"))]
impl WindowMonitor for X11Monitor {
    fn platform_name(&self) -> &str {
        "X11"
    }

    fn start(&mut self) -> Result<(), Box<dyn Error>> {
        if self.verbose {
            println!("Starting X11 window monitor");
        }

        let running = self.running.clone();
        *running.lock().unwrap() = true;
        let verbose = self.verbose;

        thread::spawn(move || {
            // Connect to the X server
            if let Ok((conn, _)) = RustConnection::connect(None) {
                let root = conn.setup().roots[0].root;

                // Get the _NET_ACTIVE_WINDOW atom
                let active_window_atom = match conn.intern_atom(false, b"_NET_ACTIVE_WINDOW") {
                    Ok(cookie) => match cookie.reply() {
                        Ok(reply) => reply.atom,
                        Err(_) => 0
                    },
                    Err(_) => 0
                };

                // Subscribe to property change events on the root window
                let values = ChangeWindowAttributesAux::new().event_mask(EventMask::PROPERTY_CHANGE);
                let _ = conn.change_window_attributes(root, &values);
                let _ = conn.flush();

                let mut last_active_window = 0;

                while *running.lock().unwrap() {
                    // Check for active window changes
                    match get_active_window(&conn, root, active_window_atom) {
                        Ok(active_window) => {
                            if active_window != 0 && active_window != last_active_window {
                                last_active_window = active_window;
                                
                                if verbose {
                                    println!("Active window changed to: {}", active_window);
                                }
                                
                                // Get window information and notify QMK
                                if let Ok(window_info) = get_window_info(&conn, active_window) {
                                    if let Err(e) = notifier::notify_qmk(&window_info, verbose) {
                                        eprintln!("Failed to notify QMK: {}", e);
                                    }
                                }
                            }
                        },
                        Err(e) => {
                            if verbose {
                                eprintln!("Error getting active window: {}", e);
                            }
                        }
                    }
                    
                    // Process X events
                    while let Ok(Some(event)) = conn.poll_for_event() {
                        match event {
                            Event::PropertyNotify(event) => {
                                if event.window == root && event.atom == active_window_atom {
                                    // Active window changed
                                    if let Ok(active_window) = get_active_window(&conn, root, active_window_atom) {
                                        if active_window != 0 && active_window != last_active_window {
                                            last_active_window = active_window;
                                            
                                            if verbose {
                                                println!("Active window changed to: {}", active_window);
                                            }
                                            
                                            // Get window information and notify QMK
                                            if let Ok(window_info) = get_window_info(&conn, active_window) {
                                                if let Err(e) = notifier::notify_qmk(&window_info, verbose) {
                                                    eprintln!("Failed to notify QMK: {}", e);
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            _ => {}
                        }
                    }
                    
                    // Sleep a bit to avoid high CPU usage
                    thread::sleep(Duration::from_millis(100));
                }
            } else if verbose {
                eprintln!("Failed to connect to X server");
            }
        });

        Ok(())
    }

    fn stop(&mut self) -> Result<(), Box<dyn Error>> {
        if let Ok(mut running) = self.running.lock() {
            *running = false;
        }
        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "x11"))]
fn get_active_window(
    conn: &RustConnection,
    root: Window,
    active_window_atom: u32,
) -> Result<Window, Box<dyn Error>> {
    let prop = conn.get_property(false, root, active_window_atom, AtomEnum::WINDOW, 0, 1)?;
    let prop_reply = prop.reply()?;
    
    if prop_reply.value_len > 0 {
        // Correctly extract the window ID from the property value
        let window_bytes = prop_reply.value;
        if window_bytes.len() >= 4 {
            let window = u32::from_ne_bytes([
                window_bytes[0], 
                window_bytes[1], 
                window_bytes[2], 
                window_bytes[3]
            ]);
            Ok(window)
        } else {
            Ok(0)
        }
    } else {
        Ok(0)
    }
}

#[cfg(all(target_os = "linux", feature = "x11"))]
fn get_window_info(conn: &RustConnection, window: Window) -> Result<WindowInfo, Box<dyn Error>> {
    // Get window class
    let class_atom = match conn.intern_atom(false, b"WM_CLASS") {
        Ok(cookie) => match cookie.reply() {
            Ok(reply) => reply.atom,
            Err(_) => 0
        },
        Err(_) => 0
    };
    
    let class_prop = conn.get_property(
        false,
        window,
        class_atom,
        AtomEnum::STRING,
        0,
        1024
    )?;
    
    let class_reply = class_prop.reply()?;
    let class_bytes = class_reply.value;
    
    // Parse the class - it's a sequence of null-terminated strings
    let mut class_parts: Vec<String> = class_bytes.split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    
    let class = if !class_parts.is_empty() { class_parts.remove(0) } else { "Unknown".to_string() };
    
    // Get window title
    let name_atom = match conn.intern_atom(false, b"_NET_WM_NAME") {
        Ok(cookie) => match cookie.reply() {
            Ok(reply) => reply.atom,
            Err(_) => 0
        },
        Err(_) => 0
    };
    
    let title = if name_atom != 0 {
        let title_prop = conn.get_property(
            false,
            window,
            name_atom,
            AtomEnum::ANY,
            0,
            1024
        )?;
        
        let title_reply = title_prop.reply()?;
        String::from_utf8_lossy(&title_reply.value).into_owned()
    } else {
        // Fallback to WM_NAME
        let title_prop = conn.get_property(
            false,
            window,
            AtomEnum::WM_NAME,
            AtomEnum::STRING,
            0,
            1024
        )?;
        
        let title_reply = title_prop.reply()?;
        String::from_utf8_lossy(&title_reply.value).into_owned()
    };
    
    Ok(WindowInfo::new(class, title))
}

