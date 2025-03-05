#![cfg(target_os = "windows")]
use crate::core::notifier;
use crate::core::types::WindowInfo;
use crate::platforms::WindowMonitor;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::thread;

#[cfg(target_os = "windows")]
use windows::{
    Win32::Foundation::{BOOL, HANDLE, HWND, LPARAM, WPARAM},
    Win32::System::Threading::GetCurrentThreadId,
    Win32::UI::Accessibility::{SetWinEventHook, UnhookWinEvent, WINEVENTPROC},
    Win32::UI::WindowsAndMessaging::{
        DispatchMessageW, GetClassNameW, GetForegroundWindow, GetWindowTextW, PeekMessageW,
        TranslateMessage, EVENT_SYSTEM_FOREGROUND, MSG, PM_REMOVE, WINEVENT_OUTOFCONTEXT,
    },
};

pub struct WindowsMonitor {
    verbose: bool,
    running: Arc<Mutex<bool>>,
    #[cfg(target_os = "windows")]
    hook: Option<HANDLE>,
}

impl WindowsMonitor {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            running: Arc::new(Mutex::new(false)),
            #[cfg(target_os = "windows")]
            hook: None,
        }
    }
}

impl WindowMonitor for WindowsMonitor {
    fn platform_name(&self) -> &str {
        "Windows"
    }

    fn start(&mut self) -> Result<(), Box<dyn Error>> {
        if self.verbose {
            println!("Starting Windows window monitor");
        }

        #[cfg(target_os = "windows")]
        {
            let running = self.running.clone();
            *running.lock().unwrap() = true;
            let verbose = self.verbose;

            // Set up the window event hook
            unsafe {
                // Get the current foreground window initially
                let hwnd = GetForegroundWindow();
                if !hwnd.is_invalid() {
                    if let Ok(window_info) = get_window_info(hwnd) {
                        let _ = notifier::notify_qmk(&window_info, verbose);
                    }
                }

                // Set up the event hook
                let hook = SetWinEventHook(
                    EVENT_SYSTEM_FOREGROUND,
                    EVENT_SYSTEM_FOREGROUND,
                    None,
                    Some(window_event_callback),
                    0,
                    0,
                    WINEVENT_OUTOFCONTEXT,
                );

                if hook.is_invalid() {
                    return Err("Failed to set Windows event hook".into());
                }

                self.hook = Some(hook);

                // Start a message loop to receive window events
                thread::spawn(move || {
                    let mut msg: MSG = MSG::default();

                    while *running.lock().unwrap() {
                        // Process any window messages
                        while unsafe { PeekMessageW(&mut msg, HWND(0), 0, 0, PM_REMOVE).as_bool() }
                        {
                            unsafe {
                                TranslateMessage(&msg);
                                DispatchMessageW(&msg);
                            }
                        }

                        // Sleep a bit to avoid high CPU usage
                        thread::sleep(std::time::Duration::from_millis(100));
                    }
                });
            }

            Ok(())
        }

        #[cfg(not(target_os = "windows"))]
        Err("Windows platform support not compiled in this build".into())
    }

    fn stop(&mut self) -> Result<(), Box<dyn Error>> {
        if let Ok(mut running) = self.running.lock() {
            *running = false;
        }

        #[cfg(target_os = "windows")]
        {
            if let Some(hook) = self.hook {
                unsafe {
                    UnhookWinEvent(hook);
                }
                self.hook = None;
            }
        }

        Ok(())
    }
}

#[cfg(target_os = "windows")]
unsafe extern "system" fn window_event_callback(
    _hook: HANDLE,
    event: u32,
    hwnd: HWND,
    _id_object: i32,
    _id_child: i32,
    _id_thread: u32,
    _event_time: u32,
) {
    if event == EVENT_SYSTEM_FOREGROUND {
        if let Ok(window_info) = get_window_info(hwnd) {
            let verbose = std::env::args().any(|arg| arg == "-v");
            let _ = notifier::notify_qmk(&window_info, verbose);

            if verbose {
                println!(
                    "Window changed: {} - {}",
                    window_info.app_class, window_info.title
                );
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn get_window_info(hwnd: HWND) -> Result<WindowInfo, Box<dyn Error>> {
    unsafe {
        // Get window class name
        let mut class_name = [0u16; 256];
        let class_len = GetClassNameW(hwnd, &mut class_name);
        let class = if class_len > 0 {
            String::from_utf16_lossy(&class_name[0..class_len as usize])
        } else {
            "Unknown".to_string()
        };

        // Get window title
        let mut title_text = [0u16; 512];
        let title_len = GetWindowTextW(hwnd, &mut title_text);
        let title = if title_len > 0 {
            String::from_utf16_lossy(&title_text[0..title_len as usize])
        } else {
            "Unknown".to_string()
        };

        Ok(WindowInfo::new(class, title))
    }
}
