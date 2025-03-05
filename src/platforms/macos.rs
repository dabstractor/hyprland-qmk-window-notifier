#![allow(unexpected_cfgs)]
#![cfg(target_os = "macos")]
use crate::core::notifier;
use crate::core::types::WindowInfo;
use crate::platforms::WindowMonitor;
use std::error::Error;
use std::ffi::c_void;

#[cfg(target_os = "macos")]
use core_foundation::{
    array::CFArray,
    base::CFRange,
    base::{CFRelease, TCFType},
    dictionary::{CFDictionary, CFDictionaryRef},
    runloop::{CFRunLoop, CFRunLoopRun},
    string::CFString,
};

#[cfg(target_os = "macos")]
use core_graphics::window::{kCGWindowListOptionOnScreenOnly, CGWindowListCopyWindowInfo};

#[cfg(target_os = "macos")]
use objc::{class, msg_send, runtime::Object, sel, sel_impl};

#[cfg(target_os = "macos")]
use dispatch::Queue;

// Existing extern block for various symbols
#[cfg(target_os = "macos")]
extern "C" {
    static NSWorkspaceDidActivateApplicationNotification: *const Object;
    static kCGWindowOwnerName: *const c_void;
    static kCGWindowName: *const c_void;
    // static kCGWindowNumber: *const c_void;

    // MacOS Block_copy function
    fn _Block_copy(block: *const c_void) -> *mut c_void;
}

// New extern block for screen recording permissions:
#[cfg(target_os = "macos")]
extern "C" {
    /// Returns true if the app already has screen recording permission (or if running on an older OS).
    fn CGPreflightScreenCaptureAccess() -> bool;
    /// Requests screen recording permission by displaying the system modal prompt.
    /// Note that this function returns immediately (it does not wait for the user's response).
    fn CGRequestScreenCaptureAccess() -> bool;
}

// Define nil as a null pointer
#[cfg(target_os = "macos")]
const NIL: *mut Object = std::ptr::null_mut();

// Global verbose setting that can be accessed by callback
#[cfg(target_os = "macos")]
static mut VERBOSE: bool = false;

#[cfg(target_os = "macos")]
#[cfg(feature = "modern_macos")]
extern "C" {
    static NSWorkspaceAuthorizationTypeScreenCapture: *const Object;
}

pub struct MacOSMonitor {
    verbose: bool,
    running: bool,
}

impl MacOSMonitor {
    pub fn new(verbose: bool) -> Self {
        Self {
            verbose,
            running: false,
        }
    }

    /// Call this function to check and request screen recording permission.
    #[cfg(target_os = "macos")]
    fn request_screen_recording_permission() -> bool {
        unsafe {
            if CGPreflightScreenCaptureAccess() {
                println!("Screen recording permission already granted.");
                return true;
            }

            println!("Screen recording permission not yet granted. Requesting...");
            CGRequestScreenCaptureAccess();
            println!(
                "Please grant permission in the System Settings dialog and restart the terminal."
            );
            false
        }
    }

    #[cfg(target_os = "macos")]
    unsafe fn setup_observers(&mut self) -> Result<(), Box<dyn Error>> {
        // Set global verbose flag for callbacks
        unsafe {
            VERBOSE = self.verbose;
        }
        let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
        let notification_center: *mut Object = msg_send![workspace, notificationCenter];

        // Remove unused sel and observer variables since they're not being used
        // let sel = sel!(observeNotification:);
        // let observer: *mut Object = msg_send![class!(NSObject), new];

        // Remove unused handle_notification function since we're using notification_handler
        // extern "C" fn handle_notification(
        //     _this: *mut Object,
        //     _cmd: objc::runtime::Sel,
        //     _: *mut Object,
        // ) {
        //     // Get the verbose flag
        //     let verbose = unsafe { VERBOSE };

        //     // Handle the window information
        //     if let Ok(Some(window_info)) = get_active_window_info() {
        //         let _ = notifier::notify_qmk(&window_info, verbose);
        //     }
        // }

        // Register the method with the Objective-C runtime
        let _: bool = unsafe {
            use objc::declare::ClassDecl;
            use objc::runtime::{Class, Object, Sel};

            // Create a custom class for our observer
            let superclass = Class::get("NSObject").unwrap();
            let mut decl = ClassDecl::new("RustNotificationObserver", superclass).unwrap();

            // Add the notification handler method
            extern "C" fn notification_handler(_: &Object, _: Sel, _: *mut Object) {
                let verbose = unsafe { VERBOSE };

                if let Ok(Some(window_info)) = get_active_window_info() {
                    let _ = notifier::notify_qmk(&window_info, verbose);
                }
            }

            decl.add_method(
                sel!(observeNotification:),
                notification_handler as extern "C" fn(&Object, Sel, *mut Object),
            );

            // Register the class
            let _cls = decl.register();

            // Create an instance of our custom class
            let observer: *mut Object =
                msg_send![Class::get("RustNotificationObserver").unwrap(), new];

            // Add the observer to the notification center
            let _: () = msg_send![notification_center,
                                addObserver:observer
                                selector:sel!(observeNotification:)
                                name:NSWorkspaceDidActivateApplicationNotification
                                object:NIL];

            // Don't release the observer, we need it to stay alive
            let _ = observer;

            true
        };

        self.running = true;

        // Fix the unused Result warning
        if let Ok(info) = get_active_window_info() {
            if let Some(window_info) = info {
                if let Err(e) = notifier::notify_qmk(&window_info, self.verbose) {
                    eprintln!("Failed to notify QMK: {}", e);
                }
            }
        }

        // Set up the run loop
        let main_queue = Queue::main();

        // Use a proper Rust closure for exec_async
        main_queue.exec_async(|| {
            println!("Main queue async block running");
            // This is a simple empty closure just to start the main queue
            // The actual work will be handled by the notification observer
        });

        Ok(())
    }
}

impl WindowMonitor for MacOSMonitor {
    fn platform_name(&self) -> &str {
        "macOS"
    }

    fn start(&mut self) -> Result<(), Box<dyn Error>> {
        if self.verbose {
            println!("Starting macOS window monitor");
        }

        #[cfg(target_os = "macos")]
        {
            unsafe {
                // First, check and request screen recording permission.
                if !MacOSMonitor::request_screen_recording_permission() {
                    return Err("Screen recording permission not granted.".into());
                }

                self.setup_observers()?;

                // Capture the initial active application
                let _ = get_active_window_info().map(|info| {
                    if let Some(window_info) = info {
                        if let Err(e) = notifier::notify_qmk(&window_info, self.verbose) {
                            eprintln!("Failed to notify QMK: {}", e);
                        }
                    }
                });

                // Run the event loop
                CFRunLoopRun();
            }

            Ok(())
        }

        #[cfg(not(target_os = "macos"))]
        Err("macOS platform support not compiled in this build".into())
    }

    fn stop(&mut self) -> Result<(), Box<dyn Error>> {
        #[cfg(target_os = "macos")]
        {
            self.running = false;
            CFRunLoop::get_current().stop();
        }

        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn get_active_window_info() -> Result<Option<WindowInfo>, Box<dyn Error>> {
    unsafe {
        let workspace: *mut Object = msg_send![class!(NSWorkspace), sharedWorkspace];
        let app: *mut Object = msg_send![workspace, frontmostApplication];

        if app.is_null() {
            return Ok(None);
        }

        let app_name: *mut Object = msg_send![app, localizedName];
        let app_name_str = nsstring_to_string(app_name);

        // Get window title from the frontmost window
        let window_list = CGWindowListCopyWindowInfo(kCGWindowListOptionOnScreenOnly, 0);
        let window_array: CFArray<CFDictionary> =
            CFArray::wrap_under_get_rule(window_list as *const _);
        let count = window_array.len();

        let mut window_title = String::from("");

        for i in 0..count {
            let range = CFRange {
                location: i as isize,
                length: 1,
            };
            let info = window_array.get_values(range)[0] as CFDictionaryRef;

            // Use a raw dictionary without type parameters
            let _: CFDictionary<*const c_void, *const c_void> =
                CFDictionary::wrap_under_get_rule(info);

            // Get the owner name
            let owner_name_ref = core_foundation::dictionary::CFDictionaryGetValue(
                info as CFDictionaryRef,
                kCGWindowOwnerName as *const _,
            );

            if owner_name_ref.is_null() {
                continue;
            }

            // Convert the value to a CFString
            let owner_name = CFString::wrap_under_get_rule(owner_name_ref as *const _);
            let owner_name_str = cfstring_to_string(&owner_name);

            if owner_name_str == app_name_str {
                // Get the window name
                let window_name_ref = core_foundation::dictionary::CFDictionaryGetValue(
                    info as CFDictionaryRef,
                    kCGWindowName as *const _,
                );

                if !window_name_ref.is_null() {
                    // Convert the value to a CFString
                    let window_name = CFString::wrap_under_get_rule(window_name_ref as *const _);
                    window_title = cfstring_to_string(&window_name);
                }

                break;
            }
        }

        CFRelease(window_list as *const c_void);

        Ok(Some(WindowInfo::new(app_name_str, window_title)))
    }
}

#[cfg(target_os = "macos")]
fn nsstring_to_string(nsstring: *mut Object) -> String {
    unsafe {
        let utf8: *const i8 = msg_send![nsstring, UTF8String];
        let len = libc::strlen(utf8);
        let bytes = std::slice::from_raw_parts(utf8 as *const u8, len);
        String::from_utf8_lossy(bytes).into_owned()
    }
}

#[cfg(target_os = "macos")]
fn cfstring_to_string(cf_string: &CFString) -> String {
    cf_string.to_string()
}
