use crate::core::types::WindowInfo;
use std::error::Error;

pub fn notify_qmk(window_info: &WindowInfo, verbose: bool) -> Result<(), Box<dyn Error>> {
    let message = format!("{}{}{}", window_info.app_class, "\x1D", window_info.title);

    // Call the qmk_notifier
    let _ = qmk_notifier::run(Some(message.clone()));

    if verbose {
        let sanitized_message = message.replace('\x1D', "|");
        println!("Notified QMK: {}", sanitized_message);
    }

    Ok(())
}

