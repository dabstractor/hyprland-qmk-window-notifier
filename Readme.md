# QMK Window Notifier

A specialized Rust application that detects active window changes in supported environments (Hyprland and macOS) and sends this information to QMK keyboards, enabling dynamic layer switching and command execution based on the active application.

## Overview

QMK Window Notifier bridges the gap between supported environments (Hyprland and macOS) and QMK-powered keyboards. It monitors window focus changes and transmits application class and title information to your keyboard, enabling context-aware layer switching and feature toggling.

This tool is part of a broader ecosystem I've created:
- **[qmk-notifier](https://github.com/dabstractor/qmk-notifier)**: QMK module that receives commands and handles layer/feature toggling on your keyboard
- **[qmk_notifier](https://github.com/dabstractor/qmk_notifier)**: Desktop application that sends commands to your keyboard via Raw HID
- **qmk-window-notifier** (this tool): Application that detects window changes in supported environments

## Features

- Seamless integration with Hyprland's event system and macOS
- Real-time window focus change detection
- Automatic transmission of application class and window title to QMK keyboards
- Minimal resource footprint
- Verbose logging option for debugging

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/dabstractor/qmk-window-notifier.git
cd qmk-window-notifier

# Build the project
cargo build --release

# The binary will be available at target/release/qmk-window-notifier
```
The binary will be available at target/release/qmk-window-notifier

### Dependencies

- [qmk-notifier](https://github.com/dabstractor/qmk-notifier) must be installed into your QMK keyboard's directory

## Usage

Simply run the application while a supported environment is active:

```bash
# Run the application
qmk-window-notifier
```

The application automatically:
1. Verifies it's running within a supported environment
2. Sets up event listeners for window focus changes
3. Captures application class and title information
4. Formats and sends this data to your QMK keyboard using the qmk_notifier library

## Integration with QMK

This tool works in conjunction with:
- The [qmk-notifier](https://github.com/dabstractor/qmk-notifier) QMK module running on your keyboard
- The [qmk_notifier](https://github.com/dabstractor/qmk_notifier) tool which handles the Raw HID communication

When a window focus change is detected, this application formats the data as:
`{application_class}{GS}{window_title}` where `{GS}` is the Group Separator character (0x1D).

## Technical Details

- Written in Rust for performance and reliability
- Uses the Hyprland crate to interact with Hyprland's IPC (if running on Wayland)
- Utilizes Hyprland's event system to detect window changes (if running on Wayland)
- Handles error conditions gracefully (e.g., when a supported environment is not running)
- Minimal overhead and resource usage

## Automatic Startup

To run this utility automatically when Hyprland starts, add the following to your Hyprland configuration file:

```bash
# ~/.config/hypr/hyprland.conf
exec-once = qmk-window-notifier
```

## Example Use Cases

- Automatically switch to a coding layer when your IDE is focused
- Enable media controls when music or video applications are active
- Activate application-specific macros based on the current window
- Create context-aware keyboard layouts that adapt to your workflow

## Contributing

Contributions are welcome! Feel free to submit issues or pull requests on GitHub.

## License

[MIT License](LICENSE)

