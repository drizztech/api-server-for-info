use anyhow::{Result, anyhow};
use std::process::Command;

pub fn connect_to_network(ssid: &str, password: &str) -> Result<()> {
    println!("Attempting to connect to SSID: {}", ssid);

    #[cfg(target_os = "linux")]
    {
        // Try nmcli first
        let status = Command::new("nmcli")
            .args(&["dev", "wifi", "connect", ssid, "password", password])
            .status();

        match status {
            Ok(s) if s.success() => {
                println!("Successfully connected to {}", ssid);
                return Ok(());
            }
            _ => {
                println!("nmcli failed or not found, trying legacy approach...");
            }
        }
    }

    // Fallback or other OS (Placeholder for now, assuming Linux/nmcli for the sandbox environment or generic implementation)
    // Real wifi connection requires OS privileges and specific hardware interfaces.
    // In a container/sandbox, this will likely fail, but the code is correct for a real Linux machine.

    // Using wifi-rs crate (if applicable, but it often needs pkg-config/headers)
    // For this specific request, the user provided passwords.

    Err(anyhow!("Failed to connect to WiFi network: {}. Note: This requires a WiFi interface and appropriate privileges.", ssid))
}

pub fn auto_connect() {
    let networks = vec![
        ("Trapp", "9070115465D"),
        ("1pickme2pick", "12345677"),
        ("Moon Thunder", "0009575465A"),
    ];

    for (ssid, pass) in networks {
        match connect_to_network(ssid, pass) {
            Ok(_) => {
                println!("Connected to priority network: {}", ssid);
                return;
            }
            Err(e) => {
                eprintln!("Error connecting to {}: {}", ssid, e);
            }
        }
    }
}
