use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// Polls for a valid local IPv4 route every `poll_interval` until `timeout` expires
pub fn wait_for_ipv4(timeout: Duration, poll_interval: Duration) -> Option<Ipv4Addr> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(ip) = crate::probe::current_local_ipv4() {
            return Some(ip);
        }
        std::thread::sleep(poll_interval);
    }
    None
}

#[cfg(target_os = "windows")]
use std::os::windows::process::CommandExt;

#[cfg(target_os = "windows")]
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(target_os = "windows")]
pub fn connect_wifi(ssid: Option<&str>) -> std::io::Result<()> {
    use std::process::Command;

    let target_profile = if let Some(s) = ssid {
        s.to_string()
    } else {
        // Find existing WLAN profiles
        let output = Command::new("netsh")
            .args(["wlan", "show", "profiles"])
            .creation_flags(CREATE_NO_WINDOW)
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        find_preferred_wlan_profile(&stdout).unwrap_or_default()
    };

    if !target_profile.is_empty() {
        let _ = Command::new("netsh")
            .args(["wlan", "connect", &format!("name={}", target_profile)])
            .creation_flags(CREATE_NO_WINDOW)
            .output();
    }

    Ok(())
}

#[cfg(target_os = "windows")]
pub fn find_preferred_wlan_profile(profiles_output: &str) -> Option<String> {
    let mut profiles = Vec::new();
    for line in profiles_output.lines() {
        if let Some(idx) = line.find(':') {
            let key = line[..idx].trim().to_lowercase();
            if key.contains("profile") {
                let name = line[idx + 1..].trim();
                if !name.is_empty() {
                    profiles.push(name.to_string());
                }
            }
        }
    }

    if profiles.is_empty() {
        return None;
    }

    // Prioritize campus / hostel / college Wi-Fi names
    let keywords = ["hostel", "college", "campus", "wifi", "eduroam", "student"];
    for keyword in &keywords {
        if let Some(p) = profiles.iter().find(|p| p.to_lowercase().contains(keyword)) {
            return Some(p.clone());
        }
    }

    // Default to the first profile if no keyword matches
    profiles.into_iter().next()
}

#[cfg(target_os = "linux")]
pub fn connect_wifi(ssid: Option<&str>) -> std::io::Result<()> {
    use std::process::Command;
    if let Some(s) = ssid {
        let _ = Command::new("nmcli")
            .args(["dev", "wifi", "connect", s])
            .output();
    } else {
        let _ = Command::new("nmcli").args(["radio", "wifi", "on"]).output();
        let _ = Command::new("nmcli").args(["networking", "on"]).output();
    }
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn connect_wifi(ssid: Option<&str>) -> std::io::Result<()> {
    use std::process::Command;
    if let Some(s) = ssid {
        let _ = Command::new("networksetup")
            .args(["-setairportnetwork", "en0", s])
            .output();
    } else {
        let _ = Command::new("networksetup")
            .args(["-setairportpower", "en0", "on"])
            .output();
    }
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn connect_wifi(_ssid: Option<&str>) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "windows")]
    use super::*;

    #[test]
    #[cfg(target_os = "windows")]
    fn test_find_preferred_wlan_profile() {
        let sample = "
Profiles on interface Wi-Fi:

Group policy profiles (read only)
---------------------------------
    <None>

User profiles
-------------
    All User Profile     : Guest_WiFi
    All User Profile     : Campus_Hostel_Net
    All User Profile     : Home_Network
";
        let found = find_preferred_wlan_profile(sample);
        assert_eq!(found, Some("Campus_Hostel_Net".to_string()));
    }
}
