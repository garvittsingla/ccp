use ccp::probe::{self, ProbeResult};
use ccp::wifi;
use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // Save credentials when `ccp set` is used.
    if args.len() > 1 && args[1] == "set" {
        let mut username = String::new();

        print!("Username: ");
        io::stdout().flush()?;
        io::stdin().read_line(&mut username)?;

        let username = username.trim();
        let password = rpassword::prompt_password("Password: ")?;

        if username.is_empty() || password.is_empty() {
            println!("Username and password cannot be empty.");
            return Ok(());
        }

        let mut file = create_credentials_file()?;

        // Store credentials as raw text: username on line 1, password on line 2.
        writeln!(file, "{}", username)?;
        writeln!(file, "{}", password)?;

        println!("Credentials saved successfully.");
        return Ok(());
    }

    // Default: load saved credentials and authenticate.
    if args.len() == 1 {
        let path = credentials_path();

        if !Path::new(&path).exists() {
            println!("Credentials not found. Run `ccp set` first.");
            return Ok(());
        }

        let mut file = File::open(&path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let mut lines = contents.lines();
        let username = lines.next().unwrap_or("").trim();
        let password = lines.next().unwrap_or("").trim();

        if username.is_empty() || password.is_empty() {
            println!("Username or password missing in credentials file.");
            return Ok(());
        }

        let cached_gateway = get_cached_gateway();
        let client = probe::build_fast_client(false)?;

        // Execute zero-lag probe pipeline
        let probe_result = probe::probe_network(&client, cached_gateway.as_deref());

        match probe_result {
            ProbeResult::OnlineUnlocked => {
                println!("Already connected and authenticated!");
                return Ok(());
            }

            ProbeResult::LockedPortal {
                gateway_base,
                login_xml_url,
            } => {
                println!("Portal detected at: {}", gateway_base);
                set_cached_gateway(&gateway_base);
                post_login(&client, &login_xml_url, username, password)?;
                return Ok(());
            }

            ProbeResult::InterfaceOffline => {
                println!("Wi-Fi interface offline or disconnected. Connecting to Wi-Fi...");
                if let Err(e) = wifi::connect_wifi(None) {
                    eprintln!("Wi-Fi connection command error: {}", e);
                }

                print!("Waiting for IPv4 route...");
                io::stdout().flush()?;
                match wifi::wait_for_ipv4(Duration::from_millis(6000), Duration::from_millis(200)) {
                    Some(ip) => {
                        println!(" Connected ({})", ip);
                        let post_connect_probe =
                            probe::probe_network(&client, cached_gateway.as_deref());
                        match post_connect_probe {
                            ProbeResult::OnlineUnlocked => {
                                println!("Already connected and authenticated!");
                            }
                            ProbeResult::LockedPortal {
                                gateway_base,
                                login_xml_url,
                            } => {
                                println!("Portal detected at: {}", gateway_base);
                                set_cached_gateway(&gateway_base);
                                post_login(&client, &login_xml_url, username, password)?;
                            }
                            ProbeResult::InterfaceOffline => {
                                println!("Interface still offline after Wi-Fi connect attempt.");
                            }
                            ProbeResult::ProbeTimeoutOrError(e) => {
                                eprintln!("Probe failed after Wi-Fi connect: {}", e);
                                if let Some(gw) = cached_gateway {
                                    let fallback_url =
                                        format!("{}/login.xml", gw.trim_end_matches('/'));
                                    println!("Attempting fallback login at: {}", fallback_url);
                                    post_login(&client, &fallback_url, username, password)?;
                                }
                            }
                        }
                    }
                    None => {
                        println!(" Timed out waiting for IPv4 route.");
                    }
                }
                return Ok(());
            }

            ProbeResult::ProbeTimeoutOrError(err_msg) => {
                eprintln!("Network probe error: {}", err_msg);
                if let Some(gw) = cached_gateway {
                    let fallback_url = format!("{}/login.xml", gw.trim_end_matches('/'));
                    println!("Attempting cached gateway fallback: {}", fallback_url);
                    post_login(&client, &fallback_url, username, password)?;
                } else {
                    println!("Unable to detect portal and no cached gateway is available.");
                }
                return Ok(());
            }
        }
    }

    println!("Usage:");
    println!("  ccp       Authenticate using saved credentials");
    println!("  ccp set   Save username and password");

    Ok(())
}

fn post_login(
    client: &reqwest::blocking::Client,
    login_xml_url: &str,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Authenticating at: {}", login_xml_url);

    let result = submit_login_post(client, login_xml_url, username, password);
    let resp = match result {
        Ok(r) => r,
        Err(e) => {
            // HTTPS vs. HTTP auto-retry:
            // Some subnets use http:// while others enforce https:// with self-signed certs.
            let alt_url = if login_xml_url.starts_with("http://") {
                login_xml_url.replacen("http://", "https://", 1)
            } else if login_xml_url.starts_with("https://") {
                login_xml_url.replacen("https://", "http://", 1)
            } else {
                return Err(Box::new(e));
            };
            println!("Initial POST failed ({}), retrying with: {}", e, alt_url);
            submit_login_post(client, &alt_url, username, password)?
        }
    };

    let status = resp.status();
    let body = resp.text().unwrap_or_default();
    println!("HTTP Status: {}", status.as_u16());

    let body_lower = body.to_lowercase();
    let failure_messages = [
        "invalid username",
        "invalid password",
        "incorrect password",
        "authentication failed",
        "login failed",
        "wrong password",
        "invalid credentials",
        "maximum login limit reached",
        "account expired",
        "access denied",
    ];

    if failure_messages.iter().any(|msg| body_lower.contains(msg)) {
        println!("Authentication failed. Check your username and password.");
        return Ok(());
    }

    if status.is_success() || status.is_redirection() {
        println!("Login request completed.");
        println!("Check your internet connection to confirm authentication.");
    } else {
        println!(
            "Unexpected response from captive portal (HTTP {}).",
            status.as_u16()
        );
    }

    Ok(())
}

fn submit_login_post(
    client: &reqwest::blocking::Client,
    url: &str,
    username: &str,
    password: &str,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    let params = [
        ("mode", "191"),
        ("username", username),
        ("password", password),
        ("a", &now_ms.to_string()),
        ("producttype", "0"),
        ("inputStr", ""),
        ("escapeUser", username),
        ("preauthid", ""),
        ("user", username),
        ("passwd", password),
        ("ok", "Login"),
    ];

    client
        .post(url)
        .header(reqwest::header::CACHE_CONTROL, "no-cache")
        .header(reqwest::header::CONNECTION, "close")
        .form(&params)
        .send()
}

fn get_config_dir() -> PathBuf {
    if let Some(config_dir) = dirs::config_dir() {
        let p = config_dir.join("ccp");
        if p.exists() || !cfg!(target_os = "windows") {
            return p;
        }
    }
    if let Some(home) = dirs::home_dir() {
        return home.join(".config").join("ccp");
    }
    if let Ok(profile) = env::var("USERPROFILE").or_else(|_| env::var("HOME")) {
        return PathBuf::from(profile).join(".config").join("ccp");
    }
    PathBuf::from(".config/ccp")
}

fn credentials_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        let legacy = home.join(".config").join("ccp").join("credentials.txt");
        if legacy.exists() {
            return legacy;
        }
    }
    get_config_dir().join("credentials.txt")
}

fn cached_gateway_path() -> PathBuf {
    get_config_dir().join("cached_gateway.txt")
}

fn get_cached_gateway() -> Option<String> {
    let path = cached_gateway_path();
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn set_cached_gateway(gateway: &str) {
    let path = cached_gateway_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, gateway);
}

fn create_credentials_file() -> std::io::Result<File> {
    let path = credentials_path();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    File::create(path)
}
