
use std::process::Command;
use std::path::Path;
use std::env;
use std::fs::{self, File};
use std::path::PathBuf;
use std::io::{self, Write, Read};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

        let mut file = create_path()?;

        // Store credentials as raw text: username on line 1, password on line 2.
        writeln!(file, "{}", username)?;
        writeln!(file, "{}", password)?;

        println!("Credentials saved successfully.");
        return Ok(());
    }

    // No arguments: load saved credentials and authenticate.
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

        let url = "http://connectivitycheck.gstatic.com/generate_204";

        match check_login_status(url) {
            Ok(redirect_url) => {
                println!("Portal URL: {}", redirect_url);

                login_portal(
                    &redirect_url,
                    username,
                    password,
                )?;
            }

            Err(e) => {
                println!("Error: {}", e);
            }
        }

        return Ok(());
    }

    println!("Usage:");
    println!("  ccp       Authenticate using saved credentials");
    println!("  ccp set   Save username and password");

    Ok(())
}

fn login_portal(
    redirect_url: &str,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {

    let output = Command::new("curl")
        .arg("-k")
        .arg("-sS")
        .arg("-v")
        .arg(redirect_url)
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/x-www-form-urlencoded")
        .arg("--data-urlencode")
        .arg("inputStr=")
        .arg("--data-urlencode")
        .arg(format!("escapeUser={}", username))
        .arg("--data-urlencode")
        .arg("preauthid=")
        .arg("--data-urlencode")
        .arg(format!("user={}", username))
        .arg("--data-urlencode")
        .arg(format!("passwd={}", password))
        .arg("--data-urlencode")
        .arg("ok=Login")
        .arg("-w")
        .arg("\n%{http_code}")
        .output()?;

    if !output.status.success() {
        eprintln!("Curl failed: {}", String::from_utf8_lossy(&output.stderr));
        return Err("Login request failed.".into());
    }

    let response = String::from_utf8_lossy(&output.stdout);
    let mut parts = response.rsplitn(2, '\n');

    let http_status = parts.next().unwrap_or("").trim();
    let body = parts.next().unwrap_or("");

    println!("HTTP Status: {}", http_status);

    eprintln!("{}", String::from_utf8_lossy(&output.stderr));

    let body_lower = body.to_lowercase();

    // Captive portals often return HTTP 200 even when login fails.
    let failure_messages = [
        "invalid username",
        "invalid password",
        "incorrect password",
        "authentication failed",
        "login failed",
        "wrong password",
        "invalid credentials",
    ];

    if failure_messages.iter().any(|message| body_lower.contains(message)) {
        println!("Authentication failed. Check your username and password.");
        return Ok(());
    }

    match http_status {
        "200" | "301" | "302" | "303" => {
            println!("Login request completed.");
            println!("Check your internet connection to confirm authentication.");
        }
        _ => {
            println!("Unexpected response from captive portal.");
        }
    }

    Ok(())
}

fn check_login_status(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("curl")
        .args([
            "-sS",
            "-D", "-",
            "-o", "/dev/null",
            "--max-time", "10",
            url,
        ])
        .output()?;

    if !output.status.success() {
        return Err(format!(
            "Connectivity check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ).into());
    }

    let headers = String::from_utf8_lossy(&output.stdout);

    println!("Response headers:\n{}", headers);

    for line in headers.lines() {
        if line.to_lowercase().starts_with("location:") {
            return Ok(line["location:".len()..].trim().to_string());
        }
    }

    Err("No redirect URL found. You may already be connected.".into())
}

fn credentials_path() -> PathBuf {
    let home = env::var("HOME").expect("HOME environment variable not set");

    let mut path = PathBuf::from(home);
    path.push(".config/ccp/credentials.txt");

    path
}

fn check_credentials_path() {
    let path = credentials_path();
    let exists = Path::new(&path).exists();

    println!("Exists: {}", exists);
}

fn create_path() -> std::io::Result<File> {
    let path = credentials_path();

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    File::create(path)
}
