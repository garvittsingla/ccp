use reqwest::blocking::Client;
use reqwest::header::{CACHE_CONTROL, CONNECTION, PRAGMA, USER_AGENT};
use reqwest::redirect::Policy;
use std::net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Canonical Firefox endpoint returning "success\n" (HTTP 200) when unlocked
pub const FIREFOX_SUCCESS_URL: &str = "http://detectportal.firefox.com/success.txt";
pub const FIREFOX_EXPECTED_BODY: &str = "success";
/// Fallback IPv4-literal probe if campus DNS drops external queries before auth
pub const RAW_IP_FALLBACK_URL: &str = "http://1.1.1.1/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// Internet is already unlocked ("success" received)
    OnlineUnlocked,
    /// Captive portal intercepted the probe; contains dynamically discovered gateway base URL
    /// e.g. "http://172.16.68.6:8090" or "https://10.1.1.9:8090"
    LockedPortal {
        gateway_base: String,
        login_xml_url: String,
    },
    /// Wi-Fi interface has no IPv4 route or is disconnected
    InterfaceOffline,
    /// Wi-Fi is connected (has local IP) but probe timed out
    ProbeTimeoutOrError(String),
}

/// Returns the target probe URL, allowing override via `CCP_PROBE_URL`
pub fn probe_target_url() -> String {
    if let Ok(override_url) = std::env::var("CCP_PROBE_URL") {
        let trimmed = override_url.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    FIREFOX_SUCCESS_URL.to_string()
}

/// Zero-packet (<0.1ms) check for active local IPv4 route via UDP socket connect
pub fn current_local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("1.1.1.1:80").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip)
            if !ip.is_loopback()
                && !ip.is_link_local()
                && !(ip.octets()[0] == 169 && ip.octets()[1] == 254) =>
        {
            Some(ip)
        }
        _ => None,
    }
}

/// Checks if a gateway host:port is reachable via a fast 400ms TCP connection check
pub fn is_gateway_reachable(gateway: &str) -> bool {
    let normalized = normalize_gateway_base(gateway);
    if let Ok(parsed) = url::Url::parse(&normalized)
        && let Some(host) = parsed.host_str()
    {
        let port = parsed
            .port()
            .unwrap_or(if parsed.scheme() == "https" { 443 } else { 80 });
        let addr_str = format!("{}:{}", host, port);
        if let Ok(mut addrs) = addr_str.to_socket_addrs()
            && let Some(addr) = addrs.next()
        {
            return TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok();
        }
    }
    false
}

/// Builds a zero-lag HTTP client configured identically to Firefox's URLFetcher
pub fn build_fast_client(follow_redirects: bool) -> Result<Client, reqwest::Error> {
    Client::builder()
        .no_proxy() // Bypass Windows WinHTTP / WPAD proxy lag
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED)) // Force IPv4 (no AAAA timeout)
        .tcp_nodelay(true)
        .pool_max_idle_per_host(0) // Matches Firefox LOAD_FRESH_CONNECTION
        .danger_accept_invalid_certs(true) // Campus :8090 portals use self-signed certs
        .redirect(if follow_redirects {
            Policy::limited(3)
        } else {
            Policy::none() // Matches Firefox redirectionLimit = 0
        })
        .connect_timeout(Duration::from_millis(1200))
        .timeout(Duration::from_millis(2500))
        .build()
}

fn is_ignored_host(host: &str) -> bool {
    let h = host.to_lowercase();
    h == "detectportal.firefox.com"
        || h == "1.1.1.1"
        || h == "connectivitycheck.gstatic.com"
        || h == "clients3.google.com"
        || h == "msftconnecttest.com"
        || h == "example.com"
}

fn is_private_or_local_ip(host: &str) -> bool {
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        let octets = ip.octets();
        octets[0] == 10
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            || (octets[0] == 192 && octets[1] == 168)
            || ip.is_loopback()
    } else {
        false
    }
}

fn format_gateway_base(scheme: &str, host: &str, port: Option<u16>, full_context: &str) -> String {
    if let Some(p) = port {
        format!("{scheme}://{host}:{p}")
    } else if full_context.contains(":8090") {
        format!("{scheme}://{host}:8090")
    } else {
        format!("{scheme}://{host}")
    }
}

pub fn normalize_gateway_base(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{}", trimmed)
    }
}

/// Extracts scheme://host[:port] gateway base from a URL string or an HTML body
pub fn extract_gateway_base(url_or_html: &str) -> Option<String> {
    let text = url_or_html.trim();
    if text.is_empty() {
        return None;
    }

    // 1. Direct URL parse attempt
    if let Ok(parsed) = url::Url::parse(text)
        && (parsed.scheme() == "http" || parsed.scheme() == "https")
        && let Some(host) = parsed.host_str()
        && !is_ignored_host(host)
    {
        return Some(format_gateway_base(
            parsed.scheme(),
            host,
            parsed.port(),
            text,
        ));
    }

    // 2. Scan for URLs within HTML / JS / text
    if let Ok(re) = regex::Regex::new(r#"https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^\s"'<>`\\]*)?"#) {
        let mut candidates = Vec::new();
        for m in re.find_iter(text) {
            let raw_url = m
                .as_str()
                .trim_end_matches(&[')', ']', ';', ',', '\'', '"', '\\'][..]);
            if let Ok(parsed) = url::Url::parse(raw_url) {
                if parsed.scheme() != "http" && parsed.scheme() != "https" {
                    continue;
                }
                if let Some(host) = parsed.host_str() {
                    if is_ignored_host(host) {
                        continue;
                    }

                    let mut score = 0i32;
                    if parsed.port() == Some(8090) || raw_url.contains(":8090") {
                        score += 100;
                    }
                    if raw_url.contains("httpclient") {
                        score += 50;
                    }
                    if raw_url.contains("login.xml") {
                        score += 50;
                    }
                    if is_private_or_local_ip(host) {
                        score += 30;
                    }
                    candidates.push((score, parsed, raw_url.to_string()));
                }
            }
        }

        candidates.sort_by_key(|a| std::cmp::Reverse(a.0));
        if let Some((_, best, raw)) = candidates.into_iter().next()
            && let Some(host) = best.host_str()
        {
            return Some(format_gateway_base(best.scheme(), host, best.port(), &raw));
        }
    }

    // 3. Fallback: Host[:port] without scheme (e.g. "172.16.68.6:8090" or "10.1.1.9:8090/login")
    let with_scheme = format!("http://{}", text);
    if let Ok(parsed) = url::Url::parse(&with_scheme)
        && let Some(host) = parsed.host_str()
        && !is_ignored_host(host)
        && (is_private_or_local_ip(host) || parsed.port().is_some() || text.contains(":8090"))
    {
        return Some(format_gateway_base("http", host, parsed.port(), text));
    }

    None
}

fn resolve_fallback_gateway(fallback_gateway: Option<&str>, err_context: &str) -> ProbeResult {
    if let Some(fb) = fallback_gateway {
        if is_gateway_reachable(fb) {
            let gateway_base = normalize_gateway_base(fb);
            let login_xml_url = format!("{}/login.xml", gateway_base.trim_end_matches('/'));
            return ProbeResult::LockedPortal {
                gateway_base,
                login_xml_url,
            };
        } else {
            return ProbeResult::ProbeTimeoutOrError(format!(
                "{}: cached gateway {} is unreachable on current network",
                err_context, fb
            ));
        }
    }
    ProbeResult::ProbeTimeoutOrError(err_context.to_string())
}

/// Probes a specific URL using the Firefox CaptiveDetect algorithm
pub fn probe_url(client: &Client, url: &str, fallback_gateway: Option<&str>) -> ProbeResult {
    let req = client
        .get(url)
        .header(CACHE_CONTROL, "no-cache")
        .header(PRAGMA, "no-cache")
        .header(CONNECTION, "close")
        .header(
            USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
        );

    match req.send() {
        Ok(resp) => parse_probe_response(resp, fallback_gateway),
        Err(primary_err) => {
            // DNS resolution failure / drop fallback:
            // Query raw IP 1.1.1.1 with Host: detectportal.firefox.com
            if url == FIREFOX_SUCCESS_URL {
                let fb_req = client
                    .get(RAW_IP_FALLBACK_URL)
                    .header(reqwest::header::HOST, "detectportal.firefox.com")
                    .header(CACHE_CONTROL, "no-cache")
                    .header(PRAGMA, "no-cache")
                    .header(CONNECTION, "close")
                    .header(
                        USER_AGENT,
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
                    );
                if let Ok(resp) = fb_req.send() {
                    return parse_probe_response(resp, fallback_gateway);
                }
            }

            resolve_fallback_gateway(fallback_gateway, &primary_err.to_string())
        }
    }
}

fn parse_probe_response(
    resp: reqwest::blocking::Response,
    fallback_gateway: Option<&str>,
) -> ProbeResult {
    let status = resp.status();

    if status.is_success() {
        let body = resp.text().unwrap_or_default();
        if body.trim() == FIREFOX_EXPECTED_BODY {
            return ProbeResult::OnlineUnlocked;
        }

        if let Some(gateway_base) = extract_gateway_base(&body) {
            let login_xml_url = format!("{}/login.xml", gateway_base.trim_end_matches('/'));
            return ProbeResult::LockedPortal {
                gateway_base,
                login_xml_url,
            };
        }
    } else if status.is_redirection() || status.as_u16() == 511 {
        if let Some(loc) = resp.headers().get(reqwest::header::LOCATION)
            && let Ok(loc_str) = loc.to_str()
            && let Some(gateway_base) = extract_gateway_base(loc_str)
        {
            let login_xml_url = format!("{}/login.xml", gateway_base.trim_end_matches('/'));
            return ProbeResult::LockedPortal {
                gateway_base,
                login_xml_url,
            };
        }
        let body = resp.text().unwrap_or_default();
        if let Some(gateway_base) = extract_gateway_base(&body) {
            let login_xml_url = format!("{}/login.xml", gateway_base.trim_end_matches('/'));
            return ProbeResult::LockedPortal {
                gateway_base,
                login_xml_url,
            };
        }
    }

    let err_msg = format!(
        "Portal intercepted request (status {}) but gateway URL could not be resolved",
        status
    );
    resolve_fallback_gateway(fallback_gateway, &err_msg)
}

/// Executes dynamic gateway discovery according to Firefox CaptiveDetect specifications
pub fn probe_network(client: &Client, fallback_gateway: Option<&str>) -> ProbeResult {
    let has_override = std::env::var("CCP_PROBE_URL").is_ok();
    if !has_override && current_local_ipv4().is_none() {
        return ProbeResult::InterfaceOffline;
    }
    let target = probe_target_url();
    probe_url(client, &target, fallback_gateway)
}

/// Extracts the message text inside <message><![CDATA[...]]></message> or <message>...</message>
pub fn extract_xml_message(body: &str) -> Option<String> {
    let re = regex::Regex::new(r#"(?is)<message>(?:\s*<!\[CDATA\[)?(.*?)(?:\]\]>\s*)?</message>"#)
        .ok()?;
    if let Some(caps) = re.captures(body)
        && let Some(m) = caps.get(1)
    {
        let msg = m.as_str().trim();
        if !msg.is_empty() {
            return Some(msg.to_string());
        }
    }
    None
}

/// Validates whether a Sophos/Cyberoam captive portal response represents a successful login.
///
/// Only treats the login as successful if the body contains "LIVE", "signed in",
/// or "successfully logged in" (case-insensitive).
/// If rejected, extracts the failure message from XML/CDATA and returns Err.
pub fn validate_sophos_response(body: &str) -> Result<String, String> {
    let body_lower = body.to_lowercase();
    let extracted_msg = extract_xml_message(body);

    // Only treat the login as successful if the body contains "LIVE", "signed in",
    // or "successfully logged in" (case-insensitive).
    let is_success = body_lower.contains("live")
        || body_lower.contains("signed in")
        || body_lower.contains("successfully logged in");

    if is_success {
        let msg = extracted_msg.unwrap_or_else(|| "Authentication successful".to_string());
        return Ok(msg);
    }

    // If XML body contains <message> without LIVE/signed in, extract it and return Err
    if let Some(msg) = extracted_msg {
        return Err(format!("Portal rejected login: {}", msg));
    }

    // Check for common captive portal failure messages
    let failure_keywords = [
        "invalid username",
        "invalid password",
        "incorrect password",
        "authentication failed",
        "login failed",
        "wrong password",
        "invalid credentials",
        "maximum login limit",
        "account expired",
        "access denied",
    ];

    for keyword in &failure_keywords {
        if body_lower.contains(keyword) {
            return Err(format!("Portal rejected login: {}", keyword));
        }
    }

    Err("Portal rejected login: Unrecognized response without LIVE status".to_string())
}

/// Submits url-encoded credentials to login.xml.
/// Keys and values (including special characters like &, =, +, #, %) are properly URL-encoded.
pub fn submit_login_post(
    client: &Client,
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
        .header(CACHE_CONTROL, "no-cache")
        .header(CONNECTION, "close")
        .form(&params)
        .send()
}

/// Authenticates to the captive portal with auto-retry between http and https,
/// and validates the Sophos XML response body.
pub fn post_login(
    client: &Client,
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

    match validate_sophos_response(&body) {
        Ok(msg) => {
            println!("Login request completed: {}", msg);
            println!("Check your internet connection to confirm authentication.");
            Ok(())
        }
        Err(err_msg) => {
            // Check follow-up probe_network in case portal unauthenticated silently
            if probe_network(client, None) == ProbeResult::OnlineUnlocked {
                println!("Login succeeded (confirmed via active probe).");
                return Ok(());
            }
            eprintln!("{}", err_msg);
            Err(err_msg.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn spawn_mock_server(raw_response: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock listener");
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/probe");
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(raw_response.as_bytes());
                let _ = stream.flush();
            }
        });
        (url, handle)
    }

    #[test]
    fn test_firefox_probe_online() {
        let (url, handle) = spawn_mock_server(
            "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nsuccess\n",
        );
        let client = build_fast_client(false).expect("Client build failed");
        let result = probe_url(&client, &url, None);
        handle.join().unwrap();
        assert_eq!(result, ProbeResult::OnlineUnlocked);
    }

    #[test]
    fn test_firefox_probe_302_redirect() {
        let (url, handle) = spawn_mock_server(
            "HTTP/1.1 302 Found\r\nLocation: http://172.16.68.6:8090/httpclient.html?u=http://detectportal.firefox.com/success.txt\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        let client = build_fast_client(false).expect("Client build failed");
        let result = probe_url(&client, &url, None);
        handle.join().unwrap();
        assert_eq!(
            result,
            ProbeResult::LockedPortal {
                gateway_base: "http://172.16.68.6:8090".to_string(),
                login_xml_url: "http://172.16.68.6:8090/login.xml".to_string(),
            }
        );
    }

    #[test]
    fn test_firefox_probe_html_js_redirect() {
        let body = "<script>window.location=\"https://10.1.1.9:8090/httpclient.html\"</script>";
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let (url, handle) = spawn_mock_server(Box::leak(resp.into_boxed_str()));
        let client = build_fast_client(false).expect("Client build failed");
        let result = probe_url(&client, &url, None);
        handle.join().unwrap();
        assert_eq!(
            result,
            ProbeResult::LockedPortal {
                gateway_base: "https://10.1.1.9:8090".to_string(),
                login_xml_url: "https://10.1.1.9:8090/login.xml".to_string(),
            }
        );
    }

    #[test]
    fn test_extract_gateway_base_variants() {
        // Meta refresh
        let meta = r#"<meta http-equiv="refresh" content="0; url=http://172.16.68.6:8090/httpclient.html">"#;
        assert_eq!(
            extract_gateway_base(meta),
            Some("http://172.16.68.6:8090".to_string())
        );

        // Single quotes window.location
        let js = "window.location.href='https://192.168.1.1:8090/login';";
        assert_eq!(
            extract_gateway_base(js),
            Some("https://192.168.1.1:8090".to_string())
        );

        // Raw IP without scheme
        let ip_port = "172.16.68.6:8090";
        assert_eq!(
            extract_gateway_base(ip_port),
            Some("http://172.16.68.6:8090".to_string())
        );
    }

    #[test]
    fn test_current_local_ipv4_non_panicking() {
        let _ = current_local_ipv4();
    }

    #[test]
    fn test_validate_sophos_response_live_cdata() {
        let xml = "<requestresponse><status><![CDATA[LIVE]]></status><message><![CDATA[You are signed in as testuser]]></message></requestresponse>";
        let res = validate_sophos_response(xml);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "You are signed in as testuser");
    }

    #[test]
    fn test_validate_sophos_response_live_plain() {
        let xml = "<requestresponse><status>LIVE</status><message>You have successfully logged in</message></requestresponse>";
        let res = validate_sophos_response(xml);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "You have successfully logged in");
    }

    #[test]
    fn test_validate_sophos_response_signed_in() {
        let body = "<html><body>You are signed in to the captive network.</body></html>";
        let res = validate_sophos_response(body);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_sophos_response_wrong_password() {
        let xml = "<requestresponse><status><![CDATA[FAIL]]></status><message><![CDATA[Make sure your password is correct]]></message></requestresponse>";
        let res = validate_sophos_response(xml);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            "Portal rejected login: Make sure your password is correct"
        );
    }

    #[test]
    fn test_validate_sophos_response_max_login_limit() {
        let xml = "<requestresponse><status><![CDATA[FAIL]]></status><message><![CDATA[Maximum login limit reached for your account]]></message></requestresponse>";
        let res = validate_sophos_response(xml);
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err(),
            "Portal rejected login: Maximum login limit reached for your account"
        );
    }

    #[test]
    fn test_cached_gateway_reachability() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let active_gw = format!("http://127.0.0.1:{}", port);
        assert!(is_gateway_reachable(&active_gw));

        drop(listener);
        // After dropping, port is no longer listening
        assert!(!is_gateway_reachable(&active_gw));
    }

    #[test]
    fn test_ccp_probe_url_env_override() {
        let override_val = "http://127.0.0.1:9999/test-probe";
        unsafe {
            std::env::set_var("CCP_PROBE_URL", override_val);
        }
        assert_eq!(probe_target_url(), override_val);
        unsafe {
            std::env::remove_var("CCP_PROBE_URL");
        }
        assert_eq!(probe_target_url(), FIREFOX_SUCCESS_URL);
    }

    #[test]
    fn test_url_encoded_credentials_special_chars() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock listener");
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/login.xml");

        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);

                // Verify the form payload encodes special characters like & and =
                assert!(
                    request.contains("password=P%40ss%26word%3D1%2B2%253"),
                    "Request body did not properly url-encode password. Raw request:\n{}",
                    request
                );

                let resp = "HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\nContent-Length: 104\r\nConnection: close\r\n\r\n<requestresponse><status><![CDATA[LIVE]]></status><message><![CDATA[OK]]></message></requestresponse>";
                let _ = stream.write_all(resp.as_bytes());
                let _ = stream.flush();
            }
        });

        let client = build_fast_client(false).unwrap();
        let result = submit_login_post(&client, &url, "user1", "P@ss&word=1+2%3");
        assert!(result.is_ok());
        handle.join().unwrap();
    }
}
