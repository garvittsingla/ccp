use reqwest::blocking::Client;
use reqwest::header::{CACHE_CONTROL, CONNECTION, PRAGMA, USER_AGENT};
use reqwest::redirect::Policy;
use std::net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// Canonical Firefox endpoint returning "success\n" (HTTP 200) when unlocked
pub const FIREFOX_SUCCESS_URL: &str = "http://detectportal.firefox.com/success.txt";
pub const FIREFOX_EXPECTED_BODY: &str = "success";
/// Fallback Google connectivity check endpoint returning HTTP 204 No Content when unlocked
pub const GSTATIC_204_URL: &str = "http://connectivitycheck.gstatic.com/generate_204";
/// Fallback IPv4-literal probe if campus DNS drops external queries before auth
pub const RAW_IP_FALLBACK_URL: &str = "http://1.1.1.1/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// Internet is already unlocked ("success" received or HTTP 204)
    OnlineUnlocked,
    /// Captive portal intercepted the probe; contains dynamically discovered gateway base URL
    /// and target login URL (e.g. "/login.xml" for Sophos or preserved "/php/uid.php?..." for Palo Alto)
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
        .danger_accept_invalid_certs(true) // Campus portals use self-signed certs
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

/// Resolves the gateway base (scheme://host[:port]) and the exact login URL.
///
/// 1. If the extracted redirect URL has a non-root path/query (e.g. Palo Alto /php/uid.php?...)
///    and does NOT end with /httpclient.html, the exact full URL is preserved as the login target.
/// 2. If the URL has no path, ends with /httpclient.html (Sophos landing page), or is a bare host:port,
///    the login target is format!("{gateway_base}/login.xml").
pub fn resolve_login_target(raw_redirect_or_html: &str) -> Option<(String, String)> {
    let text = raw_redirect_or_html.trim();
    if text.is_empty() {
        return None;
    }

    // 1. Direct URL parse attempt
    if let Ok(parsed) = url::Url::parse(text)
        && (parsed.scheme() == "http" || parsed.scheme() == "https")
        && let Some(host) = parsed.host_str()
        && !is_ignored_host(host)
    {
        return Some(determine_login_target(&parsed, text));
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
                    if raw_url.contains("login.xml")
                        || raw_url.contains("/php/")
                        || raw_url.contains("uid.php")
                    {
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
            && best.host_str().is_some()
        {
            return Some(determine_login_target(&best, &raw));
        }
    }

    // 3. Fallback: Host[:port] without scheme (e.g. "172.16.68.6:8090" or "10.1.1.9:8090/login")
    let with_scheme = format!("http://{}", text);
    if let Ok(parsed) = url::Url::parse(&with_scheme)
        && let Some(host) = parsed.host_str()
        && !is_ignored_host(host)
        && (is_private_or_local_ip(host) || parsed.port().is_some() || text.contains(":8090"))
    {
        return Some(determine_login_target(&parsed, &with_scheme));
    }

    None
}

fn determine_login_target(parsed: &url::Url, raw_str: &str) -> (String, String) {
    let scheme = parsed.scheme();
    let host = parsed.host_str().unwrap_or("localhost");
    let port = parsed.port();
    let gateway_base = format_gateway_base(scheme, host, port, raw_str);

    let path = parsed.path();
    let query = parsed.query();
    let has_non_root_path_or_query = (path != "/" && !path.is_empty()) || query.is_some();
    let ends_with_httpclient = path.ends_with("/httpclient.html") || path == "httpclient.html";

    let login_url = if has_non_root_path_or_query && !ends_with_httpclient {
        // Keep exact full redirect URL (e.g. Palo Alto /php/uid.php?vsys=1...)
        raw_str.to_string()
    } else {
        // Sophos / Cyberoam / default
        format!("{}/login.xml", gateway_base.trim_end_matches('/'))
    };

    (gateway_base, login_url)
}

/// Extracts scheme://host[:port] gateway base from a URL string or an HTML body
pub fn extract_gateway_base(url_or_html: &str) -> Option<String> {
    resolve_login_target(url_or_html).map(|(base, _)| base)
}

fn resolve_fallback_gateway(fallback_gateway: Option<&str>, err_context: &str) -> ProbeResult {
    if let Some(fb) = fallback_gateway {
        if is_gateway_reachable(fb) {
            if let Some((gateway_base, login_xml_url)) = resolve_login_target(fb) {
                return ProbeResult::LockedPortal {
                    gateway_base,
                    login_xml_url,
                };
            }
        } else {
            return ProbeResult::ProbeTimeoutOrError(format!(
                "{}: cached gateway {} is unreachable on current network",
                err_context, fb
            ));
        }
    }
    ProbeResult::ProbeTimeoutOrError(err_context.to_string())
}

/// Probes a specific URL using the Firefox CaptiveDetect algorithm with GStatic fallback
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
            if url == FIREFOX_SUCCESS_URL {
                // 1. Try connectivitycheck.gstatic.com/generate_204 (from original main:src/main.rs line 61)
                let gstatic_req = client
                    .get(GSTATIC_204_URL)
                    .header(CACHE_CONTROL, "no-cache")
                    .header(PRAGMA, "no-cache")
                    .header(CONNECTION, "close")
                    .header(
                        USER_AGENT,
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
                    );
                if let Ok(resp) = gstatic_req.send() {
                    return parse_probe_response(resp, fallback_gateway);
                }

                // 2. Try raw IP 1.1.1.1 with Host: detectportal.firefox.com
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

    // HTTP 204 No Content indicates Internet is unlocked
    if status.as_u16() == 204 {
        return ProbeResult::OnlineUnlocked;
    }

    if status.is_success() {
        let body = resp.text().unwrap_or_default();
        if body.trim() == FIREFOX_EXPECTED_BODY {
            return ProbeResult::OnlineUnlocked;
        }

        if let Some((gateway_base, login_xml_url)) = resolve_login_target(&body) {
            return ProbeResult::LockedPortal {
                gateway_base,
                login_xml_url,
            };
        }
    } else if status.is_redirection() || status.as_u16() == 511 {
        if let Some(loc) = resp.headers().get(reqwest::header::LOCATION)
            && let Ok(loc_str) = loc.to_str()
            && let Some((gateway_base, login_xml_url)) = resolve_login_target(loc_str)
        {
            return ProbeResult::LockedPortal {
                gateway_base,
                login_xml_url,
            };
        }
        let body = resp.text().unwrap_or_default();
        if let Some((gateway_base, login_xml_url)) = resolve_login_target(&body) {
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

/// Validates portal authentication responses, supporting Sophos XML, Cyberoam,
/// and original main:src/main.rs HTTP status codes (200, 301, 302, 303).
pub fn validate_portal_response(status_code: u16, body: &str) -> Result<String, String> {
    let body_lower = body.to_lowercase();
    let extracted_msg = extract_xml_message(body);

    let has_success_keyword = body_lower.contains("<status>live</status>")
        || body_lower.contains("[cdata[live]]")
        || body_lower.contains("signed in")
        || body_lower.contains("successfully logged in");

    // 1. Explicit failure checks
    if let Some(msg) = &extracted_msg
        && !has_success_keyword
    {
        return Err(format!("Portal rejected login: {}", msg));
    }

    let failure_keywords = [
        "invalid username",
        "invalid password",
        "incorrect password",
        "authentication failed",
        "login failed",
        "wrong password",
        "invalid credentials",
        "maximum login limit",
        "make sure your password is correct",
        "account expired",
        "access denied",
    ];

    for keyword in &failure_keywords {
        if body_lower.contains(keyword) {
            return Err(format!("Portal rejected login: {}", keyword));
        }
    }

    // 2. Explicit Sophos/text success
    if has_success_keyword {
        return Ok(extracted_msg.unwrap_or_else(|| "Authentication successful".to_string()));
    }

    // 3. Fallback matching main:src/main.rs (HTTP 200 | 301 | 302 | 303 without failure keywords)
    let is_sophos_xml = body.contains("<requestresponse>") || body.contains("<status>");
    if !is_sophos_xml && matches!(status_code, 200 | 301 | 302 | 303) {
        return Ok("Login request completed.".to_string());
    }

    Err(format!(
        "Portal rejected login: Unexpected response (HTTP {})",
        status_code
    ))
}

/// Wrapper for validate_portal_response assuming HTTP 200
pub fn validate_sophos_response(body: &str) -> Result<String, String> {
    validate_portal_response(200, body)
}

/// Submits url-encoded credentials to the target login URL.
/// Keys and values (including special characters like &, =, +, #, %) are properly URL-encoded.
pub fn submit_login_post(
    client: &Client,
    url: &str,
    username: &str,
    password: &str,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    let is_sophos = url.contains("login.xml") || url.contains(":8090");

    if is_sophos {
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
    } else {
        // Exact 6 form parameters from main:src/main.rs (Palo Alto / generic)
        let params = [
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
}

/// Authenticates to the captive portal with auto-retry between http and https,
/// and validates the portal response body and status code.
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

    match validate_portal_response(status.as_u16(), &body) {
        Ok(msg) => {
            println!("Login request completed: {}", msg);
            println!("Check your internet connection to confirm authentication.");
            Ok(())
        }
        Err(err_msg) => {
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
    fn test_probe_204_no_content() {
        let (url, handle) =
            spawn_mock_server("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n");
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
    fn test_resolve_login_target_palo_alto_vs_sophos() {
        // Palo Alto style redirect: preserves exact full URL with path and query
        let pa_location = "https://172.16.1.1:6082/php/uid.php?vsys=1&rule=0";
        let pa_result = resolve_login_target(pa_location);
        assert_eq!(
            pa_result,
            Some((
                "https://172.16.1.1:6082".to_string(),
                "https://172.16.1.1:6082/php/uid.php?vsys=1&rule=0".to_string()
            ))
        );

        // Sophos style redirect: ends with /httpclient.html, resolves to /login.xml
        let sophos_location =
            "http://172.16.68.6:8090/httpclient.html?u=http://detectportal.firefox.com/success.txt";
        let sophos_result = resolve_login_target(sophos_location);
        assert_eq!(
            sophos_result,
            Some((
                "http://172.16.68.6:8090".to_string(),
                "http://172.16.68.6:8090/login.xml".to_string()
            ))
        );

        // Bare gateway: resolves to /login.xml
        let bare = "http://172.16.68.6:8090";
        let bare_result = resolve_login_target(bare);
        assert_eq!(
            bare_result,
            Some((
                "http://172.16.68.6:8090".to_string(),
                "http://172.16.68.6:8090/login.xml".to_string()
            ))
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
    fn test_validate_portal_response_status_codes() {
        // Fallback for non-Sophos portals: HTTP 200 without failure keywords
        let non_sophos_html =
            "<html><body>Welcome to Palo Alto Networks Captive Portal</body></html>";
        let res = validate_portal_response(200, non_sophos_html);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), "Login request completed.");

        // HTTP 302 redirect on login success
        let res_302 = validate_portal_response(302, "");
        assert!(res_302.is_ok());

        // HTTP 200 with explicit failure keyword
        let failure_html = "<html><body>Authentication failed. Please try again.</body></html>";
        let res_fail = validate_portal_response(200, failure_html);
        assert!(res_fail.is_err());
        assert_eq!(
            res_fail.unwrap_err(),
            "Portal rejected login: authentication failed"
        );
    }

    #[test]
    fn test_cached_gateway_reachability() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let active_gw = format!("http://127.0.0.1:{}", port);
        assert!(is_gateway_reachable(&active_gw));

        drop(listener);
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

    #[test]
    fn test_submit_login_post_palo_alto_params() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock listener");
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/php/uid.php");

        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 2048];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);

                // Verify exact 6 params from main:src/main.rs (without mode=191)
                assert!(
                    !request.contains("mode=191"),
                    "Palo Alto target should not contain mode=191"
                );
                assert!(request.contains("user=user1"));
                assert!(request.contains("passwd=P%40ss%26word%3D1%2B2%253"));
                assert!(request.contains("ok=Login"));

                let resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK";
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
