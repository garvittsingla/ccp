use reqwest::blocking::Client;
use reqwest::header::{CACHE_CONTROL, CONNECTION, PRAGMA, USER_AGENT};
use reqwest::redirect::Policy;
use std::net::{IpAddr, Ipv4Addr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::LazyLock;
use std::time::Duration;

/// Canonical Firefox endpoint returning "success\n" (HTTP 200) when unlocked
pub const FIREFOX_SUCCESS_URL: &str = "http://detectportal.firefox.com/success.txt";
pub const FIREFOX_EXPECTED_BODY: &str = "success";
/// Fallback Google connectivity check endpoint returning HTTP 204 No Content when unlocked
pub const GSTATIC_204_URL: &str = "http://connectivitycheck.gstatic.com/generate_204";
/// Official Microsoft NCSI connectivity check endpoint returning "Microsoft Connect Test"
pub const MSFT_CONNECTTEST_URL: &str = "http://www.msftconnecttest.com/connecttest.txt";
pub const MSFT_EXPECTED_BODY: &str = "Microsoft Connect Test";

static META_REFRESH_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r#"(?i)<meta[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*url\s*=\s*["']?([^"'\s>]+)"#,
    )
    .unwrap()
});

static FORM_ACTION_RE: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r#"(?i)<form[^>]*action\s*=\s*["']([^"']+)["']"#).unwrap());

static JS_REDIRECT_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?i)(?:window\.|document\.|self\.|top\.)?location(?:\.href|\s*\.\s*replace|\s*\.\s*assign)?\s*(?:=|\()\s*["']([^"']+)["']"#).unwrap()
});

static GENERAL_URL_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"https?://[a-zA-Z0-9.-]+(?::[0-9]+)?(?:/[^\s"'<>`\\]*)?"#).unwrap()
});

static XML_MESSAGE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"(?is)<message>(?:\s*<!\[CDATA\[)?(.*?)(?:\]\]>\s*)?</message>"#).unwrap()
});

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

        // 1. Direct IP check fast-path (no DNS lookup)
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let IpAddr::V4(gw_ipv4) = ip
                && let Some(local_ip) = current_local_ipv4()
                && !gw_ipv4.is_loopback()
                && !local_ip.is_loopback()
            {
                // Require same /16 prefix so a cached gateway from a different subnet is never used
                if gw_ipv4.octets()[0..2] != local_ip.octets()[0..2] {
                    return false;
                }
            }

            let sock_addr = std::net::SocketAddr::new(ip, port);
            return TcpStream::connect_timeout(&sock_addr, Duration::from_millis(400)).is_ok();
        }

        // 2. Hostname resolution with IPv4 preference
        let addr_str = format!("{}:{}", host, port);
        if let Ok(addrs) = addr_str.to_socket_addrs() {
            let mut sorted_addrs: Vec<std::net::SocketAddr> = addrs.collect();
            sorted_addrs.sort_by_key(|sa| if sa.is_ipv4() { 0 } else { 1 });
            for addr in sorted_addrs {
                if TcpStream::connect_timeout(&addr, Duration::from_millis(400)).is_ok() {
                    return true;
                }
            }
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
    let ignored = [
        "detectportal.firefox.com",
        "1.1.1.1",
        "connectivitycheck.gstatic.com",
        "clients3.google.com",
        "msftconnecttest.com",
        "www.msftconnecttest.com",
        "msftncsi.com",
        "example.com",
        "w3.org",
        "www.w3.org",
        "one.one.one.one",
        "cloudflare.com",
        "mozilla.org",
        "firefox.com",
        "google.com",
        "apple.com",
        "microsoft.com",
    ];
    ignored
        .iter()
        .any(|&ig| h == ig || h.ends_with(&format!(".{ig}")))
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

fn is_valid_portal_target(parsed: &url::Url, raw_context: &str) -> bool {
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if is_ignored_host(host) {
        return false;
    }

    let port = parsed.port();
    if port == Some(8090)
        || port == Some(6082)
        || raw_context.contains(":8090")
        || raw_context.contains(":6082")
        || raw_context.contains("httpclient")
        || raw_context.contains("uid.php")
        || raw_context.contains("login.xml")
        || raw_context.contains("fgtauth")
    {
        return true;
    }

    if host == "localhost" || is_private_or_local_ip(host) {
        return true;
    }

    let addr_str = format!("{}:{}", host, port.unwrap_or(80));
    if let Ok(mut addrs) = addr_str.to_socket_addrs() {
        return addrs.any(|sa| match sa.ip() {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                octets[0] == 10
                    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                    || (octets[0] == 192 && octets[1] == 168)
                    || ipv4.is_loopback()
            }
            IpAddr::V6(ipv6) => ipv6.is_loopback(),
        });
    }

    false
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
        && is_valid_portal_target(&parsed, text)
    {
        return Some(determine_login_target(&parsed, text));
    }

    // 2. Scan for URLs inside HTML redirect/form constructs
    let mut candidates = Vec::new();

    for caps in META_REFRESH_RE.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            candidates.push((120, m.as_str().to_string()));
        }
    }

    for caps in FORM_ACTION_RE.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            candidates.push((110, m.as_str().to_string()));
        }
    }

    for caps in JS_REDIRECT_RE.captures_iter(text) {
        if let Some(m) = caps.get(1) {
            candidates.push((110, m.as_str().to_string()));
        }
    }

    for m in GENERAL_URL_RE.find_iter(text) {
        let raw_url = m
            .as_str()
            .trim_end_matches(&[')', ']', ';', ',', '\'', '"', '\\'][..]);
        if raw_url.contains(":8090")
            || raw_url.contains("httpclient")
            || raw_url.contains("login.xml")
            || raw_url.contains("/php/uid.php")
            || raw_url.contains("fgtauth")
        {
            candidates.push((100, raw_url.to_string()));
        }
    }

    candidates.sort_by_key(|a| std::cmp::Reverse(a.0));

    for (_, raw_cand) in candidates {
        if raw_cand.starts_with('/') {
            continue;
        }

        let normalized = if raw_cand.starts_with("http://") || raw_cand.starts_with("https://") {
            raw_cand
        } else {
            format!("http://{}", raw_cand)
        };

        if let Ok(parsed) = url::Url::parse(&normalized)
            && (parsed.scheme() == "http" || parsed.scheme() == "https")
            && is_valid_portal_target(&parsed, text)
        {
            return Some(determine_login_target(&parsed, &normalized));
        }
    }

    // 3. Fallback: Host[:port] without scheme (e.g. "172.16.68.6:8090" or "10.1.1.9:8090/login")
    let with_scheme = format!("http://{}", text);
    if let Ok(parsed) = url::Url::parse(&with_scheme)
        && (parsed.scheme() == "http" || parsed.scheme() == "https")
        && is_valid_portal_target(&parsed, text)
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
    let is_sophos_landing = parsed.port() == Some(8090)
        || raw_str.contains(":8090")
        || path.ends_with("/httpclient.html")
        || path == "httpclient.html"
        || path.ends_with("/login.xml");

    let login_url = if is_sophos_landing {
        format!("{}/login.xml", gateway_base.trim_end_matches('/'))
    } else {
        // For ALL non-Sophos portals (including root path http://172.16.1.1/ or /php/uid.php?...),
        // preserve the exact full redirect URL
        raw_str.to_string()
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

fn send_probe_request(
    client: &Client,
    url: &str,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    client
        .get(url)
        .header(CACHE_CONTROL, "no-cache")
        .header(PRAGMA, "no-cache")
        .header(CONNECTION, "close")
        .header(
            USER_AGENT,
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0",
        )
        .send()
}

/// Probes a specific URL using the Firefox CaptiveDetect algorithm with GStatic and MSFT fallbacks
pub fn probe_url(client: &Client, url: &str, fallback_gateway: Option<&str>) -> ProbeResult {
    let res = send_probe_request(client, url);
    let probe_result = match res {
        Ok(resp) => parse_probe_response(resp),
        Err(primary_err) => ProbeResult::ProbeTimeoutOrError(primary_err.to_string()),
    };

    // When url == FIREFOX_SUCCESS_URL, if req.send() fails OR if parse_probe_response returns
    // ProbeResult::ProbeTimeoutOrError(_) (e.g. unrecognized 403/502 response without a redirect),
    // automatically try GSTATIC_204_URL and then MSFT_CONNECTTEST_URL before fallback_gateway!
    if url == FIREFOX_SUCCESS_URL && matches!(probe_result, ProbeResult::ProbeTimeoutOrError(_)) {
        // 1. Try GSTATIC_204_URL
        if let Ok(resp) = send_probe_request(client, GSTATIC_204_URL) {
            let res2 = parse_probe_response(resp);
            if !matches!(res2, ProbeResult::ProbeTimeoutOrError(_)) {
                return res2;
            }
        }

        // 2. Try MSFT_CONNECTTEST_URL
        if let Ok(resp) = send_probe_request(client, MSFT_CONNECTTEST_URL) {
            let res3 = parse_probe_response(resp);
            if !matches!(res3, ProbeResult::ProbeTimeoutOrError(_)) {
                return res3;
            }
        }
    }

    if let ProbeResult::ProbeTimeoutOrError(err_msg) = probe_result {
        resolve_fallback_gateway(fallback_gateway, &err_msg)
    } else {
        probe_result
    }
}

fn parse_probe_response(resp: reqwest::blocking::Response) -> ProbeResult {
    let status = resp.status();

    // HTTP 204 No Content indicates Internet is unlocked
    if status.as_u16() == 204 {
        return ProbeResult::OnlineUnlocked;
    }

    if status.is_success() {
        let body = resp.text().unwrap_or_default();
        let trimmed = body.trim();
        if trimmed == FIREFOX_EXPECTED_BODY || trimmed == MSFT_EXPECTED_BODY {
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
        {
            let full_loc = if let Ok(u) = url::Url::parse(loc_str) {
                u.to_string()
            } else if let Ok(joined) = resp.url().join(loc_str) {
                joined.to_string()
            } else {
                loc_str.to_string()
            };

            if let Some((gateway_base, login_xml_url)) = resolve_login_target(&full_loc) {
                return ProbeResult::LockedPortal {
                    gateway_base,
                    login_xml_url,
                };
            }
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
    ProbeResult::ProbeTimeoutOrError(err_msg)
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
    if let Some(caps) = XML_MESSAGE_RE.captures(body)
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

    // 1. Explicit XML status failure checks
    if body_lower.contains("<status>fail</status>")
        || body_lower.contains("[cdata[fail]]")
        || body_lower.contains("<status>login</status>")
        || body_lower.contains("[cdata[login]]")
    {
        let msg = extracted_msg.unwrap_or_else(|| "Portal returned FAIL status".to_string());
        return Err(format!("Portal rejected login: {}", msg));
    }

    // 2. Failure keywords check (checked BEFORE success keywords)
    let failure_keywords = [
        "invalid username",
        "invalid user name",
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
        "not signed in",
        "keep me signed in",
        "stay signed in",
        "sign in to",
    ];

    for keyword in &failure_keywords {
        if body_lower.contains(keyword) {
            let msg = extracted_msg.unwrap_or_else(|| keyword.to_string());
            return Err(format!("Portal rejected login: {}", msg));
        }
    }

    let has_success_keyword = body_lower.contains("<status>live</status>")
        || body_lower.contains("[cdata[live]]")
        || body_lower.contains("you are signed in")
        || body_lower.contains("successfully logged in");

    // If XML message exists but body does not contain success keyword, treat as error
    if let Some(msg) = &extracted_msg
        && !has_success_keyword
    {
        return Err(format!("Portal rejected login: {}", msg));
    }

    // 3. Success keyword check
    if has_success_keyword {
        return Ok(extracted_msg.unwrap_or_else(|| "Authentication successful".to_string()));
    }

    // 4. Fallback matching main:src/main.rs (HTTP 200 | 301 | 302 | 303 for non-Sophos HTML portals)
    let is_sophos_xml = body_lower.contains("<requestresponse>") || body_lower.contains("<status>");
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

/// Authenticates to the captive portal with auto-retry to HTTPS if initial HTTP fails,
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
            // HTTPS upgrade retry only for http:// (never downgrade https:// to http://)
            if login_xml_url.starts_with("http://") {
                let https_url = login_xml_url.replacen("http://", "https://", 1);
                println!(
                    "Initial POST failed ({}), retrying with HTTPS: {}",
                    e, https_url
                );
                submit_login_post(client, &https_url, username, password)?
            } else {
                return Err(Box::new(e));
            }
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
    use std::sync::Mutex;

    static ENV_MUTEX: Mutex<()> = Mutex::new(());

    pub fn read_full_http_request(stream: &mut TcpStream) -> String {
        let _ = stream.set_nodelay(true);
        let mut data = Vec::new();
        let mut buf = [0u8; 1024];
        let mut content_length: Option<usize> = None;
        let mut header_len: Option<usize> = None;

        loop {
            let n = stream.read(&mut buf).unwrap_or(0);
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);

            if header_len.is_none()
                && let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n")
            {
                let h_end = pos + 4;
                header_len = Some(h_end);
                let header_str = String::from_utf8_lossy(&data[..h_end]);
                for line in header_str.lines() {
                    if let Some(idx) = line.find(':') {
                        let key = line[..idx].trim().to_lowercase();
                        if key == "content-length" {
                            content_length = line[idx + 1..].trim().parse::<usize>().ok();
                        }
                    }
                }
            }

            if let Some(h_end) = header_len {
                let required_total = h_end + content_length.unwrap_or(0);
                if data.len() >= required_total {
                    break;
                }
            }
        }

        String::from_utf8_lossy(&data).to_string()
    }

    fn spawn_mock_server(raw_response: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("Failed to bind mock listener");
        let port = listener.local_addr().unwrap().port();
        let url = format!("http://127.0.0.1:{port}/probe");
        let handle = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = read_full_http_request(&mut stream);
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

        // Non-Sophos root path: preserves "http://172.16.1.1/"
        let root_path = "http://172.16.1.1/";
        let root_result = resolve_login_target(root_path);
        assert_eq!(
            root_result,
            Some((
                "http://172.16.1.1".to_string(),
                "http://172.16.1.1/".to_string()
            ))
        );

        // Sophos port 8090 non-httpclient path resolves to /login.xml
        let sophos_non_client = "http://172.16.68.6:8090/index.html";
        let sophos_non_client_res = resolve_login_target(sophos_non_client);
        assert_eq!(
            sophos_non_client_res,
            Some((
                "http://172.16.68.6:8090".to_string(),
                "http://172.16.68.6:8090/login.xml".to_string()
            ))
        );
    }

    #[test]
    fn test_resolve_login_target_rejects_w3_doctype() {
        let html_with_doctype = r#"<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head><title>Test</title></head>
<body>Hello world</body>
</html>"#;
        assert_eq!(resolve_login_target(html_with_doctype), None);
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
        let body = "<html><body>You are signed in as testuser</body></html>";
        let res = validate_sophos_response(body);
        assert!(res.is_ok());
    }

    #[test]
    fn test_validate_portal_response_signed_in_false_positives() {
        // "You are not signed in" must be rejected
        let body1 = "<html><body>You are not signed in. Please log in.</body></html>";
        assert!(validate_sophos_response(body1).is_err());

        // "Keep me signed in" must be rejected
        let body2 = "<form><input type='checkbox'>Keep me signed in</form>";
        assert!(validate_sophos_response(body2).is_err());

        // "Stay signed in" must be rejected
        let body3 = "<html><body>Stay signed in to this network</body></html>";
        assert!(validate_sophos_response(body3).is_err());
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
        let _guard = ENV_MUTEX.lock().unwrap();
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
                let request = read_full_http_request(&mut stream);

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
                let request = read_full_http_request(&mut stream);

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
