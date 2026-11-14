use reqwest::blocking::Client;
use reqwest::header::{CACHE_CONTROL, CONNECTION, PRAGMA, USER_AGENT};
use reqwest::redirect::Policy;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
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

            if let Some(fb) = fallback_gateway {
                let gateway_base = normalize_gateway_base(fb);
                let login_xml_url = format!("{}/login.xml", gateway_base.trim_end_matches('/'));
                ProbeResult::LockedPortal {
                    gateway_base,
                    login_xml_url,
                }
            } else {
                ProbeResult::ProbeTimeoutOrError(primary_err.to_string())
            }
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

    if let Some(fb) = fallback_gateway {
        let gateway_base = normalize_gateway_base(fb);
        let login_xml_url = format!("{}/login.xml", gateway_base.trim_end_matches('/'));
        ProbeResult::LockedPortal {
            gateway_base,
            login_xml_url,
        }
    } else {
        ProbeResult::ProbeTimeoutOrError(format!(
            "Portal intercepted request (status {}) but gateway URL could not be resolved",
            status
        ))
    }
}

/// Executes dynamic gateway discovery according to Firefox CaptiveDetect specifications
pub fn probe_network(client: &Client, fallback_gateway: Option<&str>) -> ProbeResult {
    if current_local_ipv4().is_none() {
        return ProbeResult::InterfaceOffline;
    }
    probe_url(client, FIREFOX_SUCCESS_URL, fallback_gateway)
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
                let mut buf = [0u8; 1024];
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
        // Test that current_local_ipv4 executes cleanly without panics
        let _ = current_local_ipv4();
    }
}
