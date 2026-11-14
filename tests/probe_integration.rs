use ccp::probe::{ProbeResult, build_fast_client, extract_gateway_base, probe_url};
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
fn test_integration_firefox_probe_online() {
    let (url, handle) = spawn_mock_server(
        "HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nsuccess\n",
    );
    let client = build_fast_client(false).expect("Client build failed");
    let result = probe_url(&client, &url, None);
    handle.join().unwrap();
    assert_eq!(result, ProbeResult::OnlineUnlocked);
}

#[test]
fn test_integration_firefox_probe_302_redirect() {
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
fn test_integration_firefox_probe_html_js_redirect() {
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
fn test_integration_extract_gateway_base() {
    let text = "<form action=\"http://172.16.68.6:8090/login.xml\" method=\"post\">";
    let base = extract_gateway_base(text);
    assert_eq!(base, Some("http://172.16.68.6:8090".to_string()));
}
