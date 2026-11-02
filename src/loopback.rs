//! A loopback HTTP server for the offline unit tests: std only, no mocking
//! library (the sofi-cli fake-server pattern). A test points a client at it
//! with an explicit base URL (`Wf::with_base`, `Wf::from_bundle_at`), never
//! with `WFR_BASE_URL`, which every test in the process shares.

use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// How long the server waits for a connection it was told to expect, so a
/// client that never connects fails its test instead of hanging the suite.
const ACCEPT_DEADLINE: Duration = Duration::from_secs(10);

/// Serve up to `connections` connections on 127.0.0.1, one request each,
/// answering each request with what `respond` returns for its text.
///
/// Returns the base URL and a handle that yields every request's text, in
/// the order they arrived, once the last expected connection is served or
/// the wait for one runs out.
pub(crate) fn serve<F>(connections: usize, respond: F) -> (String, JoinHandle<Vec<String>>)
where
    F: Fn(&str) -> String + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).expect("non-blocking accept");
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = Instant::now() + ACCEPT_DEADLINE;
        while requests.len() < connections {
            let mut stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(_) => break,
            };
            // An accepted socket inherits the listener's non-blocking flag on
            // some platforms (macOS among them).
            let _ = stream.set_nonblocking(false);
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let req = read_request(&mut stream);
            let _ = stream.write_all(respond(&req).as_bytes());
            requests.push(req);
        }
        requests
    });
    (format!("http://127.0.0.1:{port}"), handle)
}

/// Read until the full request is in: headers, then, if a Content-Length is
/// declared, that many body bytes (the body often arrives in a second TCP
/// segment on loopback).
fn read_request(stream: &mut TcpStream) -> String {
    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let text = String::from_utf8_lossy(&raw);
        if let Some(head_end) = text.find("\r\n\r\n") {
            let want: usize = text
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length:")
                        .map(|v| v.trim().parse().unwrap_or(0))
                })
                .unwrap_or(0);
            if raw.len() >= head_end + 4 + want {
                break;
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
        }
    }
    String::from_utf8_lossy(&raw).into_owned()
}

/// A complete response that closes its connection: `status` is the status
/// line's code and reason (`"200 OK"`), `headers` any extra header lines.
pub(crate) fn response(status: &str, headers: &[&str], body: &str) -> String {
    let mut out = format!("HTTP/1.1 {status}\r\n");
    for header in headers {
        out.push_str(header);
        out.push_str("\r\n");
    }
    out.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    ));
    out
}

/// The value of the request header `name`, matched case-insensitively.
pub(crate) fn header<'a>(request: &'a str, name: &str) -> Option<&'a str> {
    request
        .split("\r\n\r\n")
        .next()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let (n, v) = line.split_once(':')?;
            n.trim().eq_ignore_ascii_case(name).then(|| v.trim())
        })
}
