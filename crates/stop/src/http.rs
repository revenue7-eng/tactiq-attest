//! Just enough HTTP/1.1 for agentgateway's `extAuthz` in `http` mode, on
//! loopback, with std only.
//!
//! The gateway treats a 2xx answer as allow, and any other answer, or no
//! answer, as deny (`failureMode: deny`, the default). It hands a 403 body to
//! the caller unchanged. So the mapping is:
//!
//!   running            -> 200, empty body
//!   stopped            -> 403, body = signed receipt
//!   anything went wrong -> 503, short text. Still a deny.
//!
//! One connection at a time, `Connection: close`. The service is asked once
//! per tool call; a tool call is not a high-rate event, and serial handling
//! also serialises TPM access inside the service.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Whole-request deadline, not a per-read timeout: a client that sends one
/// byte at a time cannot hold the (single) connection slot past this.
pub const REQUEST_DEADLINE: Duration = Duration::from_secs(3);
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(3);

/// Bounds on what the service reads. A request beyond them is refused, never
/// truncated: a truncated body would give a request digest of a different
/// request.
pub const HEAD_MAX: usize = 16 * 1024;
pub const BODY_MAX: usize = 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// Parse one request from raw bytes that hold at least the full head.
/// Returns the request and the number of bytes it occupied, or `Ok(None)`
/// when more bytes are needed.
pub fn parse(buf: &[u8]) -> Result<Option<(Request, usize)>, String> {
    let Some(head_end) = find(buf, b"\r\n\r\n") else {
        if buf.len() > HEAD_MAX {
            return Err(format!("request head over {HEAD_MAX} bytes"));
        }
        return Ok(None);
    };
    if head_end > HEAD_MAX {
        return Err(format!("request head over {HEAD_MAX} bytes"));
    }
    let head = std::str::from_utf8(&buf[..head_end]).map_err(|_| "request head is not UTF-8")?;
    let mut lines = head.split("\r\n");
    let line = lines.next().ok_or("empty request")?;
    let mut parts = line.split(' ');
    let (method, path, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(p), Some(v), None) => (m, p, v),
        _ => return Err(format!("bad request line {line:?}")),
    };
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(format!("unsupported version {version:?}"));
    }
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(format!("bad method {method:?}"));
    }
    let mut length: Option<usize> = None;
    for l in lines {
        let (k, v) = l.split_once(':').ok_or_else(|| format!("bad header line {l:?}"))?;
        // No whitespace inside or around the name (RFC 9112 5.1): a space
        // before the colon is how one parser's header becomes another's body.
        if k.is_empty() || !k.bytes().all(|b| b.is_ascii_graphic()) {
            return Err(format!("bad header name {k:?}"));
        }
        let v = v.trim_matches(|c| c == ' ' || c == '\t');
        if k.eq_ignore_ascii_case("transfer-encoding") {
            return Err("chunked or other transfer encodings are not accepted".into());
        }
        if k.eq_ignore_ascii_case("content-length") {
            // Plain digits only: Rust's parser would also take "+5".
            if v.is_empty() || v.len() > 8 || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("bad content-length {v:?}"));
            }
            let n: usize = v.parse().map_err(|_| format!("bad content-length {v:?}"))?;
            if length.is_some_and(|m| m != n) {
                return Err("conflicting content-length headers".into());
            }
            length = Some(n);
        }
    }
    let n = length.unwrap_or(0);
    if n > BODY_MAX {
        return Err(format!("body of {n} bytes over {BODY_MAX}"));
    }
    let start = head_end + 4;
    if buf.len() < start + n {
        return Ok(None);
    }
    Ok(Some((
        Request { method: method.into(), path: path.into(), body: buf[start..start + n].to_vec() },
        start + n,
    )))
}

fn find(h: &[u8], n: &[u8]) -> Option<usize> {
    h.windows(n.len()).position(|w| w == n)
}

/// Read one request from the stream, within `REQUEST_DEADLINE` in total.
/// Bytes after the request are refused: the service answers one request per
/// connection and does not guess what a second one was meant to be.
pub fn read_request(s: &mut TcpStream) -> Result<Request, String> {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    s.set_write_timeout(Some(WRITE_TIMEOUT)).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if let Some((req, used)) = parse(&buf)? {
            if used != buf.len() {
                return Err(format!("{} bytes after the request", buf.len() - used));
            }
            return Ok(req);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("request not complete within the deadline".into());
        }
        s.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
        let k = s.read(&mut chunk).map_err(|e| format!("read: {e}"))?;
        if k == 0 {
            return Err("connection closed before the request was complete".into());
        }
        buf.extend_from_slice(&chunk[..k]);
        if buf.len() > HEAD_MAX + BODY_MAX + 4 {
            return Err("request too large".into());
        }
    }
}

/// Write a complete response and close.
pub fn respond(s: &mut TcpStream, code: u16, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        _ => "Service Unavailable",
    };
    let head = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body)?;
    s.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_request_with_a_body() {
        let raw = b"POST /mcp HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}";
        let (r, used) = parse(raw).unwrap().unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str(), r.body.as_slice()), ("POST", "/mcp", b"{}".as_slice()));
        assert_eq!(used, raw.len());
    }

    #[test]
    fn waits_for_the_rest_of_the_body() {
        assert_eq!(parse(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nab").unwrap(), None);
        assert_eq!(parse(b"POST / HTTP/1.1\r\nContent-Le").unwrap(), None);
    }

    #[test]
    fn no_content_length_means_no_body() {
        let (r, _) = parse(b"GET /check HTTP/1.1\r\n\r\n").unwrap().unwrap();
        assert!(r.body.is_empty());
    }

    #[test]
    fn refuses_what_would_change_the_digest_silently() {
        assert!(parse(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").is_err());
        assert!(parse(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab").is_err());
        let big = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", BODY_MAX + 1);
        assert!(parse(big.as_bytes()).is_err());
    }

    #[test]
    fn content_length_is_plain_digits_and_names_have_no_spaces() {
        assert!(parse(b"POST / HTTP/1.1\r\nContent-Length: +2\r\n\r\nab").is_err());
        assert!(parse(b"POST / HTTP/1.1\r\nContent-Length: -0\r\n\r\n").is_err());
        assert!(parse(b"POST / HTTP/1.1\r\nContent-Length : 2\r\n\r\nab").is_err());
        assert!(parse(b"POST / HTTP/1.1\r\nContent-Length: 2 2\r\n\r\nab").is_err());
        let (r, _) = parse(b"POST / HTTP/1.1\r\nContent-Length:\t2 \r\n\r\nab").unwrap().unwrap();
        assert_eq!(r.body, b"ab");
    }

    #[test]
    fn refuses_malformed_heads() {
        assert!(parse(b"post / HTTP/1.1\r\n\r\n").is_err());
        assert!(parse(b"GET / HTTP/2\r\n\r\n").is_err());
        assert!(parse(b"GET /  HTTP/1.1\r\n\r\n").is_err());
        assert!(parse(b"GET / HTTP/1.1\r\nno-colon\r\n\r\n").is_err());
        assert!(parse(&vec![b'a'; HEAD_MAX + 1]).is_err());
    }
}
