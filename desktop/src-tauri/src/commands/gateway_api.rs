use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tauri::Emitter;

use crate::commands::lifecycle::desktop_defenseclaw_home;

const DEFAULT_GATEWAY_PORT: u16 = 18_970;
const DEFAULT_GATEWAY_TOKEN: &str = "defenseclaw-desktop-agentrange-token";

pub(crate) fn get_json<T: DeserializeOwned>(
    app: &tauri::AppHandle,
    path: &str,
) -> Result<T, String> {
    let home = desktop_defenseclaw_home(app)?;
    let token = gateway_token(&home).unwrap_or_else(|| DEFAULT_GATEWAY_TOKEN.to_owned());
    let port = gateway_port(&home).unwrap_or(DEFAULT_GATEWAY_PORT);
    let body = request_bytes("GET", port, path, &token, None)?;

    serde_json::from_slice(&body).map_err(|error| format!("parse gateway response: {error}"))
}

pub(crate) fn delete_json<T: DeserializeOwned>(
    app: &tauri::AppHandle,
    path: &str,
) -> Result<T, String> {
    let home = desktop_defenseclaw_home(app)?;
    let token = gateway_token(&home).unwrap_or_else(|| DEFAULT_GATEWAY_TOKEN.to_owned());
    let port = gateway_port(&home).unwrap_or(DEFAULT_GATEWAY_PORT);
    let body = request_bytes("DELETE", port, path, &token, None)?;

    serde_json::from_slice(&body).map_err(|error| format!("parse gateway response: {error}"))
}

pub(crate) fn put_json<T, B>(app: &tauri::AppHandle, path: &str, body: &B) -> Result<T, String>
where
    T: DeserializeOwned,
    B: Serialize + ?Sized,
{
    request_with_body::<T, B>(app, "PUT", path, body)
}

pub(crate) fn patch_json<T, B>(app: &tauri::AppHandle, path: &str, body: &B) -> Result<T, String>
where
    T: DeserializeOwned,
    B: Serialize + ?Sized,
{
    request_with_body::<T, B>(app, "PATCH", path, body)
}

pub(crate) fn post_json<T, B>(app: &tauri::AppHandle, path: &str, body: &B) -> Result<T, String>
where
    T: DeserializeOwned,
    B: Serialize + ?Sized,
{
    request_with_body::<T, B>(app, "POST", path, body)
}

fn request_with_body<T, B>(
    app: &tauri::AppHandle,
    method: &str,
    path: &str,
    body: &B,
) -> Result<T, String>
where
    T: DeserializeOwned,
    B: Serialize + ?Sized,
{
    let home = desktop_defenseclaw_home(app)?;
    let token = gateway_token(&home).unwrap_or_else(|| DEFAULT_GATEWAY_TOKEN.to_owned());
    let port = gateway_port(&home).unwrap_or(DEFAULT_GATEWAY_PORT);
    let payload =
        serde_json::to_vec(body).map_err(|error| format!("serialize gateway request: {error}"))?;
    let body = request_bytes(method, port, path, &token, Some(&payload))?;

    serde_json::from_slice(&body).map_err(|error| format!("parse gateway response: {error}"))
}

fn request_bytes(
    method: &str,
    port: u16,
    path: &str,
    token: &str,
    body: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(900))
        .map_err(|error| format!("connect gateway 127.0.0.1:{port}: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("configure gateway read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("configure gateway write timeout: {error}"))?;

    let normalized_path = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    let payload = body.unwrap_or_default();
    let mut request = format!(
        "{method} {normalized_path} HTTP/1.1\r\n\
         Host: 127.0.0.1:{port}\r\n\
         Authorization: Bearer {token}\r\n\
         X-DefenseClaw-Client: defenseclaw-desktop\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n"
    );
    if body.is_some() {
        request.push_str("Content-Type: application/json\r\n");
        request.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .and_then(|_| {
            if payload.is_empty() {
                Ok(())
            } else {
                stream.write_all(payload)
            }
        })
        .map_err(|error| format!("send gateway request: {error}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|error| format!("read gateway response: {error}"))?;

    parse_http_response(&response)
}

/// Run the desktop's resumable SSE subscription on a worker thread. The
/// Gateway carries only invalidation cursors; page code still fetches the
/// authoritative read model after each event.
pub(crate) fn stream_change_events(
    app: tauri::AppHandle,
    stop: Arc<AtomicBool>,
    mut cursor: i64,
    domains: Vec<String>,
) {
    let home = match desktop_defenseclaw_home(&app) {
        Ok(home) => home,
        Err(_) => return,
    };
    let token = gateway_token(&home).unwrap_or_else(|| DEFAULT_GATEWAY_TOKEN.to_owned());
    let port = gateway_port(&home).unwrap_or(DEFAULT_GATEWAY_PORT);
    let domain_query = encode_query_value(&domains.join(","));
    let path = format!("/api/v1/stream?domains={domain_query}");

    while !stop.load(Ordering::Relaxed) {
        match connect_change_stream(port, &path, &token, cursor, &stop, &app) {
            Ok(next_cursor) => cursor = cursor.max(next_cursor),
            Err(_) => {}
        }
        // Reconnect with a bounded delay. Check cancellation in short slices
        // so navigating away from a page closes the subscriber promptly.
        for _ in 0..20 {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

fn connect_change_stream(
    port: u16,
    path: &str,
    token: &str,
    cursor: i64,
    stop: &AtomicBool,
    app: &tauri::AppHandle,
) -> Result<i64, String> {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(900))
        .map_err(|error| format!("connect gateway stream: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .map_err(|error| format!("configure gateway stream timeout: {error}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|error| format!("configure gateway stream write timeout: {error}"))?;
    let mut request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nX-DefenseClaw-Client: defenseclaw-desktop\r\nAccept: text/event-stream\r\nConnection: keep-alive\r\n"
    );
    if cursor > 0 {
        request.push_str(&format!("Last-Event-ID: {cursor}\r\n"));
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .map_err(|error| format!("send gateway stream request: {error}"))?;

    let mut wire = Vec::<u8>::new();
    let mut headers_read = false;
    let mut chunked = false;
    let mut sse = Vec::<u8>::new();
    let mut latest = cursor;
    let mut read_buf = [0u8; 8192];

    while !stop.load(Ordering::Relaxed) {
        match stream.read(&mut read_buf) {
            Ok(0) => return Ok(latest),
            Ok(count) => wire.extend_from_slice(&read_buf[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(format!("read gateway stream: {error}")),
        }

        if !headers_read {
            let Some(header_end) = find_bytes(&wire, b"\r\n\r\n") else {
                continue;
            };
            let header_text = String::from_utf8_lossy(&wire[..header_end]);
            let mut lines = header_text.lines();
            let status = lines
                .next()
                .and_then(|line| line.split_whitespace().nth(1))
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or_else(|| "Gateway stream returned an invalid status line".to_owned())?;
            if !(200..300).contains(&status) {
                return Err(format!("Gateway stream returned HTTP {status}"));
            }
            chunked = lines.any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.trim().eq_ignore_ascii_case("transfer-encoding")
                        && value.to_ascii_lowercase().contains("chunked")
                })
            });
            wire.drain(..header_end + 4);
            headers_read = true;
        }

        let body_chunks = if chunked {
            take_http_chunks(&mut wire)?
        } else {
            if wire.is_empty() {
                Vec::new()
            } else {
                vec![std::mem::take(&mut wire)]
            }
        };
        for body in body_chunks {
            sse.extend_from_slice(&body);
            while let Some((event, consumed)) = take_sse_event(&sse) {
                sse.drain(..consumed);
                if event.event != "change" || event.data.is_empty() {
                    continue;
                }
                let payload: serde_json::Value = match serde_json::from_str(&event.data) {
                    Ok(payload) => payload,
                    Err(_) => continue,
                };
                if let Some(value) = payload.get("next_cursor").and_then(|value| value.as_i64()) {
                    latest = latest.max(value);
                } else if let Ok(value) = event.id.parse::<i64>() {
                    latest = latest.max(value);
                }
                let _ = app.emit("gateway-change", payload);
            }
        }
    }
    Ok(latest)
}

struct SseEvent {
    id: String,
    event: String,
    data: String,
}

fn take_sse_event(buffer: &[u8]) -> Option<(SseEvent, usize)> {
    let normalized = String::from_utf8_lossy(buffer).replace("\r\n", "\n");
    let end = normalized.find("\n\n")?;
    let event_text = &normalized[..end];
    let lf_end = buffer
        .windows(2)
        .position(|window| window == b"\n\n")
        .map(|position| position + 2);
    let crlf_end = buffer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4);
    let consumed = match (lf_end, crlf_end) {
        (Some(lf), Some(crlf)) => lf.min(crlf),
        (Some(lf), None) => lf,
        (None, Some(crlf)) => crlf,
        (None, None) => return None,
    };
    let mut event = SseEvent {
        id: String::new(),
        event: String::new(),
        data: String::new(),
    };
    for line in event_text.lines() {
        if line.starts_with(':') {
            continue;
        }
        if let Some((name, value)) = line.split_once(':') {
            let value = value.strip_prefix(' ').unwrap_or(value);
            match name {
                "id" => event.id = value.to_owned(),
                "event" => event.event = value.to_owned(),
                "data" => {
                    if !event.data.is_empty() {
                        event.data.push('\n');
                    }
                    event.data.push_str(value);
                }
                _ => {}
            }
        }
    }
    Some((event, consumed))
}

fn take_http_chunks(wire: &mut Vec<u8>) -> Result<Vec<Vec<u8>>, String> {
    let mut chunks = Vec::new();
    loop {
        let Some(line_end) = find_bytes(wire, b"\r\n") else {
            break;
        };
        let size_text = std::str::from_utf8(&wire[..line_end])
            .map_err(|error| format!("invalid HTTP chunk header: {error}"))?
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|error| format!("invalid HTTP chunk size: {error}"))?;
        if wire.len() < line_end + 2 + size + 2 {
            break;
        }
        let start = line_end + 2;
        if size == 0 {
            wire.drain(..start + 2);
            break;
        }
        chunks.push(wire[start..start + size].to_vec());
        wire.drain(..start + size + 2);
    }
    Ok(chunks)
}

fn parse_http_response(response: &[u8]) -> Result<Vec<u8>, String> {
    let header_end = find_bytes(response, b"\r\n\r\n")
        .ok_or_else(|| "gateway returned malformed HTTP response".to_owned())?;
    let header_text = String::from_utf8_lossy(&response[..header_end]);
    let mut lines = header_text.lines();
    let status_line = lines
        .next()
        .ok_or_else(|| "gateway response missing status line".to_owned())?;
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|part| part.parse::<u16>().ok())
        .ok_or_else(|| format!("gateway response has invalid status line: {status_line}"))?;

    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    let body = &response[header_end + 4..];
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };

    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&body).trim().to_owned();
        return Err(if text.is_empty() {
            format!("gateway returned HTTP {status}")
        } else {
            format!("gateway returned HTTP {status}: {text}")
        });
    }

    Ok(body)
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    let mut offset = 0usize;

    loop {
        let line_end = find_bytes_from(body, b"\r\n", offset)
            .ok_or_else(|| "gateway returned malformed chunked response".to_owned())?;
        let line = std::str::from_utf8(&body[offset..line_end])
            .map_err(|error| format!("parse chunk header: {error}"))?;
        let size_text = line.split(';').next().unwrap_or_default().trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|error| format!("parse chunk size '{size_text}': {error}"))?;
        offset = line_end + 2;

        if size == 0 {
            break;
        }
        if offset + size > body.len() {
            return Err("gateway chunk body is incomplete".to_owned());
        }
        output.extend_from_slice(&body[offset..offset + size]);
        offset += size;
        if body.get(offset..offset + 2) == Some(b"\r\n") {
            offset += 2;
        }
    }

    Ok(output)
}

#[cfg(test)]
mod change_stream_tests {
    use super::{take_http_chunks, take_sse_event};

    #[test]
    fn decodes_complete_chunks_and_keeps_partial_chunk_for_next_read() {
        let mut wire = b"6\r\nevent:\r\n7\r\n change\r\n0\r\n\r\n".to_vec();
        let chunks = take_http_chunks(&mut wire).expect("decode chunks");
        assert_eq!(chunks, vec![b"event:".to_vec(), b" change".to_vec()]);
        assert!(wire.is_empty());

        let mut partial = b"5\r\nabc".to_vec();
        assert!(take_http_chunks(&mut partial)
            .expect("decode partial")
            .is_empty());
        partial.extend_from_slice(b"de\r\n");
        assert_eq!(
            take_http_chunks(&mut partial).expect("complete chunk"),
            vec![b"abcde".to_vec()]
        );
    }

    #[test]
    fn parses_sse_fields_from_crlf_frame_without_consuming_next_frame() {
        let mut wire: &[u8] = b"id: 42\r\nevent: change\r\ndata: {\"next_cursor\":42}\r\n\r\nid: 43\nevent: change\ndata: {}\n\n";
        let (event, consumed) = take_sse_event(wire).expect("first event");
        assert_eq!(event.id, "42");
        assert_eq!(event.event, "change");
        assert_eq!(event.data, "{\"next_cursor\":42}");
        wire = &wire[consumed..];
        assert!(
            wire.starts_with(b"id: 43\n"),
            "unexpected buffered tail: {:?}",
            String::from_utf8_lossy(wire)
        );
        let (next, _) = take_sse_event(wire).expect("second event remains buffered");
        assert_eq!(next.id, "43");
    }
}

fn gateway_token(home: &std::path::Path) -> Option<String> {
    let env_text = fs::read_to_string(home.join(".env")).ok()?;
    env_text.lines().find_map(|line| {
        let line = line.trim().strip_prefix("export ").unwrap_or(line.trim());
        let (key, value) = line.split_once('=')?;
        if key.trim() != "DEFENSECLAW_GATEWAY_TOKEN" {
            return None;
        }
        let value = value.trim().trim_matches('"').trim_matches('\'');
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn gateway_port(home: &std::path::Path) -> Option<u16> {
    let config_text = fs::read_to_string(home.join("config.yaml")).ok()?;
    config_text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "api_port" {
            return None;
        }
        value.trim().parse::<u16>().ok()
    })
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    find_bytes_from(haystack, needle, 0)
}

fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

fn find_bytes_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() || start > haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| start + position)
}
