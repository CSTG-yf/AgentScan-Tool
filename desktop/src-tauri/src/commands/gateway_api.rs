use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;

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

fn find_bytes_from(haystack: &[u8], needle: &[u8], start: usize) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() || start > haystack.len() {
        return None;
    }
    haystack[start..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|position| start + position)
}
