use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::models::{TracePolicy, TraceSnapshot};

const DEFAULT_GATEWAY_PORT: u16 = 18_970;
const DEFAULT_GATEWAY_TOKEN: &str = "defenseclaw-desktop-agentrange-token";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NewTraceEvent<'a> {
    pub event_type: &'a str,
    pub source: &'a str,
    pub agent_pid: u32,
    pub agent_executable: &'a str,
    pub actor_pid: u32,
    pub actor_executable: &'a str,
    pub path: Option<&'a str>,
    pub action: Option<&'a str>,
    pub outcome: &'a str,
    pub detail: &'a str,
}

#[derive(Deserialize)]
struct GatewayClientManifest {
    host: Option<String>,
    port: Option<u16>,
    token: Option<String>,
}

pub fn default_database_path() -> PathBuf {
    crate::process_guard_service::gateway_client_manifest_path()
}

pub fn append(_path: &Path, event: &NewTraceEvent<'_>) -> Result<(), String> {
    let body =
        serde_json::to_vec(event).map_err(|error| format!("serialize behavior event: {error}"))?;
    // Behavior capture must not break process/file enforcement if the gateway
    // is temporarily down. The backend is the only durable store; this client
    // is intentionally best-effort.
    let _ = request("POST", "/api/v1/behavior-events", Some(&body));
    Ok(())
}

pub fn snapshot(limit: usize) -> Result<TraceSnapshot, String> {
    let body = request(
        "GET",
        &format!("/api/v1/behavior-events?limit={}", limit.clamp(1, 1000)),
        None,
    )?;
    serde_json::from_slice(&body).map_err(|error| format!("parse behavior event snapshot: {error}"))
}

pub fn enforce_retention(_path: &Path, policy: &TracePolicy) -> Result<(), String> {
    let max_rows = u32::from(policy.max_database_mb)
        .saturating_mul(1000)
        .max(1000);
    let path = format!(
        "/api/v1/behavior-events?retentionDays={}&maxRows={max_rows}",
        policy.retention_days
    );
    let _ = request("DELETE", &path, None);
    Ok(())
}

fn request(method: &str, path: &str, body: Option<&[u8]>) -> Result<Vec<u8>, String> {
    let config = gateway_config();
    let addr = SocketAddr::from(([127, 0, 0, 1], config.port));
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_millis(900))
        .map_err(|error| format!("connect gateway 127.0.0.1:{}: {error}", config.port))?;
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
         Host: {}:{}\r\n\
         Authorization: Bearer {}\r\n\
         X-DefenseClaw-Client: defenseclaw-desktop-behavior\r\n\
         Accept: application/json\r\n\
         Connection: close\r\n",
        config.host, config.port, config.token
    );
    if body.is_some() || method != "GET" {
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

struct GatewayConfig {
    host: String,
    port: u16,
    token: String,
}

fn gateway_config() -> GatewayConfig {
    if let Ok(manifest) =
        fs::read_to_string(crate::process_guard_service::gateway_client_manifest_path())
    {
        if let Ok(parsed) = serde_json::from_str::<GatewayClientManifest>(&manifest) {
            return GatewayConfig {
                host: parsed.host.unwrap_or_else(|| "127.0.0.1".to_owned()),
                port: parsed.port.unwrap_or(DEFAULT_GATEWAY_PORT),
                token: parsed
                    .token
                    .unwrap_or_else(|| DEFAULT_GATEWAY_TOKEN.to_owned()),
            };
        }
    }
    if let Ok(home) = std::env::var("DEFENSECLAW_HOME") {
        let home = PathBuf::from(home);
        return GatewayConfig {
            host: "127.0.0.1".to_owned(),
            port: gateway_port(&home).unwrap_or(DEFAULT_GATEWAY_PORT),
            token: gateway_token(&home).unwrap_or_else(|| DEFAULT_GATEWAY_TOKEN.to_owned()),
        };
    }
    if let Some(appdata) = std::env::var_os("APPDATA") {
        let home = PathBuf::from(appdata)
            .join("dev.defenseclaw.desktop")
            .join("defenseclaw-home");
        return GatewayConfig {
            host: "127.0.0.1".to_owned(),
            port: gateway_port(&home).unwrap_or(DEFAULT_GATEWAY_PORT),
            token: gateway_token(&home).unwrap_or_else(|| DEFAULT_GATEWAY_TOKEN.to_owned()),
        };
    }
    GatewayConfig {
        host: "127.0.0.1".to_owned(),
        port: DEFAULT_GATEWAY_PORT,
        token: DEFAULT_GATEWAY_TOKEN.to_owned(),
    }
}

fn gateway_token(home: &Path) -> Option<String> {
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

fn gateway_port(home: &Path) -> Option<u16> {
    let config_text = fs::read_to_string(home.join("config.yaml")).ok()?;
    config_text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        if key.trim() != "api_port" {
            return None;
        }
        value.trim().parse::<u16>().ok()
    })
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
