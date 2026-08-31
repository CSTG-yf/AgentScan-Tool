use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;
use serde::Serialize;

const MAX_FILES: usize = 5_000;
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DEPTH: usize = 10;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticScanSnapshot {
    captured_at: String,
    root: String,
    assets: Vec<StaticScanAsset>,
    findings: Vec<StaticScanFinding>,
    scanned_files: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticScanAsset {
    id: String,
    name: String,
    kind: String,
    category: String,
    path: String,
    risk: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticScanFinding {
    id: String,
    rule_id: &'static str,
    title: &'static str,
    category: &'static str,
    severity: &'static str,
    path: String,
    line: usize,
    evidence: String,
}

struct Rule {
    id: &'static str,
    title: &'static str,
    category: &'static str,
    severity: &'static str,
    patterns: &'static [&'static str],
}

const RULES: &[Rule] = &[
    Rule {
        id: "AR-STATIC-HIDDEN-INSTRUCTION",
        title: "隐藏或禁止披露的 Agent 指令",
        category: "提示词注入",
        severity: "high",
        patterns: &[
            "<important>",
            "ignore previous instructions",
            "不要向用户提及",
            "不得告知",
            "先读取",
        ],
    },
    Rule {
        id: "AR-STATIC-HIDDEN-TOOL",
        title: "未公开的可调用 MCP 工具",
        category: "供应链欺骗",
        severity: "critical",
        patterns: &["hidden=true"],
    },
    Rule {
        id: "AR-STATIC-STARTUP-BEACON",
        title: "组件启动时主动向外发送数据",
        category: "数据外传",
        severity: "critical",
        patterns: &["on_start=send_startup_beacon", "c2_url"],
    },
    Rule {
        id: "AR-STATIC-SHELL-TRUE",
        title: "不可信输入进入 shell 子进程",
        category: "命令执行",
        severity: "critical",
        patterns: &["shell=true"],
    },
    Rule {
        id: "AR-STATIC-ARBITRARY-FILE",
        title: "调用方可控路径被直接读取",
        category: "敏感文件访问",
        severity: "high",
        patterns: &["def read_file(path", "with open(path"],
    },
    Rule {
        id: "AR-CONFIG-WEAK-JWT",
        title: "弱 JWT 签名密钥",
        category: "弱认证",
        severity: "high",
        patterns: &[
            "jwt_secret=change-me-weak-secret",
            "jwt_secret: change-me-weak-secret",
        ],
    },
    Rule {
        id: "AR-CONFIG-SERVICE-ACCOUNT",
        title: "使用过宽的服务身份",
        category: "权限混淆",
        severity: "high",
        patterns: &[
            "opspilot_propagation=service-account",
            "opspilot_service_token=svc-root-all-access",
        ],
    },
    Rule {
        id: "AR-CONFIG-PLAINTEXT-PASSWORD",
        title: "配置中存在明文服务密码",
        category: "明文凭据",
        severity: "medium",
        patterns: &[
            "postgres_password=opspilot",
            "langflow_superuser_password=admin",
        ],
    },
    Rule {
        id: "AR-CONFIG-LANGFLOW-AUTOLOGIN",
        title: "Langflow 自动登录已启用",
        category: "认证绕过",
        severity: "medium",
        patterns: &[
            "langflow_auto_login: \"true\"",
            "langflow_skip_auth_auto_login: \"true\"",
        ],
    },
];

fn is_scan_file(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "py" | "md" | "yaml" | "yml" | "env" | "example" | "json" | "toml" | "sql"
    ) || matches!(name, "Dockerfile" | "SKILL.md")
}

fn classify(path: &Path) -> Option<(&'static str, &'static str)> {
    let normalized = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    let name = path.file_name()?.to_str()?;
    if name.eq_ignore_ascii_case("SKILL.md")
        || normalized.starts_with("skills/")
        || normalized.contains("/skills/")
    {
        Some(("Skill", "Skills"))
    } else if normalized.starts_with("mcp/")
        || normalized.contains("/mcp/")
        || normalized.contains("mcp-")
        || normalized.contains("mcp_")
    {
        Some(("MCP 服务", "MCP Servers"))
    } else if name.eq_ignore_ascii_case("Dockerfile")
        || normalized.ends_with("docker-compose.yml")
        || normalized.ends_with("docker-compose.yaml")
    {
        Some(("运行配置", "配置与运行环境"))
    } else if name.starts_with(".env")
        || normalized.ends_with("config.toml")
        || normalized.ends_with("config.yaml")
        || normalized.ends_with("config.yml")
    {
        Some(("安全配置", "配置与密钥"))
    } else if normalized.contains("opspilot")
        || normalized.contains("langflow")
        || normalized.contains("llm-stub")
    {
        Some(("Agent 源文件", "Agent 与模型"))
    } else {
        None
    }
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn visit(directory: &Path, depth: usize, files: &mut Vec<PathBuf>) {
    if depth > MAX_DEPTH || files.len() >= MAX_FILES {
        return;
    }
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        if files.len() >= MAX_FILES {
            break;
        }
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name == ".git" || name == "node_modules" || name == "__pycache__" || name == "target" {
            continue;
        }
        if path.is_dir() {
            visit(&path, depth + 1, files);
        } else if is_scan_file(&path) {
            files.push(path);
        }
    }
}

#[tauri::command]
pub fn get_static_scan(app: tauri::AppHandle) -> Result<StaticScanSnapshot, String> {
    let Some(root) = super::range::configured_root(&app) else {
        return Ok(StaticScanSnapshot {
            captured_at: Utc::now().to_rfc3339(),
            root: String::new(),
            assets: Vec::new(),
            findings: Vec::new(),
            scanned_files: 0,
            warning: Some("请先在验证靶场页面配置 AgentRange-player 目录".to_owned()),
        });
    };
    if !root.is_dir() {
        return Ok(StaticScanSnapshot {
            captured_at: Utc::now().to_rfc3339(),
            root: root.display().to_string(),
            assets: Vec::new(),
            findings: Vec::new(),
            scanned_files: 0,
            warning: Some("配置的靶场目录不存在".to_owned()),
        });
    }

    let mut files = Vec::new();
    visit(&root, 0, &mut files);
    let mut assets = Vec::new();
    let mut findings = Vec::new();
    let mut seen_assets = HashSet::new();

    for path in &files {
        let Ok(metadata) = path.metadata() else {
            continue;
        };
        if metadata.len() > MAX_FILE_BYTES {
            continue;
        }
        let relative = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let content = fs::read_to_string(path).unwrap_or_default();
        let mut file_risk = "info";
        for (line_index, line) in content.lines().enumerate() {
            let lowered = line.to_ascii_lowercase().replace(' ', "");
            for rule in RULES {
                if rule
                    .patterns
                    .iter()
                    .any(|pattern| lowered.contains(&pattern.to_ascii_lowercase().replace(' ', "")))
                {
                    if severity_rank(rule.severity) > severity_rank(file_risk) {
                        file_risk = rule.severity;
                    }
                    findings.push(StaticScanFinding {
                        id: format!("{}:{}:{}", rule.id, relative, line_index + 1),
                        rule_id: rule.id,
                        title: rule.title,
                        category: rule.category,
                        severity: rule.severity,
                        path: relative.clone(),
                        line: line_index + 1,
                        evidence: line.trim().chars().take(240).collect(),
                    });
                }
            }
        }
        if let Some((kind, category)) = classify(Path::new(&relative)) {
            if seen_assets.insert(relative.clone()) {
                assets.push(StaticScanAsset {
                    id: relative.clone(),
                    name: path
                        .file_name()
                        .and_then(|value| value.to_str())
                        .unwrap_or(&relative)
                        .to_owned(),
                    kind: kind.to_owned(),
                    category: category.to_owned(),
                    path: relative,
                    risk: file_risk.to_owned(),
                });
            }
        }
    }
    assets.sort_by(|left, right| left.path.cmp(&right.path));
    findings.sort_by(|left, right| {
        severity_rank(right.severity)
            .cmp(&severity_rank(left.severity))
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.line.cmp(&right.line))
    });
    let warning = (files.len() >= MAX_FILES)
        .then(|| format!("扫描达到 {MAX_FILES} 个文件上限，结果可能不完整"));
    Ok(StaticScanSnapshot {
        captured_at: Utc::now().to_rfc3339(),
        root: root.display().to_string(),
        assets,
        findings,
        scanned_files: files.len(),
        warning,
    })
}

#[cfg(test)]
mod tests {
    use super::{classify, is_scan_file, RULES};
    use std::path::Path;

    #[test]
    fn classifies_real_range_assets() {
        assert_eq!(
            classify(Path::new("skills/demo/SKILL.md")),
            Some(("Skill", "Skills"))
        );
        assert_eq!(
            classify(Path::new("mcp/customer_db/server.py")),
            Some(("MCP 服务", "MCP Servers"))
        );
        assert!(is_scan_file(Path::new("docker-compose.yml")));
    }

    #[test]
    fn dangerous_shell_pattern_is_present() {
        let rule = RULES
            .iter()
            .find(|rule| rule.id == "AR-STATIC-SHELL-TRUE")
            .expect("shell rule");
        assert!(rule.patterns.contains(&"shell=true"));
    }
}
