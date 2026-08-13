use std::collections::HashSet;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

const CATALOG_JSON: &str = include_str!("../../knowledge/agent-runtime-catalog.json");
static CATALOG: OnceLock<Result<AgentRuntimeCatalog, String>> = OnceLock::new();

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentRuntimeCatalog {
    pub version: u8,
    pub updated_at: String,
    pub sources: Vec<CatalogSource>,
    pub agents: Vec<AgentKnowledge>,
    pub commands: Vec<CommandKnowledge>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogSource {
    pub id: String,
    pub title: String,
    pub url: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentKnowledge {
    pub id: String,
    pub product: String,
    pub vendor: String,
    pub kind: String,
    pub launch_commands: Vec<String>,
    pub windows_process_names: Vec<String>,
    pub related_process_names: Vec<String>,
    pub guard_root_eligible: bool,
    pub confidence: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
    pub source_refs: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandKnowledge {
    pub id: String,
    pub category: String,
    pub command_names: Vec<String>,
    pub windows_process_names: Vec<String>,
    pub process_visibility: String,
    pub risk_level: String,
    pub recommended_action: String,
    pub common_uses: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

fn canonical_executable(name: &str) -> String {
    let normalized = name.trim().to_ascii_lowercase();
    normalized
        .strip_suffix(".exe")
        .unwrap_or(&normalized)
        .to_owned()
}

fn valid_process_name(name: &str) -> bool {
    !name.trim().is_empty()
        && name.len() <= 260
        && !name.contains(['/', '\\', '*', '?', ' ', '\t', '"', '\''])
}

fn unique_nonempty(values: &[String]) -> bool {
    let mut seen = HashSet::new();
    !values.is_empty()
        && values
            .iter()
            .all(|value| !value.trim().is_empty() && seen.insert(value.to_ascii_lowercase()))
}

fn unique(values: &[String]) -> bool {
    let mut seen = HashSet::new();
    values
        .iter()
        .all(|value| !value.trim().is_empty() && seen.insert(value.to_ascii_lowercase()))
}

fn validate(catalog: &AgentRuntimeCatalog) -> Result<(), String> {
    if catalog.version != 1 || catalog.updated_at.trim().is_empty() {
        return Err("unsupported Agent runtime catalog version or date".to_owned());
    }

    let mut source_ids = HashSet::new();
    for source in &catalog.sources {
        if !source_ids.insert(source.id.as_str())
            || source.title.trim().is_empty()
            || !(source.url.starts_with("https://") || source.url.starts_with("http://"))
        {
            return Err(format!(
                "invalid or duplicate catalog source: {}",
                source.id
            ));
        }
    }

    let ambiguous_roots = HashSet::from([
        "bash",
        "cmd",
        "code",
        "docker",
        "java",
        "javaw",
        "node",
        "powershell",
        "pwsh",
        "py",
        "python",
        "python3",
        "sh",
        "wsl",
    ]);
    let mut agent_ids = HashSet::new();
    let mut exact_agent_images = HashSet::new();
    for agent in &catalog.agents {
        if !agent_ids.insert(agent.id.as_str())
            || agent.product.trim().is_empty()
            || agent.vendor.trim().is_empty()
            || !unique_nonempty(&agent.launch_commands)
            || !unique_nonempty(&agent.windows_process_names)
            || !agent
                .windows_process_names
                .iter()
                .all(|name| valid_process_name(name))
            || !unique(&agent.related_process_names)
            || !agent
                .related_process_names
                .iter()
                .all(|name| valid_process_name(name))
            || !unique_nonempty(&agent.source_refs)
            || !agent
                .source_refs
                .iter()
                .all(|source| source_ids.contains(source.as_str()))
            || !matches!(
                agent.kind.as_str(),
                "terminal-agent" | "editor-agent" | "desktop-agent" | "agent-platform"
            )
            || !matches!(agent.confidence.as_str(), "high" | "medium" | "low")
        {
            return Err(format!("invalid Agent catalog entry: {}", agent.id));
        }
        if agent.guard_root_eligible {
            for image in &agent.windows_process_names {
                let canonical = canonical_executable(image);
                if ambiguous_roots.contains(canonical.as_str())
                    || !exact_agent_images.insert(canonical)
                {
                    return Err(format!(
                        "ambiguous or duplicate Agent guard-root process: {image}"
                    ));
                }
            }
        }
    }

    let mut command_ids = HashSet::new();
    for command in &catalog.commands {
        if !command_ids.insert(command.id.as_str())
            || !unique_nonempty(&command.command_names)
            || !unique_nonempty(&command.windows_process_names)
            || !command
                .windows_process_names
                .iter()
                .all(|name| valid_process_name(name))
            || !unique_nonempty(&command.common_uses)
            || !matches!(
                command.category.as_str(),
                "shell"
                    | "search"
                    | "version-control"
                    | "network"
                    | "runtime"
                    | "package-manager"
                    | "build"
                    | "container-cloud"
                    | "filesystem"
                    | "system-control"
            )
            || !matches!(
                command.process_visibility.as_str(),
                "exact-image" | "host-process" | "mixed"
            )
            || !matches!(
                command.risk_level.as_str(),
                "low" | "medium" | "high" | "critical"
            )
            || !matches!(
                command.recommended_action.as_str(),
                "observe" | "review" | "restrict"
            )
        {
            return Err(format!("invalid command catalog entry: {}", command.id));
        }
    }
    Ok(())
}

pub fn catalog() -> Result<&'static AgentRuntimeCatalog, String> {
    CATALOG
        .get_or_init(|| {
            let parsed: AgentRuntimeCatalog = serde_json::from_str(CATALOG_JSON)
                .map_err(|error| format!("parse embedded Agent runtime catalog: {error}"))?;
            validate(&parsed)?;
            Ok(parsed)
        })
        .as_ref()
        .map_err(Clone::clone)
}

pub fn identify_agent_in<'a>(
    catalog: &'a AgentRuntimeCatalog,
    image_name: &str,
) -> Option<&'a AgentKnowledge> {
    let image = canonical_executable(image_name);
    catalog.agents.iter().find(|agent| {
        agent.guard_root_eligible
            && agent
                .windows_process_names
                .iter()
                .any(|candidate| canonical_executable(candidate) == image)
    })
}

#[cfg(test)]
mod tests {
    use super::{catalog, identify_agent_in};

    #[test]
    fn embedded_catalog_is_valid_and_substantial() {
        let knowledge = catalog().expect("valid embedded runtime catalog");
        assert!(knowledge.agents.len() >= 15);
        assert!(knowledge.commands.len() >= 30);
        assert!(knowledge.sources.len() >= 10);
    }

    #[test]
    fn identifies_dedicated_agent_images_case_insensitively() {
        let cursor = identify_agent_in(
            catalog().expect("valid embedded runtime catalog"),
            " CURSOR-AGENT.EXE ",
        )
        .expect("Cursor signature");
        assert_eq!(cursor.id, "cursor");
        assert_eq!(cursor.product, "Cursor");
    }

    #[test]
    fn generic_runtime_is_not_an_agent_root() {
        let knowledge = catalog().expect("valid embedded runtime catalog");
        assert!(identify_agent_in(knowledge, "node.exe").is_none());
        assert!(identify_agent_in(knowledge, "python.exe").is_none());
    }
}
