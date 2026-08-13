use crate::knowledge;
use crate::models::GuardPolicy;

const DEFAULT_POLICY_JSON: &str = include_str!("../../contracts/process-guard.default.json");

pub fn default_policy() -> Result<GuardPolicy, String> {
    let mut policy: GuardPolicy = serde_json::from_str(DEFAULT_POLICY_JSON)
        .map_err(|error| format!("parse embedded process guard policy: {error}"))?;
    policy.agent_names = knowledge::catalog()?
        .agents
        .iter()
        .filter(|agent| agent.guard_root_eligible)
        .flat_map(|agent| agent.windows_process_names.iter().cloned())
        .collect();
    Ok(policy)
}

pub fn default_policy_json() -> Result<Vec<u8>, String> {
    serde_json::to_vec_pretty(&default_policy()?)
        .map_err(|error| format!("serialize embedded process guard policy: {error}"))
}

#[cfg(test)]
mod tests {
    use crate::models::GuardPolicy;

    use super::default_policy_json;

    #[test]
    fn service_policy_serialization_contains_catalog_roots() {
        let raw = default_policy_json().expect("serialized default policy");
        let policy: GuardPolicy = serde_json::from_slice(&raw).expect("round-trip policy");
        assert!(policy
            .agent_names
            .iter()
            .any(|name| name == "cursor-agent.exe"));
        assert!(policy.agent_names.iter().any(|name| name == "hermes.exe"));
        assert!(!policy.agent_names.iter().any(|name| name == "node.exe"));
    }
}
