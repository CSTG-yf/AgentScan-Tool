# Agent Runtime Knowledge Catalog

`agent-runtime-catalog.json` is the desktop runtime knowledge base for:

- dedicated Agent launch commands and Windows process image names;
- related host/support processes that require extra command-line or path evidence;
- common child commands started by Agents, grouped by capability and risk.

The catalog is evidence, not an automatic block list. Every generated or UI
policy must remain disabled by default and require explicit operator action.
Generic hosts such as `node.exe`, `python.exe`, `code.exe`, `wsl.exe`, and
`docker.exe` must never identify an Agent root by basename alone.

## Maintenance

1. Prefer the product's official documentation or source repository.
2. Add the source once under `sources` and reference its ID from Agent entries.
3. Keep Windows process names as basenames only; never add paths or wildcards.
4. Mark wrapper/runtime-host observations in `relatedProcessNames`, not
   `windowsProcessNames`.
5. Run `cargo test --locked` under `desktop/src-tauri`; catalog tests reject
   duplicate IDs, unknown sources, unsafe names, and ambiguous guard roots.
6. Update `updatedAt` whenever entries change.

The JSON contract is `../contracts/agent-runtime-catalog.schema.json`.
