"""Bundled, source-only arena inventory. Does not load or invoke MCP servers."""
from integration.static_inventory import main

if __name__ == "__main__":
    raise SystemExit(main())
