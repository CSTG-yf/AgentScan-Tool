from pathlib import Path
from integration.static_inventory import discover_mcp_tools, scan


def test_only_registered_alias_tools_are_assets_without_executing_source(tmp_path):
    source = tmp_path / 'entry.py'
    source.write_text('''from mcp_base.mcp_http import Tool as T, create_server as serve
raise RuntimeError("never execute")
NAME = "renamed_ping"
unused = T("not_registered", "", {}, lambda: {})
secret = T(name="hidden_admin", description="", schema={}, handler=handler, hidden=True)
registered = [T(NAME, "", {}, handler), secret, secret]
app = serve("worker", tools=registered)
# Tool("comment", "", {}, handler)
text = 'Tool("string", "", {}, handler)'
''')
    tools = discover_mcp_tools(source)
    assert {t['name'] for t in tools} == {'renamed_ping', 'hidden_admin'}
    assert next(t for t in tools if t['name']=='hidden_admin')['hidden'] is True


def test_fastmcp_decorators_names_and_async_functions(tmp_path):
    p=tmp_path/'api.py'
    p.write_text('''from mcp.server.fastmcp import FastMCP as Server
app = Server("different-name")
@app.tool()
def alpha(): pass
@app.tool(name="public_beta")
async def beta(): pass
@unrelated.tool()
def ignored(): pass
''')
    assert {t['name'] for t in discover_mcp_tools(p)} == {'alpha','public_beta'}


def test_tools_keep_risks_on_parent_mcp_and_expose_relationship(tmp_path):
    (tmp_path/'mcp/x').mkdir(parents=True)
    (tmp_path/'docker-compose.yml').write_text('services:\n  mcp-renamed:\n    build: ./mcp\n    environment: {SERVER: x.server}\n')
    (tmp_path/'mcp/x/server.py').write_text('''import subprocess
from mcp_base.mcp_http import Tool, create_server
def execute(cmd): subprocess.run(cmd, shell=True)
app = create_server("renamed", [Tool("execute", "", {}, execute)])
''')
    r=scan(tmp_path)
    assert any(a['id']=='tool.renamed.execute' for a in r['assets'])
    assert any(e['from']=='mcp.renamed' and e['to']=='tool.renamed.execute' and e['relation']=='exposes' for e in r['asset_edges'])
    assert all(f['asset_id']=='mcp.renamed' for f in r['findings'])
