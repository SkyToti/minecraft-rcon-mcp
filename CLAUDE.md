# minecraft-rcon-mcp

MCP server (Python, official `mcp` SDK 2.x) to operate a Minecraft server over RCON without trusting the agent.
Public repository: code, comments, commits and docs in **English**.

- Spec and map of the code: `docs/DESIGN.md` (read the sections your task names; it is the source of truth).
- Tests: `.venv/bin/python -m pytest` from the checkout root (from a worktree, use the main checkout's `.venv`)
  (pytest adds `src/` and `tests/` to the path; no install step). No network, no Minecraft needed.
- SDK facts verified on the installed 2.3.0: `from mcp.server.mcpserver import MCPServer, Context`;
  `@server.tool(name=…, annotations=ToolAnnotations(…), meta={…})`; `from mcp.types import ToolAnnotations`
  (fields `read_only_hint`, `destructive_hint`, …); `Context.elicit(message, schema)`; in-memory test client:
  `from mcp.client.client import Client`. `mcp.server.fastmcp` does NOT exist in 2.x.
- Only `server.py` may import `mcp`. Everything else is plain standard library.
- Never print, log, return or commit an RCON password. Never read a real `server.properties` in tests: use
  `tests/fake_rcon.py` and temp directories.
- Do not start Minecraft servers, do not push, do not create GitHub repositories. Commit on your own branch.
