# CLAUDE.md — litesoc-mcp

> Repo-specific guide. Read the workspace root [`../CLAUDE.md`](../CLAUDE.md) first for mission,
> Golden Rules, and the shared agents in `../.claude/agents/` (integration-reviewer, backend,
> security, test-runner, bug-investigator, …) and rules in `../.claude/rules/`. **Do not redefine
> root agents or root rules here** — this file only complements them.

## Purpose
**Model Context Protocol (MCP) server** — "Lightweight Security Context for AI Agents." Connects AI
editors/assistants (Cursor, Claude Desktop, Copilot) to LiteSOC so an agent can triage alerts and
events. Published to npm as `@litesoc/mcp-server` (v1.0.0); bin `litesoc-mcp`, runnable via
`npx -y @litesoc/mcp-server`.

## Technology stack
- TypeScript, **ESM** (`type: module`), Node `>=18`. Build: `tsc`.
- Deps: `@modelcontextprotocol/sdk ^1.9`, `litesoc ^2.5` (the LiteSOC **Node SDK**), `zod ^3.23`.
- **No test or lint script** — validate with typecheck + build.

## Key directories
- `src/` — `index.ts` (server + tool registration) → compiled to `dist/`.

## Commands (verbatim from package.json)
- `build` → `tsc`
- `start` → `node dist/index.js`
- `dev` → `node --loader ts-node/esm src/index.ts`
- `typecheck` → `tsc --noEmit`

There is **no** `test`/`lint` script. Validate changes with `npm run typecheck` + `npm run build`.

## Architecture & boundaries
- Transport: **stdio** (spawned by the host AI editor).
- Wraps the `litesoc` Node SDK: `new LiteSOC({ apiKey })`, using `getAlerts`, `getAlert`,
  `getEvents`, `resolveAlert`.
- Exposes **4 MCP tools**: `list_alerts`, `analyze_alert`, `get_recent_events`, `resolve_incident`.
- It does **not** call the HTTP API directly — all platform access goes through the SDK, so it
  inherits the SDK's contract (endpoints, event-name set, server-assigned severity/timestamp).

## External dependencies
- `litesoc` Node SDK (npm), which in turn talks to `https://api.litesoc.io` with `X-API-Key`.
- npm registry (publish target).

## Environment variables
- `LITESOC_API_KEY` — read at runtime and passed to the SDK constructor. This is the **only**
  source of the API key. Never hardcode or log it.

## Security-sensitive code paths
- `src/index.ts` — API-key read from `LITESOC_API_KEY`; keep it out of logs and tool output.
- `resolve_incident` is a **mutating / privileged** action (it resolves incidents on the user's
  behalf). Treat it as privileged: it must act only on the caller's own tenant via the SDK, and
  changes to it warrant extra scrutiny.

## Database / migration responsibility
None. No schema or migrations.

## Deployment / distribution target
npm package `@litesoc/mcp-server`, run via `npx`/`bin litesoc-mcp` inside an MCP-capable editor.
No CHANGELOG, no CI in this repo.

## Cross-repository consumers & dependencies
- **Depends on** `litesoc-node` (npm `litesoc`); it inherits that SDK's API contract.
- Stay in sync with the `lsoc_app` contract and `litesoc-docs`; keep tool behavior consistent with
  the other integrations (SDKs, n8n node).

## Repo-specific rules & skills pointer
- No repo-local rules or skills beyond this file. Root rules/skills apply — see
  `../.claude/rules/` and `../.claude/skills/`.
