# 🛡️ LiteSOC MCP Server

**Lightweight Security Context for AI Agents**

Connect your AI editor directly to your LiteSOC security data. This official [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server lets tools like **Cursor**, **Claude**, and **GitHub Copilot** query live security alerts, investigate forensic events, and resolve incidents — without leaving your editor.

---

## Prerequisites

- **Node.js** `>=18`
- A **LiteSOC API Key** — get yours at [litesoc.io/dashboard/settings](https://litesoc.io/dashboard/settings)
- A **Pro or Enterprise** plan for alert access and full forensic intelligence

---

## Installation & Usage

### Cursor

Add the server to your Cursor MCP settings under **Settings → MCP → Add Server**:

```json
{
  "mcpServers": {
    "litesoc": {
      "command": "npx",
      "args": ["-y", "@litesoc/mcp-server"],
      "env": {
        "LITESOC_API_KEY": "lsk_live_your_api_key_here"
      }
    }
  }
}
```

### Claude Desktop

Open `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows) and add:

```json
{
  "mcpServers": {
    "litesoc": {
      "command": "npx",
      "args": ["-y", "@litesoc/mcp-server"],
      "env": {
        "LITESOC_API_KEY": "lsk_live_your_api_key_here"
      }
    }
  }
}
```

Restart Claude Desktop after saving.

### Run Locally (from source)

```bash
git clone https://github.com/litesoc/litesoc-mcp
cd litesoc-mcp
npm install
npm run build

LITESOC_API_KEY=lsk_live_... node dist/index.js
```

---

## Available Tools

Once connected, your AI agent has access to the following tools:

### `list_alerts`

Fetch open security alerts filtered by status, severity, or detection type.

| Parameter    | Type     | Default  | Description                                              |
|-------------|----------|----------|----------------------------------------------------------|
| `status`    | `string` | `open`   | `open` · `acknowledged` · `resolved` · `dismissed`       |
| `severity`  | `string` | —        | `low` · `medium` · `high` · `critical`                   |
| `alert_type`| `string` | —        | `impossible_travel` · `brute_force_attack` · `geo_anomaly` · and more |
| `limit`     | `number` | `20`     | Max results to return (1–50)                             |

> Requires **Pro** or **Enterprise** plan.

---

### `analyze_alert`

Fetch full forensic details for a single alert by ID — VPN/Tor detection, geolocation, ISP data, source IP, and a Google Maps link.

| Parameter  | Type     | Description                              |
|-----------|----------|------------------------------------------|
| `alert_id`| `string` | Alert ID (obtained from `list_alerts`)   |

> Forensic fields (`is_vpn`, `is_tor`, `latitude`, `longitude`) are `null` on the Free plan. Upgrade at [litesoc.io/pricing](https://litesoc.io/pricing).

---

### `get_recent_events`

Fetch the latest raw security event logs from your project.

| Parameter    | Type     | Default | Description                               |
|-------------|----------|---------|-------------------------------------------|
| `limit`     | `number` | `10`    | Number of events to return (1–50)         |
| `event_name`| `string` | —       | Filter by event type (e.g. `auth.login`)  |
| `actor_id`  | `string` | —       | Filter by user or actor ID                |
| `severity`  | `string` | —       | `low` · `medium` · `high` · `critical`    |

> Network intelligence fields are redacted (`null`) on the Free plan.

---

### `resolve_incident`

Resolve or mark an alert as safe. Writes a SOC 2-compliant audit log entry with your notes and resolver identity.

| Parameter         | Type     | Description                                          |
|------------------|----------|------------------------------------------------------|
| `alert_id`       | `string` | Alert ID to resolve                                  |
| `resolution_type`| `string` | `resolved` or `dismissed`                            |
| `notes`          | `string` | Optional internal notes for the audit trail          |
| `resolved_by`    | `string` | Resolver identity. Defaults to `litesoc-mcp-agent`  |

> Every resolution triggers an immutable audit log via `recordAuditLog()` — meeting SOC 2 CC7.2 requirements.

---

## Example Prompts

Once the server is connected, try asking your AI agent:

```
List all critical alerts from the last 24 hours.
```

```
Analyze alert <alert_id> and tell me if the actor was using a VPN.
```

```
Show me the last 20 auth.login events for user@example.com.
```

```
Resolve alert <alert_id> with notes "confirmed false positive — internal IP".
```

---

## Security & Privacy

- **Plan-based data isolation** — all queries are scoped to your organization and project. Cross-tenant access is enforced at the API level.
- **PII redaction** — API keys, emails, and tokens are automatically masked in all log output. The MCP server never logs raw credentials.
- **No credential storage** — the API key is read from the environment at runtime and never persisted.
- **Free plan redaction** — `network_intelligence` and `geolocation` fields are returned as `null` for Free plan users. The agent will note this in its response.
- **Retention gating** — all event and alert queries automatically respect your plan's retention window (`X-LiteSOC-Cutoff`).

---

## API Reference

Full API documentation is available at [litesoc.io/docs/api](https://litesoc.io/docs/api).

For AI-optimized context, see [litesoc.io/llms.txt](https://litesoc.io/llms.txt).

---

## License

[MIT](./LICENSE) · Built by the [LiteSOC](https://litesoc.io) team
