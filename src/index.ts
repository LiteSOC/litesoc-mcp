#!/usr/bin/env node
/**
 * LiteSOC MCP Server v1.0.0
 *
 * Official Model Context Protocol server for LiteSOC.
 * Connects AI editors (Cursor, Claude, GitHub Copilot) directly to your
 * security alerts, forensic data, and event logs.
 *
 * Usage:
 *   LITESOC_API_KEY=lsk_live_... node dist/index.js
 *
 * Tools exposed:
 *   - list_alerts        List open security alerts (severity, type, actor)
 *   - analyze_alert      Full forensic detail for a single alert (VPN, geo, map)
 *   - get_recent_events  Fetch the latest security event logs
 *   - resolve_incident   Mark an alert as resolved with internal notes
 *
 * Docs: https://litesoc.io/docs/api
 * llms.txt: https://litesoc.io/llms.txt
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { LiteSOC, PlanRestrictedError, NotFoundError, AuthenticationError } from "litesoc";
import { z } from "zod";

// ── Bootstrap ──────────────────────────────────────────────────────────────────

const API_KEY = process.env.LITESOC_API_KEY;

if (!API_KEY) {
  process.stderr.write(
    "[litesoc-mcp] ERROR: LITESOC_API_KEY environment variable is required.\n" +
    "  Get your key at: https://litesoc.io/dashboard/settings\n"
  );
  process.exit(1);
}

const litesoc = new LiteSOC({
  apiKey: API_KEY,
  batching: false,   // MCP is interactive — send events immediately
  silent: false,     // Surface errors to the AI agent
});

// ── MCP Server ─────────────────────────────────────────────────────────────────

const server = new McpServer({
  name: "litesoc",
  version: "1.0.0",
});

// ── Helpers ────────────────────────────────────────────────────────────────────

/**
 * Converts a LiteSOC SDK error into a human-readable string the AI can act on.
 */
function formatError(err: unknown): string {
  if (err instanceof AuthenticationError) {
    return "Authentication failed. Check your LITESOC_API_KEY.";
  }
  if (err instanceof PlanRestrictedError) {
    return (
      "This action requires a Pro or Enterprise plan. " +
      "Upgrade at https://litesoc.io/pricing. " +
      "Note: forensic fields (is_vpn, is_tor, latitude, longitude) are also redacted (null) on the Free plan."
    );
  }
  if (err instanceof NotFoundError) {
    return "Resource not found. The ID may be incorrect or outside your retention window.";
  }
  if (err instanceof Error) {
    return err.message;
  }
  return String(err);
}

/**
 * Formats plan metadata as a footer note for every tool response.
 */
function planFooter(metadata: { plan: string | null; retentionDays: number | null; cutoffDate: string | null }): string {
  const parts: string[] = [];
  if (metadata.plan) parts.push(`Plan: ${metadata.plan}`);
  if (metadata.retentionDays != null) parts.push(`Retention: ${metadata.retentionDays} days`);
  if (metadata.cutoffDate) parts.push(`Data available from: ${metadata.cutoffDate}`);
  if (!parts.length) return "";
  return `\n\n---\n_${parts.join(" · ")}_`;
}

// ── Tool: list_alerts ─────────────────────────────────────────────────────────

server.tool(
  "list_alerts",
  "Fetch open security alerts from LiteSOC. Returns severity, alert type, actor ID, source IP, and creation time. " +
  "Requires Pro or Enterprise plan. Free plan users will receive a plan restriction error.",
  {
    status: z
      .enum(["open", "acknowledged", "resolved", "dismissed"])
      .optional()
      .default("open")
      .describe("Filter by alert status. Defaults to 'open'."),
    severity: z
      .enum(["low", "medium", "high", "critical"])
      .optional()
      .describe("Filter by severity level."),
    alert_type: z
      .enum([
        "impossible_travel",
        "brute_force_attack",
        "geo_anomaly",
        "new_device",
        "privilege_escalation",
        "data_exfiltration",
        "suspicious_activity",
        "rate_limit_exceeded",
      ])
      .optional()
      .describe("Filter by detection type."),
    limit: z
      .number()
      .int()
      .min(1)
      .max(50)
      .optional()
      .default(20)
      .describe("Maximum number of alerts to return (1–50). Defaults to 20."),
  },
  async ({ status, severity, alert_type, limit }) => {
    try {
      const { data, metadata } = await litesoc.getAlerts({
        status,
        severity,
        alert_type,
        limit,
      });

      if (data.data.length === 0) {
        return {
          content: [
            {
              type: "text",
              text:
                `No ${status} alerts found.` +
                (severity ? ` (severity filter: ${severity})` : "") +
                planFooter(metadata),
            },
          ],
        };
      }

      const rows = data.data.map((alert) => {
        const lines = [
          `**[${alert.severity.toUpperCase()}] ${alert.title}**`,
          `- ID: \`${alert.id}\``,
          `- Type: ${alert.alert_type}`,
          `- Status: ${alert.status}`,
          `- Actor: ${alert.actor_id ?? "unknown"}`,
          `- Source IP: ${alert.source_ip ?? "unknown"}`,
          `- Created: ${alert.created_at}`,
        ];
        if (alert.description) lines.push(`- Description: ${alert.description}`);
        return lines.join("\n");
      });

      const summary =
        `Found **${data.total}** alert(s) · showing ${data.data.length}` +
        (data.has_more ? ` · more available (use offset)` : "");

      return {
        content: [
          {
            type: "text",
            text: [summary, "", ...rows].join("\n\n") + planFooter(metadata),
          },
        ],
      };
    } catch (err) {
      return {
        content: [{ type: "text", text: `Error: ${formatError(err)}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: analyze_alert ───────────────────────────────────────────────────────

server.tool(
  "analyze_alert",
  "Fetch full forensic details for a specific alert by ID. " +
  "Includes VPN/Tor detection, geolocation, ISP data, and the full alert description. " +
  "⚠️ Forensic fields (is_vpn, is_tor, is_proxy, latitude, longitude) are null on the Free plan — upgrade to Pro for full intelligence. " +
  "Requires Pro or Enterprise plan.",
  {
    alert_id: z
      .string()
      .min(1)
      .describe("The unique alert ID (e.g. from list_alerts)."),
  },
  async ({ alert_id }) => {
    try {
      const { data: alert, metadata } = await litesoc.getAlert(alert_id);

      const forensicSection: string[] = ["### Forensic Intelligence"];

      // Geo
      if (alert.source_ip) {
        forensicSection.push(`- **Source IP:** ${alert.source_ip}`);
      }

      // These fields come from the linked triggering event via the API response metadata.
      // The Alert object itself doesn't embed event-level network_intelligence,
      // but the description and metadata fields carry enriched context from the worker.
      const meta = alert.metadata ?? {};

      // Network intelligence (may be null for Free plan)
      const networkFields: string[] = [];
      if ("is_vpn" in meta) networkFields.push(`VPN: ${meta.is_vpn ?? "redacted (Free plan)"}`);
      if ("is_tor" in meta) networkFields.push(`Tor: ${meta.is_tor ?? "redacted (Free plan)"}`);
      if ("is_proxy" in meta) networkFields.push(`Proxy: ${meta.is_proxy ?? "redacted (Free plan)"}`);
      if ("is_datacenter" in meta) networkFields.push(`Datacenter: ${meta.is_datacenter ?? "redacted (Free plan)"}`);
      if (networkFields.length) forensicSection.push(`- **Network:** ${networkFields.join(" · ")}`);

      // Geo coords
      if ("latitude" in meta && "longitude" in meta) {
        if (meta.latitude && meta.longitude) {
          forensicSection.push(`- **Coordinates:** ${meta.latitude}, ${meta.longitude}`);
          forensicSection.push(
            `- **Map:** https://www.google.com/maps?q=${meta.latitude},${meta.longitude}`
          );
        } else {
          forensicSection.push(`- **Coordinates:** redacted (Free plan — upgrade to Pro for geo data)`);
        }
      }

      // City/country from metadata if present
      if (meta.city) forensicSection.push(`- **City:** ${meta.city}`);
      if (meta.country) forensicSection.push(`- **Country:** ${meta.country}`);
      if (meta.isp) forensicSection.push(`- **ISP:** ${meta.isp}`);
      if (meta.threat_score != null) forensicSection.push(`- **Threat Score:** ${meta.threat_score}/100`);

      const lines = [
        `## Alert: ${alert.title}`,
        "",
        `| Field | Value |`,
        `|---|---|`,
        `| ID | \`${alert.id}\` |`,
        `| Type | ${alert.alert_type} |`,
        `| Severity | **${alert.severity.toUpperCase()}** |`,
        `| Status | ${alert.status} |`,
        `| Actor | ${alert.actor_id ?? "unknown"} |`,
        `| Source IP | ${alert.source_ip ?? "unknown"} |`,
        `| Created | ${alert.created_at} |`,
        `| Updated | ${alert.updated_at} |`,
        alert.resolved_at ? `| Resolved at | ${alert.resolved_at} |` : null,
        alert.resolved_by ? `| Resolved by | ${alert.resolved_by} |` : null,
        "",
        alert.description ? `**Description:** ${alert.description}` : null,
        "",
        forensicSection.length > 1 ? forensicSection.join("\n") : null,
        Object.keys(meta).length
          ? `\n### Raw Metadata\n\`\`\`json\n${JSON.stringify(meta, null, 2)}\n\`\`\``
          : null,
        `\n### Recommended Actions`,
        `- If confirmed malicious: use \`resolve_incident\` with \`resolution_type: "blocked_ip"\``,
        `- If false positive: use \`resolve_incident\` with \`resolution_type: "false_positive"\``,
        `- View in dashboard: https://litesoc.io/dashboard/alerts`,
      ]
        .filter((l) => l !== null)
        .join("\n");

      return {
        content: [{ type: "text", text: lines + planFooter(metadata) }],
      };
    } catch (err) {
      return {
        content: [{ type: "text", text: `Error: ${formatError(err)}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: get_recent_events ───────────────────────────────────────────────────

server.tool(
  "get_recent_events",
  "Fetch the latest security event logs from LiteSOC. " +
  "Returns event name, actor, IP, country, severity, and timestamp. " +
  "⚠️ Network intelligence fields (is_vpn, is_tor, latitude, longitude) are null for Free plan users.",
  {
    limit: z
      .number()
      .int()
      .min(1)
      .max(50)
      .optional()
      .default(10)
      .describe("Number of events to return (1–50). Defaults to 10."),
    event_name: z
      .string()
      .optional()
      .describe(
        "Filter by event type, e.g. 'auth.login_failed'. Supports all 26 standard events."
      ),
    actor_id: z
      .string()
      .optional()
      .describe("Filter by actor (user) ID."),
    severity: z
      .enum(["info", "warning", "critical"])
      .optional()
      .describe("Filter by severity level."),
  },
  async ({ limit, event_name, actor_id, severity }) => {
    try {
      const { data, metadata } = await litesoc.getEvents({
        limit,
        event_name,
        actor_id,
        severity,
      });

      if (data.data.length === 0) {
        return {
          content: [
            {
              type: "text",
              text: "No events found matching these filters." + planFooter(metadata),
            },
          ],
        };
      }

      const rows = data.data.map((ev) => {
        const flags: string[] = [];
        if (ev.is_vpn) flags.push("VPN");
        if (ev.is_tor) flags.push("TOR");
        if (ev.is_proxy) flags.push("Proxy");
        if (ev.is_datacenter) flags.push("Datacenter");

        // Free plan: is_vpn etc. will be null — indicate that to the AI
        const networkNote =
          ev.is_vpn === null && ev.is_tor === null
            ? " _(network intelligence redacted — Free plan)_"
            : flags.length
            ? ` 🚨 **${flags.join(", ")}**`
            : "";

        return [
          `**${ev.event_name}**${networkNote}`,
          `- ID: \`${ev.id}\``,
          `- Actor: ${ev.actor_id ?? "unknown"}`,
          `- IP: ${ev.user_ip ?? "not provided"}`,
          `- Location: ${[ev.city, ev.country_code].filter(Boolean).join(", ") || "unknown"}`,
          `- Severity: ${ev.severity}`,
          `- Time: ${ev.created_at}`,
        ].join("\n");
      });

      const summary =
        `Showing **${data.data.length}** of ${data.total} events` +
        (data.has_more ? " · more available (increase limit or use offset)" : "");

      return {
        content: [
          {
            type: "text",
            text: [summary, "", ...rows].join("\n\n") + planFooter(metadata),
          },
        ],
      };
    } catch (err) {
      return {
        content: [{ type: "text", text: `Error: ${formatError(err)}` }],
        isError: true,
      };
    }
  }
);

// ── Tool: resolve_incident ────────────────────────────────────────────────────

server.tool(
  "resolve_incident",
  "Mark a LiteSOC security alert as resolved. Records your resolution action and internal notes for the SOC 2 audit trail. " +
  "Requires Pro or Enterprise plan. " +
  "Resolution types: blocked_ip | reset_password | contacted_user | false_positive | other.",
  {
    alert_id: z
      .string()
      .min(1)
      .describe("The unique alert ID to resolve."),
    resolution_type: z
      .enum(["blocked_ip", "reset_password", "contacted_user", "false_positive", "other"])
      .optional()
      .default("other")
      .describe(
        "How the incident was handled. " +
        "'blocked_ip' = banned the source IP. " +
        "'reset_password' = forced a password reset. " +
        "'contacted_user' = reached out to the user. " +
        "'false_positive' = confirmed not a real threat. " +
        "'other' = any other resolution."
      ),
    notes: z
      .string()
      .max(1000)
      .optional()
      .describe("Internal resolution notes (max 1000 chars). Stored in the audit trail."),
    resolved_by: z
      .string()
      .optional()
      .describe(
        "Who is resolving this alert. Can be a user ID, email address, or identifier like 'ai-agent'. " +
        "Logged in the SOC 2 audit trail."
      ),
  },
  async ({ alert_id, resolution_type, notes, resolved_by }) => {
    try {
      const { data: result, metadata } = await litesoc.resolveAlert(
        alert_id,
        resolution_type,
        {
          notes,
          resolvedBy: resolved_by ?? "litesoc-mcp-agent",
        }
      );

      const lines = [
        `✅ **Alert resolved successfully.**`,
        "",
        `| Field | Value |`,
        `|---|---|`,
        `| Alert ID | \`${result.id}\` |`,
        `| New Status | ${result.status} |`,
        `| Resolution | ${result.resolution_type ?? resolution_type} |`,
        `| Resolved by | ${result.resolved_by} |`,
        `| Resolved at | ${result.resolved_at ?? result.updated_at} |`,
        "",
        notes ? `**Notes recorded:** ${notes}` : null,
        "",
        `This action has been logged in your SOC 2 audit trail. ` +
        `View the alert at: https://litesoc.io/dashboard/alerts`,
      ]
        .filter((l) => l !== null)
        .join("\n");

      return {
        content: [{ type: "text", text: lines + planFooter(metadata) }],
      };
    } catch (err) {
      return {
        content: [{ type: "text", text: `Error: ${formatError(err)}` }],
        isError: true,
      };
    }
  }
);

// ── Start ──────────────────────────────────────────────────────────────────────

const transport = new StdioServerTransport();
await server.connect(transport);
