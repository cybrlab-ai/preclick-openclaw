# Changelog

## 0.2.0 (2026-03-31)

- Align async compatibility tool naming with the upstream PreClick MCP public contract:
  - `url_scanner_async_scan`
  - `url_scanner_async_scan_with_intent`
  - `url_scanner_async_task_status`
  - `url_scanner_async_task_result`
- Clarify that `url_scanner_tasks_*` are OpenClaw proxy tools for native MCP task methods.
- Recover `url_scanner_tasks_result` automatically when the hosted `tasks/result` wait window times out but returns a recoverable `taskId`.

## 0.1.0 (2026-03-30)

- Initial release of `@cybrlab/preclick-openclaw` — the PreClick plugin for OpenClaw.
- Connects to the hosted PreClick MCP endpoint (`https://preclick.ai/mcp`).
- Uses `definePluginEntry` entry point aligned with current OpenClaw plugin SDK.
- Uses `api.logger` for scoped logging instead of console.
- Registers 8 tools as native OpenClaw agent tools:
  - `url_scanner_scan` — Analyze a URL for security threats (direct or task mode)
  - `url_scanner_scan_with_intent` — Analyze a URL with optional intent context (direct or task mode)
  - `url_scanner_scan_async` — Asynchronous scan returning a task handle
  - `url_scanner_scan_with_intent_async` — Intent-aware async scan with task handle
  - `url_scanner_tasks_get` — Check task status
  - `url_scanner_tasks_result` — Wait for and retrieve task result
  - `url_scanner_tasks_list` — List tasks
  - `url_scanner_tasks_cancel` — Cancel a task
- Consistent `structuredContent` shape across direct and async scan results.
- Includes bundled companion skill (`skills/preclick/SKILL.md`) that instructs agents to assess URLs for threats and intent alignment before navigation.
- Supports trial mode (no API key, up to 100 requests/day) and authenticated mode via `PRECLICK_API_KEY` env var or plugin config.
- Direct-call timeout recovery: when the server returns `-32603` with `data.taskId`, the plugin polls `tasks/get` and `tasks/result` to recover the scan result.
- On-demand MCP reconnect with one bounded retry for transport-level failures.
- All error return paths include OpenClaw-compatible `content[]` arrays.
- Declares `openclaw` as a peer dependency (`>=2026.3.28`).
- Requires Node.js >= 22.14.0 (aligned with OpenClaw runtime).
