# PreClick OpenClaw Plugin

> Assess target URLs for potential threats and alignment with the user's browsing intent before agent navigation.

**Publisher:** [CybrLab.ai](https://cybrlab.ai) | **Service:** [PreClick](https://preclick.ai)

This plugin connects your OpenClaw agent to the hosted PreClick MCP
endpoint over Streamable HTTP. A companion skill is included that
instructs agents to assess target URLs for potential threats and
alignment with the user's browsing intent before navigation.

**Free to use** — up to 100 requests per day with no API key and no
sign-up required. For higher limits, configure an API key (see below).

---

## Install

```bash
openclaw plugins install @cybrlab/preclick-openclaw
```

Restart your OpenClaw Gateway after installation.

## Configure

The installer automatically enables the plugin in `~/.openclaw/openclaw.json`.
No additional configuration is required for trial mode (up to 100 requests/day).

**API key (optional, higher limits):**

Add `apiKey` to the plugin config in `~/.openclaw/openclaw.json`:

```json
{
  "plugins": {
    "entries": {
      "preclick-openclaw": {
        "enabled": true,
        "config": {
          "apiKey": "YOUR_API_KEY"
        }
      }
    }
  }
}
```

To obtain an API key, contact [contact@cybrlab.ai](mailto:contact@cybrlab.ai).

**Restricted tool policy (advanced):**

If you have `tools.allow` set in your config (restricting which tools are
available), add the plugin tools to `tools.alsoAllow`:

```json
{
  "tools": {
    "alsoAllow": [
      "url_scanner_scan",
      "url_scanner_scan_with_intent",
      "url_scanner_async_scan",
      "url_scanner_async_scan_with_intent",
      "url_scanner_async_task_status",
      "url_scanner_async_task_result",
      "url_scanner_tasks_get",
      "url_scanner_tasks_result",
      "url_scanner_tasks_list",
      "url_scanner_tasks_cancel"
    ]
  }
}
```

If you have not customized `tools.allow`, this step is not needed — all plugin
tools are available by default.

## Verify

After restarting the Gateway:

```bash
openclaw plugins list
```

You should see `preclick-openclaw` listed with 10 tools:

- `url_scanner_scan` — Analyze a URL for security threats
- `url_scanner_scan_with_intent` — Analyze a URL with user intent context
- `url_scanner_async_scan` — Compatibility async submit tool
- `url_scanner_async_scan_with_intent` — Compatibility async submit with intent
- `url_scanner_async_task_status` — Compatibility async status polling
- `url_scanner_async_task_result` — Compatibility async result polling
- `url_scanner_tasks_get` — OpenClaw proxy for native `tasks/get`
- `url_scanner_tasks_result` — OpenClaw proxy for native `tasks/result`
- `url_scanner_tasks_list` — OpenClaw proxy for native `tasks/list`
- `url_scanner_tasks_cancel` — OpenClaw proxy for native `tasks/cancel`

The plugin includes a bundled skill that instructs the agent to assess
target URLs for threats and intent alignment before navigating. You can
confirm the skill loaded:

```bash
openclaw skills list | grep preclick
```

## User-Ready Flow

Use this minimal flow for first-time setup:

1. Install plugin:

```bash
openclaw plugins install @cybrlab/preclick-openclaw
```

2. Restart gateway:

```bash
openclaw gateway restart
```

3. Verify plugin and skill are available:

```bash
openclaw plugins list | grep -i preclick
openclaw skills list | grep -i preclick
openclaw skills check
```

4. Run a first prompt:

```text
Before opening https://example.com, run url_scanner_scan_with_intent with intent "log in to my account" and tell me whether I should proceed.
```

## Usage

Ask your agent to scan a URL before navigating:

```
Before opening https://example.com, run url_scanner_scan and tell me if access should be allowed.
```

For intent-aware scanning (improves detection for login, purchase, download pages):

```
I want to log in to my bank. Scan https://example.com with url_scanner_scan_with_intent and intent "log in to bank account".
```

For asynchronous execution:

```text
Start an async scan for https://example.com using url_scanner_async_scan, then poll with url_scanner_async_task_status or url_scanner_async_task_result until completed.
```

`url_scanner_scan` and `url_scanner_scan_with_intent` also support optional MCP-style task mode by adding:

```json
{
  "task": {
    "ttl": 720000
  }
}
```

### Response Fields

| Field                    | Type            | Description                                                             |
|--------------------------|-----------------|-------------------------------------------------------------------------|
| `risk_score`             | float (0.0-1.0) | Threat probability                                                      |
| `confidence`             | float (0.0-1.0) | Analysis confidence                                                     |
| `analysis_complete`      | boolean         | Whether the analysis finished fully                                     |
| `agent_access_directive` | string          | `ALLOW`, `DENY`, `RETRY_LATER`, or `REQUIRE_CREDENTIALS`                |
| `agent_access_reason`    | string          | Reason for the directive                                                |
| `intent_alignment`       | string          | `misaligned`, `no_mismatch_detected`, `inconclusive`, or `not_provided` |

Use `agent_access_directive` for navigation decisions.

## Scan Timing

URL scans typically take around 70-80 seconds on current production traffic.

- **Direct mode (sync):** `url_scanner_scan` / `url_scanner_scan_with_intent` block until completion. If the hosted service times out its direct wait but returns a recoverable task handle, the plugin continues polling automatically.
- **Compatibility async mode:** use `url_scanner_async_scan` / `url_scanner_async_scan_with_intent`, then poll with `url_scanner_async_task_status` / `url_scanner_async_task_result`.
- **Native task mode:** pass `task` on the base scan tools, then use the plugin's `url_scanner_tasks_*` proxies for MCP task methods.

## Troubleshooting

| Symptom                                | Cause                                  | Fix                                                                                          |
|----------------------------------------|----------------------------------------|----------------------------------------------------------------------------------------------|
| Plugin not listed                      | Not installed or Gateway not restarted | Run install command, restart Gateway                                                         |
| `[PreClick] Connection failed` in logs | Endpoint unreachable                   | Check network; verify `curl https://preclick.ai/mcp` works                                   |
| Tools not appearing                    | Connection failed or `tools.allow` set | Check Gateway logs for `[PreClick]`; if `tools.allow` is set, add tools to `tools.alsoAllow` |
| `401 Unauthorized`                     | API key required or invalid            | Set `apiKey` in plugin config                                                                |
| `429 Too Many Requests`                | Rate limit exceeded                    | Reduce frequency or add API key for higher limits                                            |
| Scan takes too long                    | Target site is slow or complex         | Wait for completion; scans typically take around 70-80 seconds                               |

## How It Works

This plugin is a thin wrapper. It:

1. Registers pre-defined tool schemas as native OpenClaw agent tools
2. Connects to `https://preclick.ai/mcp` using the MCP SDK
3. Proxies tool calls to the remote server

No scanner logic runs locally. No files are written to your system. The plugin
does not modify your OpenClaw configuration.

## Security

- **No shell access.** Communication uses typed JSON-RPC over HTTPS.
- **No local execution.** All analysis runs on the remote PreClick service.
- **No config mutation.** The plugin never writes to `~/.openclaw/` files.
- **Auditable.** Source is a single file of JavaScript. Review it yourself.

## Important Notice

This tool is intended for authorized security assessment only. Use it solely on systems or websites that you own or for which you have got explicit permission to assess. Any unauthorized, unlawful, or malicious use is strictly prohibited. You are responsible for ensuring compliance with all applicable laws, regulations, and contractual obligations.

## Links

- [Full API Documentation](https://github.com/cybrlab-ai/preclick-mcp/blob/main/docs/API.md)
- [Authentication Guide](https://github.com/cybrlab-ai/preclick-mcp/blob/main/docs/AUTHENTICATION.md)

## Support

- **Email:** [contact@cybrlab.ai](mailto:contact@cybrlab.ai)
- **Publisher:** [CybrLab.ai](https://cybrlab.ai)
- **Service:** [PreClick](https://preclick.ai)

## License

Apache License 2.0
