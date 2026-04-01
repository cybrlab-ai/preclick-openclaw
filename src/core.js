/**
 * PreClick OpenClaw Plugin
 *
 * Thin wrapper that connects OpenClaw agents to the PreClick MCP server
 * for URL security scanning. No scanner logic is bundled — all analysis
 * runs on the remote PreClick service.
 *
 * Publisher: CybrLab.ai (https://cybrlab.ai)
 * Service:   PreClick (https://preclick.ai)
 * License:   Apache-2.0
 */

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  CancelTaskResultSchema,
  CreateTaskResultSchema,
  GetTaskResultSchema,
  GetTaskPayloadResultSchema,
  ListTasksResultSchema,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";

const PLUGIN_ID = "preclick-openclaw";
const ENDPOINT = "https://preclick.ai/mcp";
const CLIENT_NAME = "preclick-openclaw-plugin";
const CLIENT_VERSION = "0.2.1";
const REQUEST_TIMEOUT_MS = 600_000;
const REQUEST_TIMEOUT_CODE = -32001;
const INTERNAL_ERROR_CODE = -32603;
const DEFAULT_TASK_TTL_MS = 720_000;

const TASK_OPTIONS_SCHEMA = {
  type: "object",
  description:
    "Optional task options. Include this object to request task-augmented (async) execution.",
  properties: {
    ttl: {
      type: "integer",
      description:
        "Optional task result retention in milliseconds. Example: 720000.",
    },
  },
  additionalProperties: false,
};

function createScanInputSchema({ includesIntent = false } = {}) {
  const properties = {
    url: {
      type: "string",
      description:
        "The URL to analyze. Must be HTTP or HTTPS. If no scheme provided, https:// is assumed.",
    },
    task: TASK_OPTIONS_SCHEMA,
  };

  if (includesIntent) {
    properties.intent = {
      type: "string",
      description:
        "User's stated purpose for visiting the URL (e.g., 'login to email', 'book a hotel', 'download software'). Max 248 characters.",
    };
  }

  return {
    type: "object",
    properties,
    required: ["url"],
  };
}

function createCompatAsyncScanInputSchema({ includesIntent = false } = {}) {
  const properties = {
    url: {
      type: "string",
      description:
        "The URL to analyze. Must be HTTP or HTTPS. If no scheme provided, https:// is assumed.",
    },
  };

  if (includesIntent) {
    properties.intent = {
      type: "string",
      description:
        "User's stated purpose for visiting the URL (e.g., 'login to email', 'book a hotel', 'download software'). Max 248 characters.",
    };
  }

  return {
    type: "object",
    properties,
    required: ["url"],
  };
}

/**
 * Public plugin tool surface.
 *
 * Existing tool names stay backward-compatible. Async and task lifecycle tools
 * are added for discoverability and parity with MCP task workflows.
 */
const TOOL_DEFS = [
  // --- Primary scan tools (direct + task-augmented) ---
  {
    name: "url_scanner_scan",
    description:
      "Analyze a URL for security threats including phishing, malware, and suspicious patterns. Supports direct (sync) and task-augmented (async) execution. Returns risk score, confidence, agent access guidance, and intent_alignment (always not_provided for this tool; use url_scanner_scan_with_intent for intent context). For clients without native MCP Tasks support, see url_scanner_async_scan.",
    inputSchema: createScanInputSchema(),
    kind: "scan",
    mcpTool: "url_scanner_scan",
    mode: "auto",
  },
  {
    name: "url_scanner_scan_with_intent",
    description:
      "Analyze a URL for security threats with optional user intent context. Supports direct (sync) and task-augmented (async) execution. Use when the user states their purpose (e.g., login, purchase, booking) so intent/content mismatch can be considered as an additional signal. Returns risk score, confidence, agent access guidance, and intent_alignment. For clients without native MCP Tasks support, see url_scanner_async_scan_with_intent.",
    inputSchema: createScanInputSchema({ includesIntent: true }),
    kind: "scan",
    mcpTool: "url_scanner_scan_with_intent",
    mode: "auto",
  },

  // --- Compatibility async tools (for clients without native MCP Tasks) ---
  {
    name: "url_scanner_async_scan",
    description:
      "Submit a URL for asynchronous security analysis and return immediately with a task_id. Poll with url_scanner_async_task_status or url_scanner_async_task_result. Compatibility wrapper for clients without native MCP Tasks support. Call as an ordinary tool without a native MCP task parameter.",
    inputSchema: createCompatAsyncScanInputSchema(),
    kind: "compat_async",
    mcpTool: "url_scanner_async_scan",
  },
  {
    name: "url_scanner_async_scan_with_intent",
    description:
      "Submit a URL with optional user intent for asynchronous security analysis and return immediately with a task_id. Poll with url_scanner_async_task_status or url_scanner_async_task_result. Compatibility wrapper for clients without native MCP Tasks support. Call as an ordinary tool without a native MCP task parameter.",
    inputSchema: createCompatAsyncScanInputSchema({ includesIntent: true }),
    kind: "compat_async",
    mcpTool: "url_scanner_async_scan_with_intent",
  },
  {
    name: "url_scanner_async_task_status",
    description:
      "Check the status of an asynchronous scan task using native MCP task semantics (working, completed, failed, cancelled). Compatibility wrapper for clients without native MCP Tasks support. Call as an ordinary tool without a native MCP task parameter.",
    inputSchema: {
      type: "object",
      properties: {
        task_id: {
          type: "string",
          description:
            "The task ID returned by url_scanner_async_scan or url_scanner_async_scan_with_intent.",
        },
      },
      required: ["task_id"],
    },
    kind: "compat_async",
    mcpTool: "url_scanner_async_task_status",
  },
  {
    name: "url_scanner_async_task_result",
    description:
      "Retrieve the result of an asynchronous scan task. Returns a working status while the task is still running, the final scan result when completed, or an MCP error when the underlying task failed/cancelled/expired. Compatibility wrapper for clients without native MCP Tasks support. Call as an ordinary tool without a native MCP task parameter.",
    inputSchema: {
      type: "object",
      properties: {
        task_id: {
          type: "string",
          description:
            "The task ID returned by url_scanner_async_scan or url_scanner_async_scan_with_intent.",
        },
      },
      required: ["task_id"],
    },
    kind: "compat_async",
    mcpTool: "url_scanner_async_task_result",
  },

  // --- Native MCP task lifecycle tools ---
  {
    name: "url_scanner_tasks_get",
    description: "Plugin proxy for native MCP tasks/get. Returns non-blocking status for an existing URL scan task.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: { type: "string", description: "Task identifier." },
      },
      required: ["taskId"],
    },
    kind: "task",
    mcpMethod: "tasks/get",
    resultSchema: GetTaskResultSchema,
  },
  {
    name: "url_scanner_tasks_result",
    description: "Plugin proxy for native MCP tasks/result. Waits for task completion and returns the task result payload.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: { type: "string", description: "Task identifier." },
      },
      required: ["taskId"],
    },
    kind: "task",
    mcpMethod: "tasks/result",
    resultSchema: GetTaskPayloadResultSchema,
  },
  {
    name: "url_scanner_tasks_list",
    description: "Plugin proxy for native MCP tasks/list. Lists URL scan tasks for the authenticated API key context.",
    inputSchema: {
      type: "object",
      additionalProperties: false,
      properties: {},
    },
    kind: "task",
    mcpMethod: "tasks/list",
    resultSchema: ListTasksResultSchema,
  },
  {
    name: "url_scanner_tasks_cancel",
    description: "Plugin proxy for native MCP tasks/cancel. Cancels a queued or running URL scan task.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: { type: "string", description: "Task identifier." },
      },
      required: ["taskId"],
    },
    kind: "task",
    mcpMethod: "tasks/cancel",
    resultSchema: CancelTaskResultSchema,
  },
];

/**
 * Module-level state persists across OpenClaw register() re-invocations.
 * Exported for test infrastructure (src/test-hooks.js, not shipped in npm package).
 */
export const _pluginState = {
  client: null,
  connectionHeaders: null,
  connectMcpImpl: connectMcp,
  log: console,
};

/**
 * Create a fresh MCP client and connect to the PreClick endpoint.
 */
async function connectMcp() {
  const transport = new StreamableHTTPClientTransport(
    new URL(ENDPOINT),
    { requestInit: { headers: { ..._pluginState.connectionHeaders } } },
  );

  const newClient = new Client(
    { name: CLIENT_NAME, version: CLIENT_VERSION },
    { capabilities: {} },
  );
  newClient.requestTimeoutMs = REQUEST_TIMEOUT_MS;

  await newClient.connect(transport);
  return newClient;
}

export default definePluginEntry({
  id: PLUGIN_ID,
  name: "PreClick Security Scanner",

  register(api) {
    _pluginState.log = api.logger || console;

    // Register tools synchronously so the gateway picks them up immediately.
    for (const toolDef of TOOL_DEFS) {
      registerToolProxy(api, toolDef);
    }
    _pluginState.log.info(
      `[PreClick] Registered ${TOOL_DEFS.length} tool(s): ${TOOL_DEFS.map((t) => t.name).join(", ")}`,
    );

    api.registerService({
      id: PLUGIN_ID,

      async start() {
        const apiKey = resolveApiKey(api);

        _pluginState.log.info(`[PreClick] Endpoint: ${ENDPOINT}`);
        if (apiKey) {
          _pluginState.log.info(`[PreClick] Auth: API key configured`);
        } else {
          _pluginState.log.info(
            `[PreClick] Auth: trial mode (up to 100 requests/day, no API key)`,
          );
        }

        _pluginState.connectionHeaders = {
          Accept: "application/json, text/event-stream",
        };
        if (apiKey) {
          _pluginState.connectionHeaders["X-API-Key"] = apiKey;
        }

        try {
          _pluginState.client = await _pluginState.connectMcpImpl();
          _pluginState.log.info(`[PreClick] Connected to ${ENDPOINT}`);
        } catch (err) {
          _pluginState.log.error(`[PreClick] Connection failed: ${err.message}`);
          _pluginState.log.error(
            `[PreClick] Verify endpoint is reachable: curl -s -o /dev/null -w "%{http_code}" ${ENDPOINT}`,
          );
          _pluginState.client = null;
        }
      },

      async stop() {
        if (_pluginState.client) {
          try {
            await _pluginState.client.close();
          } catch {
            // Ignore close errors during shutdown
          }
          _pluginState.client = null;
          _pluginState.log.info(`[PreClick] Disconnected`);
        }
        _pluginState.connectionHeaders = null;
      },
    });

    /**
     * Register a single MCP tool as a native OpenClaw tool.
     *
     * OpenClaw agent-tools execute signature: execute(_id, params)
     * - _id: tool invocation ID (managed by OpenClaw runtime)
     * - params: the arguments object passed by the agent
     */
    function registerToolProxy(api, toolDef) {
      api.registerTool({
        name: toolDef.name,
        description: toolDef.description || `PreClick tool: ${toolDef.name}`,
        parameters: toolDef.inputSchema,

        async execute(_id, params = {}) {
          if (!_pluginState.client && !_pluginState.connectionHeaders) {
            return errorResult(
              "PreClick plugin has not been started. Check logs for errors.",
            );
          }

          const input = asObjectParams(params);
          if (!input) {
            return errorResult("Invalid arguments: expected an object.");
          }

          try {
            if (toolDef.kind === "scan") {
              return await executeScanTool(toolDef, input);
            }
            if (toolDef.kind === "compat_async") {
              return await executeCompatAsyncTool(toolDef, input);
            }
            return await executeTaskMethodTool(toolDef, input);
          } catch (err) {
            const message = err?.message || String(err);
            return errorResult(`PreClick error: ${message}`);
          }
        },
      });
    }
  },
});

async function executeScanTool(toolDef, params) {
  const { task, ...scanArgs } = params;
  let taskOptions;

  try {
    taskOptions = parseTaskOptions(task, { forceTask: toolDef.mode === "task" });
  } catch (err) {
    return errorResult(err.message);
  }

  const mode = taskOptions ? "task" : "direct";

  if (mode === "task") {
    try {
      const taskResult = await callToolAsTask(toolDef.mcpTool, scanArgs, taskOptions);
      return normalizeStructuredResult(taskResult, "PreClick task created.");
    } catch (err) {
      const message = err?.message || String(err);
      return errorResult(`PreClick async error: ${message}`);
    }
  }

  return executeDirectScan(toolDef.mcpTool, scanArgs);
}

/**
 * Execute a compatibility async tool.
 *
 * These are plain MCP tools (no task parameter) that the server provides for
 * clients without native MCP Tasks support. Called via callTool like direct
 * scans but without task/recovery logic since they return quickly.
 */
async function executeCompatAsyncTool(toolDef, params) {
  return executeToolCall(toolDef.mcpTool, params, {
    allowTaskTimeoutRecovery: false,
  });
}

async function executeTaskMethodTool(toolDef, params, options = {}) {
  try {
    const methodParams =
      toolDef.mcpMethod === "tasks/list" ? {} : params;

    const rawResult = await callMcpRequest(
      {
        method: toolDef.mcpMethod,
        params: methodParams,
      },
      toolDef.resultSchema,
      {
        timeout: REQUEST_TIMEOUT_MS,
        resetTimeoutOnProgress: true,
      },
      { allowRetry: true },
    );

    const result = normalizeTaskMethodPayload(toolDef.mcpMethod, rawResult);

    if (toolDef.mcpMethod === "tasks/result") {
      return normalizeCompletedTaskValue(result);
    }

    return normalizeStructuredResult(result, "PreClick task operation completed.");
  } catch (err) {
    if (toolDef.mcpMethod === "tasks/result" && isRecoverableTaskTimeout(err)) {
      try {
        return await recoverFromTimeout(err.data.taskId, err.data.pollInterval, {
          ...options.recoveryOptions,
          sourceLabel: "tasks/result timeout",
        });
      } catch (recoveryErr) {
        return errorResult(
          `PreClick task recovery failed: ${recoveryErr.message}`,
        );
      }
    }

    const message = err?.message || String(err);
    return errorResult(`PreClick task error: ${message}`);
  }
}

async function executeDirectScan(mcpToolName, scanArgs, options = {}) {
  return executeToolCall(mcpToolName, scanArgs, {
    allowTaskTimeoutRecovery: true,
    recoveryOptions: options.recoveryOptions,
  });
}

async function executeToolCall(mcpToolName, toolArgs, options = {}) {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await ensureConnectedClient();

      const result = await _pluginState.client.callTool({
        name: mcpToolName,
        arguments: toolArgs,
      }, undefined, {
        timeout: REQUEST_TIMEOUT_MS,
        resetTimeoutOnProgress: true,
      });

      if (result.isError) {
        const text = extractErrorText(result.content) || "Unknown error";
        return errorResult(text);
      }

      return normalizeToolResult(result);
    } catch (err) {
      if (options.allowTaskTimeoutRecovery && isRecoverableTaskTimeout(err)) {
        try {
          return await recoverFromTimeout(
            err.data.taskId,
            err.data.pollInterval,
            {
              ...options.recoveryOptions,
              sourceLabel:
                options.recoveryOptions?.sourceLabel || "direct-call timeout",
            },
          );
        } catch (recoveryErr) {
          return errorResult(
            `PreClick timeout recovery failed: ${recoveryErr.message}`,
          );
        }
      }

      if (shouldRetryCallError(err, attempt)) {
        const message = err?.message || String(err);
        _pluginState.log.warn(
          `[PreClick] Call failed (${message}), reconnecting...`,
        );
        await resetClientConnection();
        continue;
      }

      const message = err?.message || String(err);
      return errorResult(`PreClick error: ${message}`);
    }
  }

  return errorResult(
    "PreClick error: request failed after retry. Please try again.",
  );
}

async function callToolAsTask(mcpToolName, scanArgs, taskOptions) {
  return callMcpRequest(
    {
      method: "tools/call",
      params: {
        name: mcpToolName,
        arguments: scanArgs,
      },
    },
    CreateTaskResultSchema,
    {
      timeout: REQUEST_TIMEOUT_MS,
      resetTimeoutOnProgress: true,
      task: taskOptions,
    },
    { allowRetry: false },
  );
}

async function callMcpRequest(request, resultSchema, requestOptions, options = {}) {
  const maxAttempts = options.allowRetry ? 2 : 1;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    await ensureConnectedClient();

    try {
      return await _pluginState.client.request(request, resultSchema, requestOptions);
    } catch (err) {
      if (options.allowRetry && shouldRetryCallError(err, attempt)) {
        const message = err?.message || String(err);
        _pluginState.log.warn(
          `[PreClick] Request failed (${message}), reconnecting...`,
        );
        await resetClientConnection();
        continue;
      }

      throw err;
    }
  }

  throw new Error("PreClick request failed after retry.");
}

async function ensureConnectedClient() {
  if (_pluginState.client) {
    return;
  }

  try {
    _pluginState.client = await _pluginState.connectMcpImpl();
    _pluginState.log.info(`[PreClick] Reconnected to ${ENDPOINT}`);
  } catch (err) {
    throw new Error(`PreClick reconnect failed: ${err.message}`);
  }
}

async function resetClientConnection() {
  if (!_pluginState.client) {
    return;
  }

  try {
    await _pluginState.client.close();
  } catch {
    // ignore
  }

  _pluginState.client = null;
}

/**
 * Recover a task-backed result after a recoverable server wait timeout.
 *
 * The server returns `data.taskId` and `data.pollInterval` when a request
 * times out but the underlying task keeps running. This function polls
 * `tasks/get` until the task completes, then fetches the full result via
 * `tasks/result`.
 */
async function recoverFromTimeout(taskId, pollIntervalMs, options = {}) {
  const maxWaitMs = Number.isInteger(options.maxWaitMs)
    ? options.maxWaitMs
    : 500_000;
  const sleepFn = typeof options.sleepFn === "function" ? options.sleepFn : delay;
  const deadline = Date.now() + maxWaitMs;
  const interval = Math.max(pollIntervalMs || 2000, 1000);
  const sourceLabel = options.sourceLabel || "server timeout";

  _pluginState.log.info(
    `[PreClick] Recovering task ${taskId} after ${sourceLabel}`,
  );

  while (Date.now() < deadline) {
    await sleepFn(interval);

    let taskResult;
    try {
      taskResult = await callMcpRequest(
        {
          method: "tasks/get",
          params: { taskId },
        },
        GetTaskResultSchema,
        {
          timeout: REQUEST_TIMEOUT_MS,
          resetTimeoutOnProgress: true,
        },
        { allowRetry: true },
      );
    } catch {
      continue;
    }

    const task = taskResult?.task || taskResult;
    const status = String(task?.status || "").toLowerCase();

    if (status === "completed") {
      const taskPayload = await fetchCompletedTaskPayload(taskId, deadline, {
        interval,
        sleepFn,
      });
      _pluginState.log.info(`[PreClick] Task ${taskId} recovered successfully`);
      return normalizeRecoveredTaskPayload(taskPayload);
    }

    if (status === "failed" || status === "cancelled") {
      throw new Error(`Task ${taskId} ended with status: ${status}`);
    }
  }

  throw new Error(`Recovery poll exhausted for task ${taskId}`);
}

async function fetchCompletedTaskPayload(taskId, deadline, options = {}) {
  const interval = Math.max(options.interval || 1000, 1);
  const sleepFn = typeof options.sleepFn === "function" ? options.sleepFn : delay;

  while (Date.now() < deadline) {
    try {
      return await callMcpRequest(
        {
          method: "tasks/result",
          params: { taskId },
        },
        GetTaskPayloadResultSchema,
        {
          timeout: REQUEST_TIMEOUT_MS,
          resetTimeoutOnProgress: true,
        },
        { allowRetry: true },
      );
    } catch (err) {
      if (!isRecoverableTaskTimeout(err)) {
        throw err;
      }

      _pluginState.log.warn(
        `[PreClick] tasks/result timed out for completed task ${taskId}, retrying...`,
      );

      if (Date.now() < deadline) {
        await sleepFn(interval);
      }
    }
  }

  throw new Error(`Completed task result fetch exhausted for task ${taskId}`);
}

/**
 * Normalize a completed task value into a consistent tool result.
 *
 * If the value is a tool-result envelope (has content[] or structuredContent),
 * pass it through normalizeToolResult so the consumer sees the scan data
 * in the same shape as a direct scan. Otherwise wrap it as structured content.
 */
function normalizeCompletedTaskValue(value) {
  if (value && typeof value === "object" &&
      (Array.isArray(value.content) || value.structuredContent !== undefined)) {
    return normalizeToolResult(value);
  }
  return normalizeStructuredResult(value, "PreClick scan completed.");
}

function normalizeRecoveredTaskPayload(taskPayload) {
  if (taskPayload?.value !== undefined) {
    return normalizeCompletedTaskValue(taskPayload.value);
  }

  if (Array.isArray(taskPayload?.content) || taskPayload?.structuredContent !== undefined) {
    return normalizeToolResult(taskPayload);
  }

  return normalizeStructuredResult(taskPayload, "PreClick scan completed.");
}

function normalizeTaskMethodPayload(method, payload) {
  if (!payload || typeof payload !== "object") {
    return payload;
  }

  if (method === "tasks/get" || method === "tasks/cancel") {
    if (payload.task && typeof payload.task === "object") {
      return payload;
    }

    if (payload.taskId && payload.status) {
      return { task: payload };
    }
  }

  return payload;
}

function isRecoverableTaskTimeout(err) {
  return (
    err instanceof McpError &&
    err.code === INTERNAL_ERROR_CODE &&
    typeof err.data?.taskId === "string" &&
    err.data.taskId.length > 0
  );
}

function normalizeStructuredResult(payload, fallbackText) {
  const response = {
    structuredContent: payload,
    content: [{ type: "text", text: safeSerialize(payload, fallbackText) }],
  };

  if (payload?._meta !== undefined) {
    response._meta = payload._meta;
  }

  return response;
}

function parseTaskOptions(taskParam, { forceTask = false } = {}) {
  if (taskParam === undefined || taskParam === null) {
    return forceTask ? { ttl: DEFAULT_TASK_TTL_MS } : undefined;
  }

  if (typeof taskParam !== "object" || Array.isArray(taskParam)) {
    throw new Error("Invalid 'task' parameter: expected an object.");
  }

  const allowedKeys = new Set(["ttl"]);
  for (const key of Object.keys(taskParam)) {
    if (!allowedKeys.has(key)) {
      throw new Error(`Invalid task option '${key}'.`);
    }
  }

  const options = {};

  if (taskParam.ttl !== undefined) {
    if (!Number.isInteger(taskParam.ttl) || taskParam.ttl <= 0) {
      throw new Error("Invalid task.ttl: expected a positive integer.");
    }
    options.ttl = taskParam.ttl;
  }

  if (forceTask && Object.keys(options).length === 0) {
    options.ttl = DEFAULT_TASK_TTL_MS;
  }

  return options;
}

function asObjectParams(params) {
  if (!params || typeof params !== "object" || Array.isArray(params)) {
    return null;
  }
  return params;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Resolve API key from OpenClaw plugin config.
 * Never silently mutates user config files.
 */
function resolveApiKey(api) {
  const pluginConfig =
    api.config?.plugins?.entries?.[PLUGIN_ID]?.config || {};

  return pluginConfig.apiKey || null;
}

function extractErrorText(content) {
  if (!Array.isArray(content)) {
    return "";
  }
  return content
    .map((item) => (typeof item?.text === "string" ? item.text : ""))
    .filter(Boolean)
    .join("\n");
}

/**
 * Build an error result that OpenClaw can safely process.
 *
 * OpenClaw runtime calls .filter() on result.content unconditionally,
 * so every return — including errors — must include a content[] array.
 */
export function errorResult(message) {
  return {
    isError: true,
    error: message,
    content: [{ type: "text", text: message }],
  };
}

export function normalizeToolResult(result) {
  const response = {};

  if (result?.structuredContent !== undefined) {
    response.structuredContent = result.structuredContent;
  }
  if (result?._meta !== undefined) {
    response._meta = result._meta;
  }

  // OpenClaw runtime expects content to be an array for successful tool output.
  if (Array.isArray(result?.content) && result.content.length > 0) {
    response.content = result.content;
  } else if (result?.structuredContent !== undefined) {
    response.content = [
      { type: "text", text: safeSerialize(result.structuredContent) },
    ];
  } else {
    response.content = [{ type: "text", text: "PreClick scan completed." }];
  }

  return response;
}

export function shouldRetryCallError(err, attempt) {
  if (attempt !== 0) {
    return false;
  }

  // Retry transport-like failures once.
  if (!(err instanceof McpError)) {
    return true;
  }

  // Retry only MCP transport/request timeout signals; server-side protocol
  // errors such as recoverable task wait timeouts must be handled explicitly.
  return err.code === REQUEST_TIMEOUT_CODE;
}

function safeSerialize(value, fallback = "PreClick scan completed.") {
  try {
    return JSON.stringify(value);
  } catch {
    return fallback;
  }
}

// Internal functions exported for test infrastructure.
// Test state mutators live in src/test-hooks.js (not shipped in npm package).
export {
  connectMcp as _defaultConnectMcp,
  parseTaskOptions,
  asObjectParams,
  normalizeStructuredResult,
  normalizeTaskMethodPayload,
  normalizeRecoveredTaskPayload,
  extractErrorText,
  safeSerialize,
  resolveApiKey,
  executeDirectScan,
  executeCompatAsyncTool,
  executeTaskMethodTool,
  recoverFromTimeout,
  callMcpRequest,
  isRecoverableTaskTimeout,
};
