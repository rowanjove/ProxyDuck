const DEFAULT_CORE_URL = "http://127.0.0.1:46666";
const AUTH_HEADER = "X-ProxyDuck-Token";

export async function invokeTauri(command, args = {}) {
  const invoke = window.__TAURI__?.tauri?.invoke;
  if (!invoke) throw new Error("Tauri bridge unavailable");
  return invoke(command, args);
}

export class CoreApiError extends Error {
  constructor(message, diagnostics = [], status = 0) {
    super(message);
    this.name = "CoreApiError";
    this.status = Number(status) || 0;
    this.diagnostics = Array.isArray(diagnostics) ? diagnostics : [];
  }
}

function apiError(message, diagnostics, status) {
  return new CoreApiError(message, diagnostics, status);
}

function shouldRetryNamedPipe(method, error) {
  if (error instanceof CoreApiError) return false;
  return ["GET", "HEAD", "OPTIONS"].includes(String(method).toUpperCase());
}

export class CoreApi {
  constructor() {
    this.baseUrl = DEFAULT_CORE_URL;
    this.token = "";
    this.transport = "http";
    this.lastDiagnostics = [];
  }

  async initializeSession() {
    if (!window.__TAURI__) return;
    const session = await invokeTauri("refresh_core_session");
    this.baseUrl = String(session.coreUrl || DEFAULT_CORE_URL).replace(/\/$/, "");
    this.token = session.token || "";
    this.transport = session.transport === "named_pipe" ? "named_pipe" : session.transport === "unavailable" ? "unavailable" : "http";
  }

  async request(path, { method = "GET", body, timeout = 6500 } = {}) {
    this.lastDiagnostics = [];
    if (this.transport === "unavailable") {
      if (window.__TAURI__) await this.initializeSession();
    }
    if (this.transport === "unavailable") {
      throw new Error("ProxyDuck 核心服务不可用，请先启动 ProxyDuck Core 服务");
    }
    if (this.transport === "named_pipe") {
      try {
        return await this.requestNamedPipe(method, path, body, timeout);
      } catch (error) {
        if (!window.__TAURI__) throw error;
        // A response from Core is authoritative. Never replay a write after
        // an uncertain transport result: the first request may have reached
        // the service even when the client did not receive its response.
        if (!shouldRetryNamedPipe(method, error)) throw error;
        await this.initializeSession();
        if (this.transport === "named_pipe") return this.requestNamedPipe(method, path, body, timeout);
        if (this.transport === "unavailable") throw error;
      }
    }
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), timeout);
    const headers = { "Content-Type": "application/json" };
    if (this.token) headers[AUTH_HEADER] = this.token;

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal
      });
      const payload = await response.json().catch(() => null);
      if (!response.ok || !payload?.ok) {
        throw apiError(payload?.error || `请求失败 (${response.status})`, payload?.diagnostics, response.status);
      }
      this.lastDiagnostics = Array.isArray(payload?.diagnostics) ? payload.diagnostics : [];
      return payload.data;
    } catch (error) {
      if (error?.name === "AbortError") throw new Error("核心服务响应超时");
      throw error;
    } finally {
      window.clearTimeout(timeoutId);
    }
  }

  async requestNamedPipe(method, path, body, timeout) {
    const response = await invokeTauri("core_ipc_request", {
      request: { method, path, body, deadlineMs: Math.min(timeout, 120000) }
    });
    if (!response || response.status < 200 || response.status >= 300) {
      const details = response?.error?.details;
      throw apiError(
        details?.error || response?.error?.message || `请求失败 (${response?.status || "IPC"})`,
        details?.diagnostics,
        response?.status
      );
    }
    this.lastDiagnostics = Array.isArray(response.body?.diagnostics) ? response.body.diagnostics : [];
    return response.body?.data ?? response.body;
  }

  get(path, options) { return this.request(path, options); }
  post(path, body, options) { return this.request(path, { ...options, method: "POST", body }); }
  put(path, body, options) { return this.request(path, { ...options, method: "PUT", body }); }
  delete(path, options) { return this.request(path, { ...options, method: "DELETE" }); }

  async download(path, { timeout = 15000 } = {}) {
    if (this.transport === "unavailable") {
      if (window.__TAURI__) await this.initializeSession();
    }
    if (this.transport === "unavailable") {
      throw new Error("ProxyDuck 核心服务不可用，请先启动 ProxyDuck Core 服务");
    }
    if (this.transport === "named_pipe") {
      try {
        return await this.downloadNamedPipe(path, timeout);
      } catch (error) {
        if (!window.__TAURI__) throw error;
        // Diagnostics export is a POST and must not be replayed implicitly.
        if (!shouldRetryNamedPipe("POST", error)) throw error;
        await this.initializeSession();
        if (this.transport === "named_pipe") return this.downloadNamedPipe(path, timeout);
        if (this.transport === "unavailable") throw error;
      }
    }
    const controller = new AbortController();
    const timeoutId = window.setTimeout(() => controller.abort(), timeout);
    const headers = {};
    if (this.token) headers[AUTH_HEADER] = this.token;
    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method: "POST",
        headers,
        signal: controller.signal
      });
      if (!response.ok) {
        const payload = await response.json().catch(() => null);
        throw apiError(payload?.error || `请求失败 (${response.status})`, payload?.diagnostics, response.status);
      }
      return response.blob();
    } catch (error) {
      if (error?.name === "AbortError") throw new Error("核心服务响应超时");
      throw error;
    } finally {
      window.clearTimeout(timeoutId);
    }
  }

  async downloadNamedPipe(path, timeout) {
    const response = await invokeTauri("core_ipc_request", {
      request: { method: "POST", path, deadlineMs: Math.min(timeout, 120000) }
    });
    if (!response || response.status < 200 || response.status >= 300) {
      const details = response?.error?.details;
      throw apiError(
        details?.error || response?.error?.message || `请求失败 (${response?.status || "IPC"})`,
        details?.diagnostics,
        response?.status
      );
    }
    if (!response.binaryBase64) throw new Error("核心服务未返回诊断包");
    const raw = atob(response.binaryBase64);
    const bytes = Uint8Array.from(raw, (character) => character.charCodeAt(0));
    return new Blob([bytes], { type: "application/zip" });
  }

  getConnections(params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.get(`/connections${q ? `?${q}` : ""}`);
  }

  getConnectionsSummary() {
    return this.get("/connections/summary");
  }

  discoverEndpoints(ownPort = 0) {
    return this.post("/endpoints/discover", { ownPort });
  }

  addDiscoveredEndpoint(payload) {
    return this.post("/endpoints/discover/add", payload);
  }

  getTimeline(params = {}) {
    const q = new URLSearchParams(params).toString();
    return this.get(`/timeline${q ? `?${q}` : ""}`);
  }

  clearTimeline() {
    return this.post("/timeline/clear", {});
  }

  analyzeRules() {
    return this.get("/rules/analyze");
  }

  simulateRule(payload) {
    return this.post("/rules/simulate", payload);
  }

  getAutostartStatus() {
    return getAutostartStatus();
  }

  setAutostartConfig(enabled, silent = true) {
    return setAutostartConfig(enabled, silent);
  }

  checkForAppUpdates(customEndpoint = null) {
    return checkForAppUpdates(customEndpoint);
  }

  installAppUpdate(downloadUrl) {
    return installAppUpdate(downloadUrl);
  }
}

export async function getAutostartStatus() {
  if (!window.__TAURI__) return { enabled: false, silent: true, method: "none", isElevated: false };
  return invokeTauri("get_autostart_status");
}

export async function setAutostartConfig(enabled, silent = true) {
  if (!window.__TAURI__) return;
  return invokeTauri("set_autostart_config", { enabled, silent });
}

export async function checkForAppUpdates(customEndpoint = null) {
  if (!window.__TAURI__) return { hasUpdate: false, currentVersion: "1.1.0", latestVersion: "1.1.0" };
  return invokeTauri("check_update", { customEndpoint });
}

export async function installAppUpdate(downloadUrl) {
  if (!window.__TAURI__) return;
  return invokeTauri("install_update", { downloadUrl });
}
