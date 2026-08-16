const DEFAULT_CORE_URL = "http://127.0.0.1:46666";
const AUTH_HEADER = "X-ProxyDuck-Token";

export async function invokeTauri(command, args = {}) {
  const invoke = window.__TAURI__?.tauri?.invoke;
  if (!invoke) throw new Error("Tauri bridge unavailable");
  return invoke(command, args);
}

export class CoreApi {
  constructor() {
    this.baseUrl = DEFAULT_CORE_URL;
    this.token = "";
  }

  async initializeSession() {
    if (!window.__TAURI__) return;
    const session = await invokeTauri("get_core_session");
    this.baseUrl = String(session.coreUrl || DEFAULT_CORE_URL).replace(/\/$/, "");
    this.token = session.token || "";
  }

  async request(path, { method = "GET", body, timeout = 6500 } = {}) {
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
        throw new Error(payload?.error || `请求失败 (${response.status})`);
      }
      return payload.data;
    } catch (error) {
      if (error?.name === "AbortError") throw new Error("核心服务响应超时");
      throw error;
    } finally {
      window.clearTimeout(timeoutId);
    }
  }

  get(path, options) { return this.request(path, options); }
  post(path, body, options) { return this.request(path, { ...options, method: "POST", body }); }
  put(path, body, options) { return this.request(path, { ...options, method: "PUT", body }); }
  delete(path, options) { return this.request(path, { ...options, method: "DELETE" }); }
}
