export function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

export function formatNumber(value) {
  return new Intl.NumberFormat("zh-CN").format(Number(value) || 0);
}

export function formatTime(value, includeDate = false) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat("zh-CN", {
    month: includeDate ? "2-digit" : undefined,
    day: includeDate ? "2-digit" : undefined,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  }).format(date);
}

export function engineLabel(mode) {
  return ({
    win_divert: "WinDivert",
    sing_box: "sing-box TUN",
    windivert: "WinDivert",
    wfp: "WFP",
    api_hook: "API Hook"
  })[mode] || mode || "—";
}

export function proxyKindLabel(kind) {
  return ({ socks5: "SOCKS5", http: "HTTP", direct: "DIRECT", interface: "接口", vpn: "VPN" })[kind] || String(kind || "—").toUpperCase();
}

export function startModeLabel(mode) {
  return ({
    start_and_bind: "启动并绑定",
    start_only: "仅启动",
    bind_only: "仅绑定"
  })[mode] || mode || "—";
}

export function matchKindLabel(kind) {
  return ({ pid: "PID", exe_path: "路径", app_name: "进程名", wildcard: "关键字" })[kind] || kind || "匹配";
}

export function ruleSourceLabel(source) {
  return source === "quick_bar" ? "快捷启动托管" : "手动规则";
}

export function matcherSummary(matcher = {}) {
  const parts = [];
  if (matcher.pids?.length) parts.push(`PID ${matcher.pids.join(", ")}`);
  if (matcher.exePaths?.length) parts.push(matcher.exePaths.join(", "));
  if (matcher.appNames?.length) parts.push(matcher.appNames.join(", "));
  if (matcher.wildcard) parts.push(`*${matcher.wildcard}*`);
  return parts.join(" · ") || "未设置匹配条件";
}

export function protocolSummary(protocols = []) {
  return protocols.map((protocol) => String(protocol).toUpperCase()).join(" · ") || "—";
}

export function initials(name) {
  const clean = String(name || "APP").trim();
  const words = clean.split(/\s+/).filter(Boolean);
  if (words.length > 1) return `${words[0][0]}${words[1][0]}`.toUpperCase();
  return clean.slice(0, 2).toUpperCase();
}

export function fileName(path) {
  const pieces = String(path || "").split(/[\\/]/).filter(Boolean);
  return pieces.at(-1) || "应用";
}

export function totalHits(stats = {}) {
  return Object.values(stats.processHits || {}).reduce((total, value) => total + (Number(value) || 0), 0);
}

export function protectionSummary(runtime = {}) {
  const enabled = [runtime.dnsEnforced, runtime.ipv6Blocked, runtime.dohBlocked].filter(Boolean).length;
  return enabled === 3 ? "全部启用" : `${enabled}/3 已启用`;
}

export function validateEndpoint(kind, endpoint) {
  if (kind === "direct") return true;
  const value = String(endpoint || "").trim();
  const match = value.match(/^(.+):(\d+)$/);
  if (!match) return false;
  const port = Number(match[2]);
  return Boolean(match[1].trim()) && port > 0 && port <= 65535;
}

export function normalizeError(error) {
  const message = error instanceof Error ? error.message : String(error || "未知错误");
  if (message.includes("Failed to fetch") || message.includes("fetch failed")) return "无法连接本地核心服务";
  if (message.includes("401") || message.toLowerCase().includes("token")) return "核心服务鉴权失败，请重启应用";
  return message;
}
