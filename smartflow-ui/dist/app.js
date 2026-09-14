import { CoreApi, invokeTauri } from "./api.mjs";
import { applyTranslations, getLanguage, initializeLanguage, setLanguage, t } from "./i18n.mjs";
import {
  escapeHtml,
  fileName,
  formatNumber,
  formatTime,
  initials,
  matcherSummary,
  normalizeError,
  totalHits,
  validateEndpoint
} from "./lib.mjs";

const api = new CoreApi();
const $ = (id) => document.getElementById(id);
const state = {
  online: false,
  currentView: "overview",
  health: null,
  capabilities: [],
  config: null,
  stats: {},
  runtimeStatus: null,
  ruleStats: [],
  ruleConflicts: [],
  proxyStats: [],
  hits: [],
  logs: [],
  processes: [],
  processesLoaded: false,
  refreshing: false,
  reconnectTimer: null,
  reconnectInFlight: false,
  editingRuleId: null,
  rulePidCreationTime: null,
  preflight: null,
  testedProxyIds: new Set(),
  doctorDiagnosis: null,
  doctorSnapshots: [],
  doctorRepairPlan: null,
  studioConfigs: [],
  studioActivePath: null,
  studioActiveDoc: null,
  studioCurrentTab: "visual",
  historyRuns: [],
  overviewTab: "recent",
  connections: [],
  discoveredEndpoints: [],
  timelineEvents: [],
  autostartStatus: null,
  updateInfo: null
};

const viewMeta = {
  overview: "page.overview",
  rules: "page.rules",
  doctor: "page.doctor",
  studio: "page.studio",
  history: "page.history",
  profiles: "page.profiles",
  proxies: "page.proxies",
  launch: "page.launch",
  processes: "page.processes",
  settings: "page.settings"
};

const iconCache = new Map();
let iconQueue = Promise.resolve();

function emptyState(title, description, compact = false) {
  return `<div class="empty-state${compact ? " compact" : ""}"><div><svg><use href="#i-pulse"/></svg><strong>${escapeHtml(title)}</strong><span>${escapeHtml(description)}</span></div></div>`;
}

function statusBadge(label, tone = "neutral") {
  return `<span class="status-badge ${tone}"><span></span>${escapeHtml(label)}</span>`;
}

function toast(title, message = "", type = "success") {
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.innerHTML = `<svg><use href="#${type === "error" ? "i-alert" : "i-check"}"/></svg><div><strong>${escapeHtml(title)}</strong>${message ? `<span>${escapeHtml(message)}</span>` : ""}</div>`;
  $("toastStack").appendChild(node);
  window.setTimeout(() => node.remove(), type === "error" ? 5200 : 3200);
}

function proxyKindText(kind) {
  return t(`proxyKind.${kind}`);
}

function ruleSourceText(source) {
  return t(`source.${source}`);
}

function matchKindText(kind) {
  return t(`matchKind.${kind}`);
}

function protocolText(protocols) {
  return protocols.map((protocol) => t(`protocol.${protocol}`)).join(" · ");
}

function startModeText(mode) {
  return t(`startMode.${mode}`);
}

function reportError(error, context = t("toast.operationFailed")) {
  const message = normalizeError(error);
  toast(context, message, "error");
  if (message.includes("核心服务") || message.includes("鉴权") || /core|auth/i.test(message)) setOnline(false, message);
}

function setOnline(online, message = "") {
  state.online = online;
  if (online && state.reconnectTimer) {
    window.clearTimeout(state.reconnectTimer);
    state.reconnectTimer = null;
  }
  const status = $("coreStatus");
  status.classList.toggle("online", online);
  status.classList.toggle("offline", !online);
  status.querySelector("strong").textContent = t(online ? "core.online" : "core.offline");
  status.querySelector("small").textContent = api.baseUrl.replace(/^https?:\/\//, "");
  $("connectionBanner").classList.toggle("hidden", online);
  if (message) $("connectionMessage").textContent = message;
}

function initTheme() {
  const saved = localStorage.getItem("proxyduck-theme") || localStorage.getItem("proxydock-theme") || localStorage.getItem("smartflow-theme");
  const theme = saved || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
  document.documentElement.dataset.theme = theme;
  updateThemeIcon();
}

function initLanguage() {
  const language = initializeLanguage();
  applyTranslations();
  $("languageSelect").value = language;
}

function updateThemeIcon() {
  const light = document.documentElement.dataset.theme === "light";
  $("themeBtn").innerHTML = `<svg><use href="#${light ? "i-moon" : "i-sun"}"/></svg>`;
  $("themeBtn").title = t(light ? "theme.dark" : "theme.light");
  $("themeBtn").setAttribute("aria-label", $("themeBtn").title);
}

function toggleTheme() {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = next;
  localStorage.setItem("proxyduck-theme", next);
  updateThemeIcon();
}

function switchLanguage(language) {
  setLanguage(language);
  applyTranslations();
  $("languageSelect").value = getLanguage();
  renderAll();
  switchView(state.currentView);
  setOnline(state.online);
  updateThemeIcon();
}

function switchView(view) {
  if (!viewMeta[view]) return;
  state.currentView = view;
  document.querySelectorAll(".nav-item[data-view]").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  document.querySelectorAll(".view").forEach((node) => node.classList.toggle("active", node.id === `view-${view}`));
  $("pageTitle").textContent = t(`${viewMeta[view]}.title`);
  $("pageSubtitle").textContent = t(`${viewMeta[view]}.subtitle`);
  if (view === "overview" && state.config) updateOverviewHeader();
  document.querySelector(".workspace").scrollTo({ top: 0, behavior: "smooth" });
  if (view === "processes" && !state.processesLoaded) loadProcesses().catch((error) => reportError(error, t("toast.processFailed")));
  if (view === "doctor") {
    loadDoctorStatus().catch((error) => reportError(error, "加载网络状态失败"));
    loadSnapshots().catch((error) => reportError(error, "加载快照失败"));
  }
  if (view === "studio" && !state.studioConfigs.length) {
    discoverConfigs().catch((error) => reportError(error, "扫描配置失败"));
  }
  if (view === "history") {
    loadDiagnosticHistory().catch((error) => reportError(error, "加载诊断历史失败"));
  }
  if (view === "settings") {
    loadAutostartConfig().catch(() => {});
  }
}

function proxyName(id) {
  if (id === "direct") return t("common.direct");
  if (id === "block") return t("common.block");
  if (id === "reject") return t("common.reject");
  return state.config?.proxies.find((proxy) => proxy.id === id)?.name || id || "—";
}

function ruleActionType(rule) {
  return String(rule?.action?.type || "proxy").toLowerCase();
}

function ruleRouteName(rule) {
  const action = ruleActionType(rule);
  if (action === "direct") return t("common.direct");
  if (action === "block") return t("common.block");
  if (action === "reject") return t("common.reject");
  return proxyName(rule?.action?.proxyId || rule?.proxyProfile);
}

function proxyHealth(proxyId) {
  return state.runtimeStatus?.proxyHealth?.find((item) => item.proxyId === proxyId) || null;
}

function proxyHealthText(health) {
  if (!health) return t("proxyHealth.unknown");
  const key = String(health.state || "unknown").replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase();
  return t(`proxyHealth.${key}`) || t("proxyHealth.unknown");
}

function proxyLatencySummary(health) {
  const samples = (health?.latencyHistoryMs || []).filter((value) => Number.isFinite(value));
  if (!samples.length) return "";
  const average = Math.round(samples.reduce((sum, value) => sum + value, 0) / samples.length);
  return `${samples.at(-1)} ms · avg ${average} ms`;
}

function enabledProxyOptions(selected = "") {
  const proxies = (state.config?.proxies || []).filter((proxy) => proxy.enabled);
  return proxies.map((proxy) => `<option value="${escapeHtml(proxy.id)}"${proxy.id === selected ? " selected" : ""}>${escapeHtml(proxy.name)} · ${escapeHtml(proxyKindText(proxy.kind))}</option>`).join("");
}

function currentEngineCapability() {
  const mode = state.config?.engineMode || "proxifyre";
  return state.capabilities.find((capability) => capability.mode === mode) || null;
}

function renderCapabilities() {
  if (!state.capabilities.length) return;
  const selectedMode = state.config?.engineMode || "proxifyre";
  $("engineMode").innerHTML = state.capabilities.map((capability) => {
    const suffix = capability.available ? "" : ` — ${capability.unavailableReason || t("common.disabled")}`;
    return `<option value="${escapeHtml(capability.mode)}"${capability.mode === selectedMode ? " selected" : ""} title="${escapeHtml(capability.unavailableReason || "")}">${escapeHtml(capability.displayName + suffix)}</option>`;
  }).join("");

  const capability = currentEngineCapability();
  if (!capability) return;
  const availableCount = state.capabilities.filter((item) => item.available).length;
  $("engineCapabilityHint").textContent = t(
    availableCount > 1 ? "settings.engineReady" : "settings.engineSingle",
    { engine: capability.displayName }
  );
  const proxyKinds = capability.supportedProxyKinds || [];
  $("proxyKind").innerHTML = proxyKinds.map((kind) => `<option value="${escapeHtml(kind)}">${escapeHtml(proxyKindText(kind))}</option>`).join("");
  for (const control of [$("ruleChildren"), $("launchChildren")]) {
    control.disabled = !capability.supportsChildInheritance;
    if (control.disabled) control.checked = false;
    control.closest("label")?.classList.toggle("is-disabled", control.disabled);
  }
}

function syncProxySelects() {
  const options = enabledProxyOptions();
  $("ruleProxy").innerHTML = options;
  $("launchProxy").innerHTML = options;
}

function updateOverviewHeader() {
  const rules = state.config?.rules || [];
  const proxies = state.config?.proxies || [];
  const enabledRules = rules.filter((rule) => rule.enabled).length;
  const enabledProxies = proxies.filter((proxy) => proxy.enabled).length;
  $("pageSubtitle").textContent = t("overview.summary", {
    rules: enabledRules,
    proxies: enabledProxies,
    hits: formatNumber(totalHits(state.stats)),
    ruleLabel: t(enabledRules === 1 ? "overview.ruleSingular" : "overview.rulePlural"),
    proxyLabel: t(enabledProxies === 1 ? "overview.proxySingular" : "overview.proxyPlural")
  });
}

function renderOverview() {
  if (!state.config) return;
  const { runtime, rules } = state.config;
  const runtimeToggle = $("runtimeToggle");
  const phase = state.runtimeStatus?.dataPlane?.phase || (runtime.enabled ? "starting" : "paused");
  runtimeToggle.classList.toggle("is-on", runtime.enabled);
  runtimeToggle.classList.toggle("has-error", ["degraded", "error"].includes(phase));
  runtimeToggle.setAttribute("aria-pressed", String(runtime.enabled));
  runtimeToggle.setAttribute("aria-label", t(runtime.enabled ? "runtime.pause" : "runtime.enable"));
  $("runtimeStateLabel").textContent = t(`runtimePhase.${phase}`);
  $("navRuleCount").textContent = rules.length;
  updateOverviewHeader();
  renderOverviewRules();
  renderRecentActivity();
  renderLiveConnections();
  renderOnboarding();
}

function renderOnboarding() {
  const panel = $("onboardingPanel");
  if (!state.config || localStorage.getItem("proxyduck-onboarding-dismissed") === "1" || localStorage.getItem("proxydock-onboarding-dismissed") === "1") {
    panel.classList.add("hidden");
    return;
  }
  const dataPlane = state.runtimeStatus?.dataPlane;
  const steps = [
    [t("onboarding.core"), state.online],
    [t("onboarding.prerequisites"), Boolean(state.preflight?.desktopBridge && state.preflight?.webviewReady && state.preflight?.elevated)],
    [t("onboarding.proxy"), state.config.proxies.some((proxy) => proxy.enabled && state.testedProxyIds.has(proxy.id))],
    [t("onboarding.rule"), state.config.rules.some((rule) => rule.enabled)],
    [t("onboarding.runtime"), dataPlane?.phase === "running"]
  ];
  const complete = steps.every(([, done]) => done);
  panel.classList.toggle("hidden", complete);
  $("onboardingSteps").innerHTML = steps.map(([label, done], index) => `<div class="setting-row"><span><strong>${done ? "✓" : index + 1}. ${escapeHtml(label)}</strong></span>${statusBadge(t(done ? "common.enabled" : "common.paused"), done ? "success" : "neutral")}</div>`).join("");
}

function renderOverviewRules() {
  const rules = (state.config?.rules || []).filter((rule) => rule.enabled);
  $("overviewRuleList").innerHTML = rules.length ? rules.map((rule) => {
    const lastHit = [...state.hits].reverse().find((hit) => hit.ruleId === rule.id);
    const proxy = state.config.proxies.find((item) => item.id === (rule.action?.proxyId || rule.proxyProfile));
    const action = ruleActionType(rule);
    const dataPlaneRunning = state.runtimeStatus?.dataPlane?.phase === "running";
    const status = !state.config.runtime.enabled
      ? statusBadge(t("common.paused"), "neutral")
      : action !== "proxy" && dataPlaneRunning
        ? statusBadge(t("common.routing"), "success")
        : proxy?.enabled && dataPlaneRunning
        ? statusBadge(t("common.routing"), "success")
        : statusBadge(t(`runtimePhase.${state.runtimeStatus?.dataPlane?.phase || "starting"}`), "neutral");
    return `<div class="data-list data-row overview-rule-columns"><div class="cell-main"><strong>${escapeHtml(rule.name)}</strong><small title="${escapeHtml(matcherSummary(rule.matcher))}">${escapeHtml(matcherSummary(rule.matcher))}</small></div><div class="cell-main"><strong>${escapeHtml(ruleRouteName(rule))}</strong><small>${escapeHtml(protocolText(rule.protocols))}</small></div>${status}<time class="metadata">${lastHit ? escapeHtml(formatTime(lastHit.ts)) : "—"}</time></div>`;
  }).join("") : emptyState(t("empty.noActiveRules"), t("empty.noActiveRulesDescription"), true);
}

function renderRecentActivity() {
  const hits = [...state.hits].reverse().slice(0, 6);
  $("recentActivity").innerHTML = renderActivityRows(hits);
}

function renderActivityRows(hits) {
  return hits.length ? hits.map((hit) => `<div class="data-list data-row activity-columns"><time class="metadata">${escapeHtml(formatTime(hit.ts))}</time><div class="cell-main"><strong>${escapeHtml(hit.processName)}</strong><small>PID ${escapeHtml(hit.processPid)}</small></div><div class="cell-main"><strong>${escapeHtml(hit.proxyName)}</strong><small>${escapeHtml(hit.ruleName)} · ${escapeHtml(matchKindText(hit.matchKind))}</small></div>${statusBadge(t("common.routed"), "success")}</div>`).join("") : emptyState(t("empty.noActivity"), t("empty.noActivityDescription"), true);
}

function renderAllActivity() {
  $("allActivity").innerHTML = renderActivityRows([...state.hits].reverse());
}

function switchOverviewTab(tab) {
  state.overviewTab = tab;
  const recentTabBtn = $("overviewActivityTab");
  const liveTabBtn = $("overviewConnectionsTab");
  const recentTable = $("recentActivityTable");
  const liveTable = $("liveConnectionsTable");
  if (!recentTabBtn || !liveTabBtn) return;
  if (tab === "recent") {
    recentTabBtn.classList.add("active");
    liveTabBtn.classList.remove("active");
    recentTable.classList.remove("hidden");
    liveTable.classList.add("hidden");
    renderRecentActivity();
  } else {
    liveTabBtn.classList.add("active");
    recentTabBtn.classList.remove("active");
    liveTable.classList.remove("hidden");
    recentTable.classList.add("hidden");
    loadLiveConnections();
  }
}

async function loadLiveConnections() {
  try {
    const res = await api.getConnections(50);
    state.connections = Array.isArray(res) ? res : (res?.connections || []);
  } catch (_) {
    state.connections = [];
  }
  renderLiveConnections();
}

function renderLiveConnections() {
  const container = $("liveConnectionsList");
  if (!container) return;
  const connections = state.connections || [];
  if (!connections.length) {
    container.innerHTML = emptyState(t("empty.noActivity"), t("empty.noActivityDescription"), true);
    return;
  }
  container.innerHTML = connections.map((conn) => {
    const timeStr = conn.createdAt ? formatTime(conn.createdAt) : "—";
    const procName = conn.processName || `PID ${conn.pid}`;
    const target = conn.destDomain ? `${conn.destDomain}:${conn.destPort}` : `${conn.destIp || '—'}:${conn.destPort || '—'}`;
    const route = conn.proxyName || conn.action || t("common.direct");
    return `<div class="data-list data-row live-connection-columns">
      <time class="metadata">${escapeHtml(timeStr)}</time>
      <div class="cell-main"><strong>${escapeHtml(procName)}</strong><small>PID ${escapeHtml(conn.pid)}</small></div>
      <div class="cell-main"><strong>${escapeHtml(target)}</strong><small>${escapeHtml((conn.protocol || "tcp").toUpperCase())}</small></div>
      <div class="cell-main"><strong>${escapeHtml(route)}</strong></div>
      <button class="button small ghost" data-explain-conn data-process="${escapeHtml(procName)}" data-pid="${escapeHtml(conn.pid)}" data-target="${escapeHtml(target)}" data-dest="${escapeHtml(conn.destDomain || conn.destIp || '')}" data-port="${escapeHtml(conn.destPort || 0)}" data-proto="${escapeHtml(conn.protocol || 'tcp')}">${escapeHtml(t("overview.explain"))}</button>
    </div>`;
  }).join("");
}

function localSimulateRule(info) {
  const rules = state.config?.rules || [];
  const proc = (info.process || "").toLowerCase();
  for (const r of rules) {
    if (!r.enabled) continue;
    const m = r.matcher || {};
    const matchesApp = (m.appNames || []).some((a) => proc.includes(a.toLowerCase()));
    const matchesExe = (m.exePaths || []).some((e) => proc.includes(e.toLowerCase()));
    if (matchesApp || matchesExe) {
      const act = ruleActionType(r);
      return {
        matched_rule_id: r.id,
        matched_rule_name: r.name,
        action: act,
        target_proxy: ruleRouteName(r),
        proxy_id: r.action?.proxyId || r.proxyProfile
      };
    }
  }
  return {
    matched_rule_id: null,
    matched_rule_name: null,
    action: "direct",
    target_proxy: t("common.direct")
  };
}

async function openExplainModal(info) {
  const modal = $("explainModal");
  if (!modal) return;
  $("explainModalTarget").textContent = `${info.process || 'PID ' + info.pid} → ${info.target || 'Destination'}`;
  const summaryBox = $("explainSummary");
  const chainList = $("explainChainList");
  summaryBox.innerHTML = `<div class="loading-state"><span></span><span>正在追溯决策链…</span></div>`;
  chainList.innerHTML = "";
  modal.showModal();

  let simResult = null;
  try {
    simResult = await api.simulateRule({
      process_name: info.process?.replace(/\.exe$/i, ""),
      process_path: info.process,
      dest_domain: info.dest,
      dest_port: Number(info.port) || 0,
      protocol: info.proto || "tcp"
    });
  } catch (_) {
    simResult = localSimulateRule(info);
  }

  const action = simResult?.action || "direct";
  const matchedRuleName = simResult?.matched_rule_name || t("simulator.noRuleMatched");
  const targetProxy = simResult?.target_proxy || proxyName(simResult?.proxy_id || "direct");
  const tone = action === "proxy" ? "success" : action === "block" || action === "reject" ? "danger" : "neutral";

  summaryBox.innerHTML = `
    <div class="explain-summary-row"><span>${escapeHtml(t("explain.decision"))}</span>${statusBadge(action.toUpperCase(), tone)}</div>
    <div class="explain-summary-row"><span>${escapeHtml(t("explain.matchedRule"))}</span><strong>${escapeHtml(matchedRuleName)}</strong></div>
    <div class="explain-summary-row"><span>${escapeHtml(t("explain.outboundProxy"))}</span><strong>${escapeHtml(targetProxy)}</strong></div>
    <div class="explain-summary-row"><span>${escapeHtml(t("explain.dnsProtection"))}</span><small>${state.config?.runtime?.dnsEnforced ? escapeHtml(t("explain.dnsBlocked")) : escapeHtml(t("explain.dnsAllowed"))}</small></div>
    <div class="explain-summary-row"><span>${escapeHtml(t("explain.killSwitch"))}</span><small>${state.config?.runtime?.leakProtectionMode === "strict" ? escapeHtml(t("explain.killSwitchActive")) : escapeHtml(t("explain.killSwitchInactive"))}</small></div>
  `;

  const rules = state.config?.rules || [];
  if (!rules.length) {
    chainList.innerHTML = `<p class="metadata">${escapeHtml(t("simulator.noRuleMatched"))}</p>`;
    return;
  }
  chainList.innerHTML = rules.map((r) => {
    const isMatched = simResult?.matched_rule_id === r.id;
    return `<div class="explain-step ${isMatched ? "matched" : "skipped"}">
      <span class="step-badge ${isMatched ? "matched" : "skipped"}">${isMatched ? "MATCH" : "SKIP"}</span>
      <div class="cell-main">
        <strong>${escapeHtml(r.name)}</strong>
        <small>${isMatched ? escapeHtml(t("explain.chainMatched")) : escapeHtml(t("explain.chainSkipped"))} · ${escapeHtml(matcherSummary(r.matcher))}</small>
      </div>
    </div>`;
  }).join("");
}

async function runSimulation() {
  const process_name = $("simProcess").value.trim();
  const dest_domain = $("simDestination").value.trim();
  const dest_port = Number($("simPort").value) || 0;
  const protocol = $("simProtocol").value || "tcp";
  const resultBox = $("simResultBox");
  const resultContent = $("simResultContent");

  resultBox.classList.remove("hidden");
  resultContent.innerHTML = `<div class="loading-state"><span></span><span>正在执行仿真分析…</span></div>`;

  let simResult;
  try {
    simResult = await api.simulateRule({ process_name, dest_domain, dest_port, protocol });
  } catch (_) {
    simResult = localSimulateRule({ process: process_name, dest: dest_domain, port: dest_port, proto: protocol });
  }

  const action = simResult?.action || "direct";
  const tone = action === "proxy" ? "success" : action === "block" || action === "reject" ? "danger" : "neutral";
  const matchedRuleName = simResult?.matched_rule_name || t("simulator.noRuleMatched");
  const targetProxy = simResult?.target_proxy || proxyName(simResult?.proxy_id || "direct");

  resultContent.innerHTML = `
    <div class="explain-summary-card" style="margin-top: 8px;">
      <div class="explain-summary-row"><span>${escapeHtml(t("simulator.finalAction"))}</span>${statusBadge(action.toUpperCase(), tone)}</div>
      <div class="explain-summary-row"><span>${escapeHtml(t("simulator.matchedRuleName"))}</span><strong>${escapeHtml(matchedRuleName)}</strong></div>
      <div class="explain-summary-row"><span>${escapeHtml(t("simulator.targetProxy"))}</span><strong>${escapeHtml(targetProxy)}</strong></div>
      ${simResult?.matched_rule_id ? `<div class="explain-summary-row"><span>${escapeHtml(t("simulator.matchedRuleId"))}</span><code>${escapeHtml(simResult.matched_rule_id)}</code></div>` : ""}
    </div>
  `;
}

async function runEndpointDiscovery() {
  const container = $("discoveredEndpointsList");
  if (!container) return;
  container.innerHTML = `<div class="loading-state"><span></span><span>${escapeHtml(t("discovery.scanning"))}</span></div>`;
  try {
    const list = await api.discoverEndpoints(1500);
    state.discoveredEndpoints = list || [];
    renderDiscoveredEndpoints();
  } catch (error) {
    container.innerHTML = `<p class="metadata" style="padding: 12px;">${escapeHtml(t("discovery.noEndpoints"))}</p>`;
  }
}

function renderDiscoveredEndpoints() {
  const container = $("discoveredEndpointsList");
  if (!container) return;
  const list = state.discoveredEndpoints || [];
  if (!list.length) {
    container.innerHTML = `<p class="metadata" style="padding: 12px;">${escapeHtml(t("discovery.noEndpoints"))}</p>`;
    return;
  }
  container.innerHTML = list.map((ep) => `
    <div class="data-list discovery-columns" style="align-items:center;">
      <div class="cell-main"><strong>${escapeHtml(ep.clientName || ep.name || "Proxy")}</strong><small>${escapeHtml(t("discovery.detected"))}</small></div>
      <span><code>${escapeHtml(ep.port)}</code></span>
      <span><span class="tag">${escapeHtml((ep.protocol || "socks5").toUpperCase())}</span></span>
      <button class="button small primary" data-add-endpoint-client="${escapeHtml(ep.clientName || ep.name || 'Discovered')}" data-add-endpoint-port="${escapeHtml(ep.port)}" data-add-endpoint-proto="${escapeHtml(ep.protocol || 'socks5')}">${escapeHtml(t("discovery.addEndpoint"))}</button>
    </div>
  `).join("");
}

async function addDiscoveredEndpointItem(clientName, port, proto) {
  const name = `${clientName} (:${port})`;
  const kind = proto.toLowerCase() === "http" ? "http" : "socks5";
  const endpoint = `127.0.0.1:${port}`;
  try {
    await api.addDiscoveredEndpoint({ name, kind, endpoint });
  } catch (_) {
    await api.post("/proxies", { name, kind, endpoint, auth: null });
  }
  await loadConfig();
  toast(t("toast.proxyAdded", { name }) || `${name} 已成功添加为代理端点`);
  $("discoveryModal")?.close();
}

async function loadTimelineEvents() {
  const container = $("timelineEventsList");
  if (!container) return;
  container.innerHTML = `<div class="loading-state"><span></span><span>正在加载审计时间线…</span></div>`;
  try {
    const list = await api.getTimeline(100);
    state.timelineEvents = list || [];
    renderTimelineEvents();
  } catch (_) {
    state.timelineEvents = [];
    renderTimelineEvents();
  }
}

function renderTimelineEvents() {
  const container = $("timelineEventsList");
  if (!container) return;
  const events = state.timelineEvents || [];
  if (!events.length) {
    container.innerHTML = emptyState(t("timeline.empty"), "", true);
    return;
  }
  container.innerHTML = events.map((ev) => `
    <div class="data-list timeline-columns" style="align-items:center;">
      <time class="metadata">${escapeHtml(formatTime(ev.timestamp || ev.ts || Date.now()))}</time>
      <span><span class="tag">${escapeHtml(ev.category || "audit")}</span></span>
      <div class="cell-main"><strong>${escapeHtml(ev.summary || ev.message || "")}</strong><small>${escapeHtml(ev.details || "")}</small></div>
    </div>
  `).join("");
}

async function clearTimelineEvents() {
  const confirmed = await confirmAction(t("timeline.clear"), "确定清空所有事件审计记录？");
  if (!confirmed) return;
  await api.clearTimeline();
  state.timelineEvents = [];
  renderTimelineEvents();
  toast(t("timeline.clear") + " 成功");
}

async function loadAutostartConfig() {
  if (!window.__TAURI__) {
    $("autostartStatusHint").textContent = "桌面专属能力 (Tauri 模式)";
    return;
  }
  try {
    const res = await api.getAutostartStatus();
    state.autostartStatus = res;
    $("autostartEnabled").checked = Boolean(res.enabled);
    $("autostartSilent").checked = Boolean(res.silent);
    $("autostartStatusHint").textContent = res.method === "task_scheduler"
      ? t("autostart.modeTaskScheduler")
      : t("autostart.modeRegistry");
  } catch (error) {
    $("autostartStatusHint").textContent = normalizeError(error);
  }
}

async function handleAutostartChange() {
  if (!window.__TAURI__) return;
  const enabled = $("autostartEnabled").checked;
  const silent = $("autostartSilent").checked;
  try {
    await api.setAutostartConfig(enabled, silent);
    toast(t("autostart.saveSuccess"));
    await loadAutostartConfig();
  } catch (error) {
    reportError(error, t("autostart.saveFailed"));
  }
}

async function checkAppUpdates() {
  const statusLabel = $("updateCheckStatus");
  statusLabel.textContent = t("updater.checking");
  try {
    const res = await api.checkForAppUpdates();
    state.updateInfo = res;
    if (res.hasUpdate) {
      statusLabel.textContent = t("updater.foundNew", { version: res.latestVersion });
      $("updateModalVersion").textContent = `v${res.latestVersion} (当前: v${res.currentVersion})`;
      $("updateReleaseNotes").textContent = res.releaseNotes || "无更新说明";
      $("updateDownloadProgress").classList.add("hidden");
      $("confirmInstallUpdateBtn").disabled = false;
      $("updateModal").showModal();
    } else {
      statusLabel.textContent = t("updater.upToDate");
      toast(t("updater.upToDate"));
    }
  } catch (error) {
    statusLabel.textContent = normalizeError(error);
    reportError(error, "检查更新失败");
  }
}

async function installAppUpdate() {
  if (!state.updateInfo?.downloadUrl) return;
  const progressBox = $("updateDownloadProgress");
  const btn = $("confirmInstallUpdateBtn");
  btn.disabled = true;
  progressBox.classList.remove("hidden");
  progressBox.textContent = t("updater.downloading");
  try {
    await api.installAppUpdate(state.updateInfo.downloadUrl);
    progressBox.textContent = t("updater.readyToInstall");
  } catch (error) {
    progressBox.textContent = t("updater.downloadFailed");
    reportError(error, t("updater.downloadFailed"));
    btn.disabled = false;
  }
}

function renderRules() {
  if (!state.config) return;
  const query = $("ruleSearch").value.trim().toLowerCase();
  const rules = state.config.rules.filter((rule) => {
    const haystack = `${rule.name} ${rule.group || ""} ${(rule.tags || []).join(" ")} ${matcherSummary(rule.matcher)} ${ruleRouteName(rule)}`.toLowerCase();
    return !query || haystack.includes(query);
  });
  $("ruleList").innerHTML = rules.length ? rules.map((rule) => {
    const managed = rule.source === "quick_bar";
    const conflict = state.ruleConflicts.some((item) => item.firstRuleId === rule.id || item.secondRuleId === rule.id);
    const index = state.config.rules.findIndex((item) => item.id === rule.id);
    const labels = [rule.group, ...(rule.tags || [])].filter(Boolean).join(" · ");
    return `<div class="data-list data-row rule-columns"><div class="cell-main"><input class="rule-select" type="checkbox" data-rule-select data-id="${escapeHtml(rule.id)}" ${managed ? "disabled" : ""} aria-label="${escapeHtml(rule.name)}"/><strong>${escapeHtml(rule.name)}</strong><small>${escapeHtml(ruleSourceText(rule.source))}${labels ? ` · ${escapeHtml(labels)}` : ""}${conflict ? ` · ${escapeHtml(t("rules.conflict"))}` : ""}</small></div><div class="cell-main"><strong title="${escapeHtml(matcherSummary(rule.matcher))}">${escapeHtml(matcherSummary(rule.matcher))}</strong><small>${escapeHtml(t(rule.autoBindChildren ? "rules.childProcesses" : "rules.currentProcess"))}</small></div><span class="tag">${escapeHtml(ruleRouteName(rule))}</span><span class="tag">${escapeHtml(protocolText(rule.protocols))}</span>${managed ? statusBadge(t(rule.enabled ? "common.enabled" : "common.paused"), rule.enabled ? "success" : "neutral") : `<span class="switch-control compact"><input class="inline-switch" type="checkbox" data-action="toggle-rule" data-id="${escapeHtml(rule.id)}" ${rule.enabled ? "checked" : ""} aria-label="${escapeHtml(t(rule.enabled ? "common.enabled" : "common.disabled"))}: ${escapeHtml(rule.name)}"/><span class="switch-track" aria-hidden="true"></span></span>`}<div class="row-actions">${managed ? "" : `<button class="mini-button" data-action="move-rule-up" data-id="${escapeHtml(rule.id)}" ${index <= 0 ? "disabled" : ""} title="${escapeHtml(t("rules.moveUp"))}">↑</button><button class="mini-button" data-action="move-rule-down" data-id="${escapeHtml(rule.id)}" ${index >= state.config.rules.length - 1 ? "disabled" : ""} title="${escapeHtml(t("rules.moveDown"))}">↓</button><button class="mini-button" data-action="edit-rule" data-id="${escapeHtml(rule.id)}" title="${escapeHtml(t("common.edit"))}"><svg><use href="#i-settings"/></svg></button><button class="mini-button" data-action="duplicate-rule" data-id="${escapeHtml(rule.id)}" title="${escapeHtml(t("common.duplicate"))}"><svg><use href="#i-plus"/></svg></button><button class="mini-button danger" data-action="delete-rule" data-id="${escapeHtml(rule.id)}" title="${escapeHtml(t("common.delete"))}"><svg><use href="#i-trash"/></svg></button>`}</div></div>`;
  }).join("") : emptyState(t(query ? "empty.noMatchingRules" : "empty.noRules"), t(query ? "empty.changeSearch" : "empty.createFirstRule"));
}

function renderProfiles() {
  const profiles = state.config?.profiles || [];
  const activeId = state.config?.activeProfileId || "";
  $("profileList").innerHTML = profiles.length ? profiles.map((profile) => {
    const active = profile.id === activeId;
    const changed = active ? t("profiles.active") : t("profiles.inactive");
    return `<div class="data-list data-row profile-columns"><div class="cell-main"><strong>${escapeHtml(profile.name)}</strong><small>${escapeHtml(profile.description || t("profiles.noDescription"))}</small></div><span class="tag">${escapeHtml(profile.engineMode || "—")}</span>${statusBadge(changed, active ? "success" : "neutral")}<span class="metadata">${escapeHtml(String((profile.rules || []).length))}</span><div class="row-actions"><button class="button ghost small" data-action="diff-profile" data-id="${escapeHtml(profile.id)}">${escapeHtml(t("profiles.diff"))}</button><button class="button ghost small" data-action="clone-profile" data-id="${escapeHtml(profile.id)}">${escapeHtml(t("profiles.clone"))}</button>${active ? "" : `<button class="button primary small" data-action="activate-profile" data-id="${escapeHtml(profile.id)}">${escapeHtml(t("profiles.activate"))}</button>`}<button class="mini-button danger" data-action="delete-profile" data-id="${escapeHtml(profile.id)}" title="${escapeHtml(t("common.delete"))}"><svg><use href="#i-trash"/></svg></button></div></div>`;
  }).join("") : emptyState(t("profiles.empty"), t("profiles.emptyDescription"), true);
}

function renderProxies() {
  const proxies = state.config?.proxies || [];
  $("proxyGrid").innerHTML = proxies.length ? proxies.map((proxy) => { const health = proxyHealth(proxy.id); const latency = proxyLatencySummary(health); return `<div class="data-list data-row proxy-columns"><div class="proxy-identity"><svg><use href="#i-server"/></svg><div><strong>${escapeHtml(proxy.name)}</strong><small>${escapeHtml(proxy.id)}</small></div></div><span class="tag">${escapeHtml(proxyKindText(proxy.kind))}</span><code class="endpoint" title="${escapeHtml(proxy.endpoint)}">${escapeHtml(proxy.kind === "direct" ? t("common.direct") : proxy.endpoint)}</code><div class="status-control">${statusBadge(proxyHealthText(health), health?.state === "healthy" ? "success" : health?.state === "offline" || health?.state === "authFailed" ? "danger" : "neutral")}${latency ? `<small class="metadata">${escapeHtml(latency)}</small>` : ""}<span class="switch-control compact"><input class="inline-switch" type="checkbox" data-action="toggle-proxy" data-id="${escapeHtml(proxy.id)}" ${proxy.enabled ? "checked" : ""} aria-label="${escapeHtml(t(proxy.enabled ? "common.enabled" : "common.disabled"))}: ${escapeHtml(proxy.name)}"/><span class="switch-track" aria-hidden="true"></span></span></div><div class="row-actions"><button class="mini-button" data-action="test-proxy" data-id="${escapeHtml(proxy.id)}" title="${escapeHtml(t("proxies.test"))}"><svg><use href="#i-pulse"/></svg></button><button class="mini-button danger" data-action="delete-proxy" data-id="${escapeHtml(proxy.id)}" title="${escapeHtml(t("common.delete"))}"><svg><use href="#i-trash"/></svg></button></div></div>`; }).join("") : emptyState(t("empty.noProxies"), t("empty.noProxiesDescription"));
}

function renderLaunches() {
  const items = state.config?.quickBar || [];
  const rows = items.length ? items.map((item) => `<div class="data-list data-row launch-columns"><div class="launch-identity"><span class="app-avatar" data-exe="${escapeHtml(item.exePath)}">${escapeHtml(initials(item.name))}</span><div><strong>${escapeHtml(item.name)}</strong><small>${escapeHtml(t(item.autoBindChildren ? "launch.childProcesses" : "launch.mainProcessOnly"))}</small></div></div><span class="tag">${escapeHtml(proxyName(item.proxyProfile))}</span><span class="metadata">${escapeHtml(startModeText(item.startMode))}</span><code class="path-cell" title="${escapeHtml(item.exePath)}">${escapeHtml(item.exePath)}</code><div class="row-actions"><button class="mini-button launch-button" data-action="launch-quick" data-id="${escapeHtml(item.id)}" title="${escapeHtml(t("launch.start"))}"><svg><use href="#i-play"/></svg></button><button class="mini-button danger" data-action="delete-launch" data-id="${escapeHtml(item.id)}" title="${escapeHtml(t("common.delete"))}"><svg><use href="#i-trash"/></svg></button></div></div>`).join("") : emptyState(t("empty.noLaunches"), t("empty.noLaunchesDescription"), true);
  $("launchGrid").innerHTML = `${rows}<button class="launch-add-row" data-open-modal="launch"><span><svg><use href="#i-plus"/></svg></span>${escapeHtml(t("common.addApplication"))}</button>`;
  hydrateAppIcons($("launchGrid"));
}

function renderProcesses() {
  const query = $("processSearch").value.trim().toLowerCase();
  const processes = state.processes.filter((process) => {
    const haystack = `${process.pid} ${process.name} ${process.exe}`.toLowerCase();
    return !query || haystack.includes(query);
  }).slice(0, 350);
  $("processCount").textContent = t("processes.count", { shown: processes.length, total: state.processes.length });
  $("processList").innerHTML = processes.length ? processes.map((process) => `<div class="data-list data-row process-columns"><div class="cell-main"><strong>${escapeHtml(process.name)}</strong><small>${escapeHtml(fileName(process.exe))}</small></div><span class="tag">${escapeHtml(process.pid)}</span><div class="path-cell" title="${escapeHtml(process.exe)}">${escapeHtml(process.exe || t("processes.systemPath"))}</div><div class="row-actions"><button class="button ghost small" data-action="evaluate-process" data-pid="${escapeHtml(process.pid)}">${escapeHtml(t("processes.evaluate"))}</button><button class="button ghost small" data-action="rule-from-process" data-name="${escapeHtml(encodeURIComponent(process.name))}" data-exe="${escapeHtml(encodeURIComponent(process.exe || ""))}" data-pid="${escapeHtml(process.pid)}" data-creation-time="${escapeHtml(process.creationTime ?? "")}"><svg><use href="#i-plus"/></svg>${escapeHtml(t("common.rule"))}</button></div></div>`).join("") : emptyState(t(query ? "empty.noMatchingProcesses" : "empty.noProcesses"), t(query ? "empty.changeSearch" : "empty.waitForScan"));
}

function renderDiagnostics() {
  const renderRank = (items, nameKey, detail) => items.length ? items.slice(0, 10).map((item, index) => `<div class="rank-row"><span>${index + 1}</span><div><strong>${escapeHtml(item[nameKey])}</strong><small>${escapeHtml(detail(item))}</small></div><b>${formatNumber(item.matches ?? item.hits)}</b></div>`).join("") : emptyState(t("empty.noStats"), t("empty.noStatsDescription"), true);
  $("ruleStatsList").innerHTML = renderRank(state.ruleStats, "ruleName", (item) => `${item.proxyName} · ${ruleSourceText(item.source)}`);
  $("proxyStatsList").innerHTML = renderRank(state.proxyStats, "proxyName", (item) => item.proxyId);
  const logs = [...state.logs].reverse().slice(0, 120);
  $("logList").innerHTML = logs.length ? logs.map((log) => `<div class="log-line"><span>${escapeHtml(formatTime(log.ts))}</span><span class="level-${escapeHtml(log.level.toLowerCase())}">${escapeHtml(log.level.toUpperCase())}</span><span>${escapeHtml(log.source)}</span><span>${escapeHtml(log.message)}</span></div>`).join("") : emptyState(t("empty.noLogs"), t("empty.noLogsDescription"), true);
}

function renderSettings() {
  if (!state.config) return;
  renderCapabilities();
  $("languageSelect").value = getLanguage();
  $("engineMode").value = state.config.engineMode;
  $("logLevel").value = state.config.runtime.logLevel || "info";
  $("leakProtectionMode").value = state.config.runtime.leakProtectionMode || "availability";
  $("dnsEnforced").checked = Boolean(state.config.runtime.dnsEnforced);
  $("ipv6Blocked").checked = Boolean(state.config.runtime.ipv6Blocked);
  $("dohBlocked").checked = Boolean(state.config.runtime.dohBlocked);
  $("coreUrlValue").textContent = api.baseUrl;
  $("configVersionValue").textContent = `${state.config.version || state.health?.version || "—"} · schema ${state.config.schemaVersion ?? 0}`;
  const dataPlane = state.runtimeStatus?.dataPlane;
  $("dataPlaneStatusValue").textContent = dataPlane
    ? `${t(`runtimePhase.${dataPlane.phase}`)} · PID ${dataPlane.childPid || "—"} · ${dataPlane.proxyEndpointReachable === true ? t("settings.proxyReachable") : dataPlane.proxyEndpointReachable === false ? t("settings.proxyUnreachable") : t("settings.proxyUnknown")} · ${dataPlane.firewallRules} ${t("settings.firewallRuleUnit")}${dataPlane.failClosedActive ? ` · ${t("settings.failClosedActive")}` : ""}`
    : "—";
  $("dataPlaneStatusValue").title = dataPlane?.message || "";
  const diagnostics = state.runtimeStatus?.compileDiagnostics || [];
  const diagnosticValue = $("compileDiagnosticsValue");
  diagnosticValue.textContent = diagnostics.length
    ? diagnostics.map((item) => `${item.severity || "info"}: ${item.code || "diagnostic"}`).join(" · ")
    : "—";
  diagnosticValue.className = diagnostics.some((item) => String(item.severity).toLowerCase() === "error")
    ? "diagnostic-error"
    : diagnostics.some((item) => String(item.severity).toLowerCase() === "warning")
      ? "diagnostic-warning"
      : "";
  diagnosticValue.title = diagnostics.map((item) => item.message || item.code || "").filter(Boolean).join("\n");
}

function renderAll() {
  syncProxySelects();
  renderOverview();
  renderRules();
  renderProfiles();
  renderProxies();
  renderLaunches();
  if (state.processesLoaded) renderProcesses();
  renderDiagnostics();
  renderSettings();
}

function hydrateAppIcons(container) {
  container.querySelectorAll(".app-avatar[data-exe]").forEach((avatar) => {
    const path = avatar.dataset.exe;
    if (!path) return;
    requestAppIcon(path).then((src) => {
      if (src && avatar.isConnected) avatar.innerHTML = `<img src="${src}" alt="" />`;
    });
  });
}

function requestAppIcon(path) {
  if (iconCache.has(path)) return iconCache.get(path);
  const promise = iconQueue.then(() => api.get(`/icon/exe?exePath=${encodeURIComponent(path)}`, { timeout: 9000 })).catch(() => null);
  iconQueue = promise.catch(() => null);
  iconCache.set(path, promise);
  return promise;
}

async function loadConfig() {
  const [config, conflicts] = await Promise.all([api.get("/config"), api.get("/rules/conflicts")]);
  state.config = config;
  state.ruleConflicts = conflicts;
  renderAll();
}

function syncApiDiagnostics(diagnostics = api.lastDiagnostics) {
  if (!state.runtimeStatus) return;
  state.runtimeStatus = { ...state.runtimeStatus, compileDiagnostics: diagnostics || [] };
}

async function loadCapabilities() {
  state.capabilities = await api.get("/capabilities");
  if (state.config) renderCapabilities();
}

async function loadLiveData({ includeHealth = true } = {}) {
  const snapshot = await api.get("/snapshot");
  if (includeHealth || !state.health) state.health = snapshot.health;
  state.stats = snapshot.stats;
  state.runtimeStatus = snapshot.runtimeStatus;
  state.ruleStats = snapshot.ruleStats;
  state.proxyStats = snapshot.proxyStats;
  state.hits = snapshot.recentHits;
  state.logs = snapshot.logs;
  if (state.overviewTab === "connections" || state.currentView === "overview") {
    try {
      const connData = await api.getConnections(50);
      state.connections = Array.isArray(connData) ? connData : (connData?.connections || []);
    } catch (_) {}
  }
  setOnline(true);
  renderOverview();
  renderProxies();
  renderDiagnostics();
}

async function loadProcesses() {
  state.processes = await api.get("/processes", { timeout: 9000 });
  state.processesLoaded = true;
  renderProcesses();
}

async function refreshAll({ quiet = false } = {}) {
  if (state.refreshing) return;
  state.refreshing = true;
  $("refreshBtn").disabled = true;
  try {
    await Promise.all([loadCapabilities(), loadConfig(), loadLiveData(), state.currentView === "processes" ? loadProcesses() : Promise.resolve()]);
    if (!quiet) toast(t("toast.refreshed"), t("toast.refreshedDescription"));
  } catch (error) {
    setOnline(false, normalizeError(error));
    scheduleReconnect();
    if (!quiet) reportError(error, t("toast.refreshFailed"));
    throw error;
  } finally {
    state.refreshing = false;
    $("refreshBtn").disabled = false;
  }
}

function scheduleReconnect() {
  if (state.reconnectTimer || state.reconnectInFlight) return;
  state.reconnectTimer = window.setTimeout(async () => {
    state.reconnectTimer = null;
    if (document.hidden) {
      scheduleReconnect();
      return;
    }
    await connectWithRetry({ background: true });
  }, 3000);
}

async function connectWithRetry({ background = false } = {}) {
  if (state.reconnectInFlight) return false;
  state.reconnectInFlight = true;
  let lastError;
  try {
    for (let attempt = 0; attempt < 24; attempt += 1) {
      try {
        // Re-probe the installed service on every attempt; its state can
        // change after startup without the desktop process being restarted.
        await api.initializeSession();
        await refreshAll({ quiet: true });
        return true;
      } catch (error) {
        lastError = error;
        $("connectionMessage").textContent = t("connection.starting", { attempt: attempt + 1 });
        await new Promise((resolve) => window.setTimeout(resolve, 250));
      }
    }
    setOnline(false, normalizeError(lastError));
    if (!background) reportError(lastError, t("toast.coreFailed"));
    return false;
  } finally {
    state.reconnectInFlight = false;
    if (!state.online) scheduleReconnect();
  }
}

async function runAction(button, action) {
  if (button) button.disabled = true;
  try {
    await action();
    return true;
  } catch (error) {
    reportError(error);
    return false;
  } finally {
    if (button?.isConnected) button.disabled = false;
  }
}

function openModal(type, defaults = {}) {
  if (type === "launch" && !(state.config?.proxies || []).some((proxy) => proxy.enabled)) {
    toast(t("toast.proxyRequired"), t("toast.proxyRequiredDescription"), "error");
    switchView("proxies");
    return;
  }
  const modal = $(`${type}Modal`);
  if (!modal) return;
  if (type === "activity") {
    renderAllActivity();
    modal.showModal();
    return;
  }
  if (type === "simulator") {
    $("simResultBox")?.classList.add("hidden");
    if (defaults.process) $("simProcess").value = defaults.process;
    if (defaults.destination) $("simDestination").value = defaults.destination;
    if (defaults.port) $("simPort").value = defaults.port;
    modal.showModal();
    return;
  }
  if (type === "discovery") {
    modal.showModal();
    runEndpointDiscovery();
    return;
  }
  if (type === "timeline") {
    modal.showModal();
    loadTimelineEvents();
    return;
  }
  if (type === "explain") {
    openExplainModal(defaults);
    return;
  }
  if (type === "update") {
    modal.showModal();
    return;
  }
  const form = $(`${type}Form`);
  form.reset();
  if (type === "rule") {
    const rule = defaults.rule || null;
    state.editingRuleId = rule?.id || null;
    const matcher = rule?.matcher || {};
    state.rulePidCreationTime = matcher.pidCreationTime ?? defaults.pidCreationTime ?? null;
    const matchType = matcher.pids?.length ? "pids" : matcher.exePaths?.length ? "exePaths" : matcher.appNames?.length ? "appNames" : "wildcard";
    const matchValue = matchType === "wildcard" ? matcher.wildcard : matcher[matchType]?.[0];
    $("ruleTcp").checked = rule ? rule.protocols.includes("tcp") : true;
    $("ruleUdp").checked = rule ? rule.protocols.includes("udp") : true;
    $("ruleDns").checked = rule ? rule.protocols.includes("dns") : true;
    $("ruleChildren").checked = Boolean(rule?.autoBindChildren);
    $("ruleName").value = rule?.name || defaults.name || "";
    $("ruleGroup").value = rule?.group || defaults.group || "";
    $("ruleTags").value = (rule?.tags || defaults.tags || []).join(", ");
    $("ruleMatchType").value = rule ? matchType : defaults.matchType || "appNames";
    $("ruleMatchValue").value = rule ? matchValue || "" : defaults.matchValue || "";
    const action = ruleActionType(rule);
    $("ruleAction").value = action;
    $("ruleProxy").innerHTML = enabledProxyOptions(rule?.action?.proxyId || rule?.proxyProfile || defaults.proxy || "");
    $("ruleProxy").disabled = action !== "proxy";
    $("ruleProxy").required = action === "proxy";
    const destination = rule?.destination || {};
    $("ruleDestination").value = [...(destination.domains || []), ...(destination.ipCidrs || [])].join(", ");
    $("ruleDestinationPorts").value = (destination.ports || []).join(", ");
    $("ruleModalTitle").textContent = t(rule ? "modal.editRule" : "modal.createRule");
    $("ruleSubmitLabel").textContent = t(rule ? "common.save" : "modal.createRule");
  }
  if (type === "launch") {
    $("launchChildren").checked = true;
    $("launchName").value = defaults.name || "";
    $("launchExe").value = defaults.exe || "";
    $("launchProxy").innerHTML = enabledProxyOptions(defaults.proxy || "");
  }
  if (type === "proxy") {
    $("proxyKind").value = "socks5";
    syncProxyEndpointState();
  }
  renderCapabilities();
  modal.showModal();
  window.setTimeout(() => form.querySelector("input")?.focus(), 50);
}

function syncRuleActionState() {
  const proxy = $("ruleAction").value === "proxy";
  $("ruleProxy").disabled = !proxy;
  $("ruleProxy").required = proxy;
}

function syncProxyEndpointState() {
  const direct = $("proxyKind").value === "direct";
  $("proxyEndpoint").disabled = direct;
  $("proxyEndpoint").required = !direct;
  $("proxyEndpoint").placeholder = direct ? t("modal.directPlaceholder") : "127.0.0.1:7897";
  for (const control of [$("proxyUsername"), $("proxyPassword")]) {
    control.disabled = direct;
    if (direct) control.value = "";
  }
}

function confirmAction(title, message) {
  return new Promise((resolve) => {
    const modal = $("confirmModal");
    $("confirmTitle").textContent = title;
    $("confirmMessage").textContent = message;
    modal.returnValue = "";
    modal.addEventListener("close", () => resolve(modal.returnValue === "confirm"), { once: true });
    modal.showModal();
  });
}

async function switchEngineMode(control) {
  const previousMode = state.config?.engineMode;
  const nextMode = control.value;
  if (!previousMode || nextMode === previousMode) return;
  const capability = state.capabilities.find((item) => item.mode === nextMode);
  if (!capability?.available) throw new Error(capability?.unavailableReason || t("settings.engineUnavailable"));
  await api.post("/engine/mode", { mode: nextMode });
  await Promise.all([loadConfig(), loadCapabilities(), loadLiveData({ includeHealth: true })]);
  toast(t("toast.engineSwitched"), t("toast.engineSwitchedDescription", { engine: capability.displayName }));
}

function sanitizedConfig() {
  const config = structuredClone(state.config);
  for (const proxy of config?.proxies || []) {
    proxy.requiresSecret = Boolean(proxy.passwordRef || proxy.password);
    proxy.password = null;
    proxy.passwordRef = null;
  }
  return config;
}

function downloadJson(fileName, data) {
  const blob = new Blob([`${JSON.stringify(data, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = fileName;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function exportConfig() {
  downloadJson(`proxyduck-config-${new Date().toISOString().slice(0, 10)}.json`, sanitizedConfig());
  toast(t("toast.configExported"));
}

async function exportDiagnostics() {
  const blob = await api.download("/diagnostics/bundle");
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `ProxyDuck-Diagnostics-${new Date().toISOString().replace(/[:.]/g, "-")}.zip`;
  anchor.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast(t("toast.diagnosticsExported"));
}

async function importConfigFile(file) {
  if (!file) return;
  const parsed = JSON.parse(await file.text());
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.rules) || !Array.isArray(parsed.proxies)) throw new Error(t("validation.configFile"));
  const preview = await api.post("/config/import/preview", parsed);
  const previewDiagnostics = api.lastDiagnostics;
  if (!preview.valid) {
    const error = new Error(preview.validationError || t("validation.importConfigPreviewInvalid"));
    error.diagnostics = previewDiagnostics;
    throw error;
  }
  const changedSections = (preview.changedSections || [])
    .map((section) => t(`confirm.configSection.${section}`))
    .join(t("confirm.configSectionSeparator")) || t("confirm.noConfigChanges");
  const previewDescription = t("confirm.importConfigPreviewDescription", {
    operation: t(`confirm.importOperation.${preview.operation || "replace"}`),
    changed: changedSections,
    proxies: preview.proposed?.proxyCount ?? 0,
    rules: preview.proposed?.ruleCount ?? 0,
    profiles: preview.proposed?.profileCount ?? 0,
    quickBar: preview.proposed?.quickBarCount ?? 0
  });
  if (!await confirmAction(t("confirm.importConfig"), previewDescription)) return;
  state.config = await api.put("/config", parsed);
  const diagnostics = api.lastDiagnostics;
  await loadConfig();
  syncApiDiagnostics(diagnostics);
  toast(t("toast.configImported"));
}

async function importProxyFile(file) {
  if (!file) return;
  const parsed = JSON.parse(await file.text());
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error(t("validation.proxyImportFile"));
  const preview = await api.post("/proxies/import/preview", parsed);
  const previewDiagnostics = api.lastDiagnostics;
  if (!preview.valid) {
    const error = new Error(preview.validationError || t("validation.proxyImportPreviewInvalid"));
    error.diagnostics = previewDiagnostics;
    throw error;
  }
  const disabled = (preview.items || []).filter((item) => item.enabled === false).length;
  const previewDescription = t("confirm.importProxiesPreviewDescription", {
    format: preview.format,
    added: preview.added ?? 0,
    updated: preview.updated ?? 0,
    skipped: preview.skipped ?? 0,
    disabled
  });
  if (!await confirmAction(t("confirm.importProxies"), previewDescription)) return;
  const applied = await api.post("/proxies/import", parsed);
  const diagnostics = api.lastDiagnostics;
  await loadConfig();
  syncApiDiagnostics(diagnostics);
  toast(t("toast.proxiesImported"), t("toast.proxiesImportedDescription", {
    added: applied.added ?? preview.added ?? 0,
    updated: applied.updated ?? preview.updated ?? 0,
    skipped: applied.skipped ?? preview.skipped ?? 0
  }));
}

async function submitProxy() {
  const kind = $("proxyKind").value;
  const endpoint = $("proxyEndpoint").value.trim();
  if (!validateEndpoint(kind, endpoint)) throw new Error(t("validation.endpoint"));
  await api.post("/proxies", {
    name: $("proxyName").value.trim(),
    kind,
    endpoint: kind === "direct" ? "direct" : endpoint,
    username: kind === "direct" ? null : $("proxyUsername").value.trim() || null,
    password: kind === "direct" ? null : $("proxyPassword").value || null,
    enabled: true
  });
  $("proxyModal").close();
  await loadConfig();
  toast(t("toast.proxyAdded"));
}

async function submitRule() {
  const matchType = $("ruleMatchType").value;
  const rawValue = $("ruleMatchValue").value.trim();
  const matcher = { appNames: [], exePaths: [], pids: [], hashes: [], wildcard: null, pidCreationTime: null };
  if (matchType === "pids") {
    const pid = Number(rawValue);
    if (!Number.isInteger(pid) || pid <= 0) throw new Error(t("validation.pid"));
    if (state.rulePidCreationTime === null || state.rulePidCreationTime === undefined) throw new Error(t("validation.pidCreationTime"));
    matcher.pids = [pid];
    if (state.rulePidCreationTime !== null && state.rulePidCreationTime !== undefined) {
      matcher.pidCreationTime = Number(state.rulePidCreationTime);
    }
  } else if (matchType === "wildcard") {
    matcher.wildcard = rawValue;
  } else {
    matcher[matchType] = [rawValue];
  }
  const protocols = [["tcp", $("ruleTcp")], ["udp", $("ruleUdp")], ["dns", $("ruleDns")]].filter(([, input]) => input.checked).map(([protocol]) => protocol);
  if (!protocols.length) throw new Error(t("validation.protocol"));
  const destinations = $("ruleDestination").value.split(",").map((value) => value.trim()).filter(Boolean);
  const domains = destinations.filter((value) => !value.includes("/"));
  const ipCidrs = destinations.filter((value) => value.includes("/"));
  const rawPorts = $("ruleDestinationPorts").value.split(",").map((value) => value.trim()).filter(Boolean);
  const ports = rawPorts.map((value) => Number(value));
  if (ports.some((value) => !Number.isInteger(value) || value <= 0 || value > 65535)) throw new Error(t("validation.destinationPort"));
  const existing = state.editingRuleId ? state.config.rules.find((rule) => rule.id === state.editingRuleId) : null;
  const actionType = $("ruleAction").value;
  if (actionType === "proxy" && !$("ruleProxy").value) throw new Error(t("validation.proxy"));
  const action = actionType === "proxy" ? { type: "proxy", proxyId: $("ruleProxy").value } : { type: actionType };
  const payload = {
    name: $("ruleName").value.trim(), group: $("ruleGroup").value.trim() || null,
    tags: $("ruleTags").value.split(",").map((value) => value.trim()).filter(Boolean),
    matcher, proxyProfile: $("ruleProxy").value || existing?.proxyProfile || "",
    action,
    protocols, enabled: existing?.enabled ?? true, autoBindChildren: $("ruleChildren").checked,
    forceDns: protocols.includes("dns"), blockIpv6: existing?.blockIpv6 ?? true, blockDoh: existing?.blockDoh ?? true,
    destination: { domains, ipCidrs, ports }
  };
  if (state.editingRuleId) await api.put(`/rules/${state.editingRuleId}`, payload);
  else await api.post("/rules", payload);
  $("ruleModal").close();
  await loadConfig();
  toast(t(existing ? "toast.ruleUpdated" : "toast.ruleCreated"));
  state.editingRuleId = null;
}

async function submitLaunch() {
  await api.post("/quickbar", {
    name: $("launchName").value.trim(), exePath: $("launchExe").value.trim(),
    proxyProfile: $("launchProxy").value, startMode: $("launchMode").value,
    runAsAdmin: $("launchAdmin").checked, autoBindChildren: $("launchChildren").checked
  });
  $("launchModal").close();
  await loadConfig();
  toast(t("toast.launchAdded"));
}

function selectedRuleIds() {
  return [...document.querySelectorAll(".rule-select:checked")]
    .map((control) => control.dataset.id)
    .filter(Boolean);
}

async function batchEnableRules(enabled) {
  const ruleIds = selectedRuleIds();
  if (!ruleIds.length) throw new Error(t("validation.rulesSelection"));
  await api.post("/rules/batch-enabled", { ruleIds, enabled });
  await loadConfig();
  toast(t("toast.ruleBatchUpdated", { count: ruleIds.length }));
}

function bindForm(formId, submit) {
  $(formId).addEventListener("submit", (event) => {
    event.preventDefault();
    if (event.submitter?.value === "cancel") {
      event.currentTarget.closest("dialog").close();
      return;
    }
    runAction(event.submitter, submit);
  });
}

async function handleAction(button) {
  const { action, id } = button.dataset;
  if (!action) return;
  if (action === "launch-quick") {
    const item = state.config?.quickBar?.find((entry) => entry.id === id);
    try {
      await api.post(`/quickbar/${id}/launch`, {});
      toast(t("toast.launchSent"));
    } catch (error) {
      if (window.__TAURI__ && item && String(error?.message || "").includes("Session 0")) {
        await invokeTauri("launch_desktop_process", {
          exePath: item.exePath,
          args: item.args || [],
          workDir: item.workDir || null,
          runAsAdmin: Boolean(item.runAsAdmin)
        });
        toast(t("toast.launchSent"));
      } else {
        throw error;
      }
    }
    return;
  }
  if (action === "rule-from-process") {
    const name = decodeURIComponent(button.dataset.name || "");
    const exe = decodeURIComponent(button.dataset.exe || "");
    openModal("rule", { name: getLanguage() === "en" ? `Route ${name}` : `${name} 路由`, matchType: exe ? "exePaths" : "appNames", matchValue: exe || name, pidCreationTime: button.dataset.creationTime ? Number(button.dataset.creationTime) : null });
    return;
  }
  if (action === "evaluate-process") {
    const result = await api.get(`/rules/evaluate/${button.dataset.pid}`);
    const selected = result.matches.find((match) => match.selected);
    const chain = result.matches.map((match) => `${match.ruleName} (${matchKindText(match.matchKind)})`).join(" → ");
    toast(selected ? t("processes.evaluationMatched") : t("processes.evaluationNoMatch"), selected ? `${selected.ruleName} · ${proxyName(selected.proxyId)}${chain ? ` · ${chain}` : ""}` : t("processes.evaluationNoMatchDescription"));
    return;
  }
  if (action === "edit-rule") {
    const rule = state.config.rules.find((item) => item.id === id);
    if (rule) openModal("rule", { rule });
    return;
  }
  if (action === "duplicate-rule") {
    await api.post(`/rules/${id}/duplicate`, {});
    await loadConfig();
    toast(t("toast.ruleDuplicated"));
    return;
  }
  if (action === "create-profile") {
    const name = window.prompt(t("profiles.namePrompt"));
    if (!name?.trim()) return;
    const description = window.prompt(t("profiles.descriptionPrompt"), "") || "";
    await api.post("/profiles", { name: name.trim(), description: description.trim() });
    await loadConfig();
    toast(t("profiles.created"));
    return;
  }
  if (action === "activate-profile") {
    const profile = (state.config?.profiles || []).find((item) => item.id === id);
    if (!profile) return;
    await api.post(`/profiles/${id}/activate`, {});
    await refreshAll({ quiet: true });
    toast(t("profiles.activated"), profile.name);
    return;
  }
  if (action === "clone-profile") {
    const profile = (state.config?.profiles || []).find((item) => item.id === id);
    if (!profile) return;
    const name = window.prompt(t("profiles.clonePrompt"), `${profile.name} Copy`);
    if (!name?.trim()) return;
    await api.post(`/profiles/${id}/clone`, { name: name.trim() });
    await loadConfig();
    toast(t("profiles.cloned"));
    return;
  }
  if (action === "diff-profile") {
    const diff = await api.get(`/profiles/${id}/diff`);
    const sections = (diff.changedSections || []).join(", ") || t("profiles.noChanges");
    toast(t("profiles.diff"), sections);
    return;
  }
  if (action === "move-rule-up" || action === "move-rule-down") {
    const rules = [...state.config.rules];
    const index = rules.findIndex((rule) => rule.id === id);
    const target = index + (action === "move-rule-up" ? -1 : 1);
    if (index < 0 || target < 0 || target >= rules.length) return;
    [rules[index], rules[target]] = [rules[target], rules[index]];
    await api.post("/rules/reorder", { ruleIds: rules.map((rule) => rule.id) });
    await loadConfig();
    toast(t("toast.ruleReordered"));
    return;
  }
  if (action === "toggle-rule") {
    const rule = state.config.rules.find((item) => item.id === id);
    if (!rule) return;
    await api.put(`/rules/${id}`, {
      name: rule.name, matcher: rule.matcher, proxyProfile: rule.proxyProfile,
      action: rule.action, network: rule.network, dns: rule.dns, destination: rule.destination,
      protocols: rule.protocols, enabled: button.checked, autoBindChildren: rule.autoBindChildren,
      forceDns: rule.forceDns, blockIpv6: rule.blockIpv6, blockDoh: rule.blockDoh
    });
    await loadConfig();
    toast(t(button.checked ? "toast.ruleEnabled" : "toast.rulePaused"));
    return;
  }
  if (action === "toggle-proxy") {
    const proxy = state.config.proxies.find((item) => item.id === id);
    if (!proxy) return;
    await api.put(`/proxies/${id}`, { name: proxy.name, kind: proxy.kind, endpoint: proxy.endpoint, enabled: button.checked });
    await loadConfig();
    toast(t(button.checked ? "toast.proxyEnabled" : "toast.proxyDisabled"));
    return;
  }
  if (action === "test-proxy") {
    const result = await api.post(`/proxies/${id}/test`, {});
    if (!result.protocolAccepted) throw new Error(result.error || t("proxies.testFailed"));
    state.testedProxyIds.add(id);
    renderOnboarding();
    const transportStatus = [];
    if (result.tcpSupported === true) transportStatus.push(t("proxies.tcpAvailable"));
    if (result.tcpSupported === false) transportStatus.push(t("proxies.tcpUnavailable", { error: result.tcpError || t("proxies.tcpRejected") }));
    if (result.udpSupported === true) transportStatus.push(t("proxies.udpAvailable"));
    if (result.udpSupported === false) transportStatus.push(t("proxies.udpUnavailable", { error: result.udpError || t("proxies.udpRejected") }));
    toast(t("proxies.testSucceeded"), [t("proxies.testLatency", { latency: result.latencyMs }), ...transportStatus].join(" · "));
    return;
  }

  const descriptors = {
    "delete-rule": [t("confirm.deleteRule"), t("confirm.deleteRuleDescription"), `/rules/${id}`],
    "delete-proxy": [t("confirm.deleteProxy"), t("confirm.deleteProxyDescription"), `/proxies/${id}`],
    "delete-launch": [t("confirm.deleteLaunch"), t("confirm.deleteLaunchDescription"), `/quickbar/${id}`],
    "delete-profile": [t("profiles.deleteTitle"), t("profiles.deleteDescription"), `/profiles/${id}`]
  };
  if (descriptors[action]) {
    const [title, message, path] = descriptors[action];
    if (!await confirmAction(title, message)) return;
    await api.delete(path);
    await loadConfig();
    toast(t("toast.itemDeleted"));
    return;
  }
}

// --- Network Doctor ---
async function loadDoctorStatus() {
  try {
    const data = await api.get("/network/status");
    state.doctorDiagnosis = data;
    renderDoctor(data);
  } catch (err) {
    reportError(err, "获取网络状态失败");
  }
}

async function runDiagnose() {
  const btn = $("runDiagnoseBtn");
  btn.disabled = true;
  btn.innerHTML = `<svg><use href="#i-refresh"/></svg><span>${escapeHtml(t("doctor.diagnosing"))}</span>`;
  try {
    const data = await api.post("/network/diagnose");
    state.doctorDiagnosis = data;
    renderDoctor(data);
    toast("体检完成", `发现 ${data.issues?.length || 0} 个网络与代理项`);
    if (data.issues && data.issues.length > 0) {
      loadRepairPlan(data.issues);
    } else {
      $("doctorRepairSection")?.classList.add("hidden");
      $("runRepairBtn")?.classList.add("hidden");
    }
  } catch (err) {
    reportError(err, "体检执行失败");
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg><use href="#i-pulse"/></svg><span>${escapeHtml(t("doctor.runDiagnose"))}</span>`;
  }
}

async function loadRepairPlan(issues) {
  try {
    const plan = await api.post("/network/repair/plan", { issues });
    state.doctorRepairPlan = plan;
    renderRepairPlan(plan);
  } catch (err) {
    console.error("Failed to build repair plan:", err);
  }
}

function renderDoctor(diag) {
  if (!diag) return;
  const banner = $("doctorOverallBanner");
  if (banner) {
    banner.className = `doctor-status-banner ${diag.status || "inconclusive"}`;
    const title = $("doctorOverallTitle");
    const subtitle = $("doctorOverallSubtitle");
    const meta = $("doctorOverallMeta");

    if (diag.status === "normal") {
      title.textContent = "网络与代理状态良好";
      subtitle.textContent = "10 层链路均正常通行，未发现阻断或死端口";
    } else if (diag.status === "warning") {
      title.textContent = "检测到部分网络或代理隐患";
      subtitle.textContent = `发现 ${diag.issues?.length || 0} 个异常项，建议参考修复建议`;
    } else {
      title.textContent = "网络或关键代理严重受损";
      subtitle.textContent = `发现 ${diag.issues?.length || 0} 个严重问题，可能导致网络完全中断`;
    }
    meta.innerHTML = `<small>体检时间: ${formatTime(diag.timestamp)}</small>`;
  }

  const layersGrid = $("doctorLayersGrid");
  if (layersGrid) {
    const layers = [
      { name: t("doctor.layerAdapter"), ok: Boolean(diag.adapters?.hasConnectedAdapter) },
      { name: t("doctor.layerRoute"), ok: Boolean(diag.routes?.hasDefaultRoute) },
      { name: t("doctor.layerGateway"), ok: Boolean(diag.gateway?.reachable) },
      { name: t("doctor.layerInternet"), ok: Boolean(diag.internet?.ipLevelConnected) },
      { name: t("doctor.layerDns"), ok: Boolean(diag.dns?.allResolvesSucceeded) },
      { name: t("doctor.layerNcsi"), ok: !diag.ncsi?.captivePortalDetected },
      { name: t("doctor.layerProxy"), ok: Boolean(diag.proxy?.wininetAccessible) && diag.proxy?.proxyPortReachable !== false },
      { name: t("doctor.layerDualPath"), ok: Boolean(diag.dualPath?.directInternetOk) },
      { name: t("doctor.layerWinsock"), ok: Boolean(diag.winsock?.isHealthy) },
      { name: t("doctor.layerHosts"), ok: Boolean(diag.hosts?.fileAccessible) },
    ];

    layersGrid.innerHTML = layers.map((l) => {
      const tone = l.ok ? "success" : "danger";
      const label = l.ok ? "正常" : "异常";
      return `<div class="layer-card">
        <span class="layer-card-title">${escapeHtml(l.name)}</span>
        ${statusBadge(label, tone)}
      </div>`;
    }).join("");
  }

  const issuesList = $("doctorIssuesList");
  if (issuesList) {
    if (!diag.issues || diag.issues.length === 0) {
      issuesList.innerHTML = `<div class="empty-state compact"><div><svg><use href="#i-check"/></svg><strong>未发现异常</strong><span>网络与代理链路正常</span></div></div>`;
    } else {
      issuesList.innerHTML = diag.issues.map((issue) => {
        const tone = issue.severity === "critical" ? "danger" : issue.severity === "warning" ? "warning" : "neutral";
        return `<div class="issue-card ${escapeHtml(issue.severity || "info")}">
          <div class="issue-header">
            <div style="display:flex;align-items:center;gap:8px;">
              ${statusBadge(issue.severity?.toUpperCase() || "INFO", tone)}
              <span class="issue-title">${escapeHtml(issue.title)}</span>
            </div>
            <small style="color:var(--muted)">置信度: ${escapeHtml(issue.confidence || "unknown")}</small>
          </div>
          <div class="issue-detail">${escapeHtml(issue.explanation || "")}</div>
          <div style="margin-top:6px;font-size:11px;color:var(--accent);">${escapeHtml((issue.suggestedActions || []).join("；"))}</div>
        </div>`;
      }).join("");
    }
  }
}

function renderRepairPlan(plan) {
  const section = $("doctorRepairSection");
  const list = $("doctorRepairPlanList");
  const runBtn = $("runRepairBtn");

  if (!plan || !plan.recommendedActions || plan.recommendedActions.length === 0) {
    section?.classList.add("hidden");
    runBtn?.classList.add("hidden");
    return;
  }

  section?.classList.remove("hidden");
  runBtn?.classList.remove("hidden");

  if (list) {
    list.innerHTML = plan.recommendedActions.map((act) => {
      const isL1 = act.level === "level1_safe";
      const badgeTone = isL1 ? "success" : "warning";
      const badgeText = isL1 ? t("doctor.level1Badge") : t("doctor.level2Badge");
      return `<div class="repair-action-item">
        <div>
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px;">
            ${statusBadge(badgeText, badgeTone)}
            <strong>${escapeHtml(act.title || act.id || "")}</strong>
          </div>
          <small style="color:var(--secondary)">${escapeHtml(act.description || "")}</small>
        </div>
        <small style="color:var(--muted)">${escapeHtml(act.impact || "")}</small>
      </div>`;
    }).join("");
  }
}

async function runRepair() {
  if (!state.doctorRepairPlan || !state.doctorRepairPlan.recommendedActions?.length) {
    toast("无待执行的修复项", "", "warning");
    return;
  }
  const btn = $("runRepairBtn");
  btn.disabled = true;
  btn.textContent = t("doctor.repairing");
  try {
    await api.post("/network/repair/run", {
      planId: state.doctorRepairPlan.planId,
      actions: state.doctorRepairPlan.recommendedActions.map((action) => action.id)
    });
    toast("智能急救已执行", "已自动创建网络快照并应用修复项");
    await runDiagnose();
    await loadSnapshots();
  } catch (err) {
    reportError(err, "执行急救失败");
  } finally {
    btn.disabled = false;
    btn.textContent = t("doctor.runRepair");
  }
}

async function loadSnapshots() {
  try {
    const list = await api.get("/network/snapshots");
    state.doctorSnapshots = list || [];
    renderSnapshots(state.doctorSnapshots);
  } catch (err) {
    console.error("Failed to load snapshots:", err);
  }
}

function renderSnapshots(snapshots) {
  const container = $("doctorSnapshotList");
  if (!container) return;
  if (!snapshots || snapshots.length === 0) {
    container.innerHTML = `<div class="empty-state compact"><div><svg><use href="#i-snapshot"/></svg><strong>${escapeHtml(t("doctor.noSnapshots"))}</strong><span>急救执行前会自动生成快照</span></div></div>`;
    return;
  }
  container.innerHTML = snapshots.map((s) => {
    const coverage = s.fullyReversible ? "完整恢复点" : "部分恢复点";
    return `<div class="data-list snapshot-columns" style="align-items:center;">
      <span>${escapeHtml(formatTime(s.createdAt))}</span>
      <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(s.reason || "系统快照")}</span>
      <span>${statusBadge(coverage, s.fullyReversible ? "success" : "warning")}</span>
      <span>${s.items?.length || 0} 项</span>
      <button class="button small ghost" data-rollback-snapshot="${escapeHtml(s.id)}">${escapeHtml(t("doctor.rollback"))}</button>
    </div>`;
  }).join("");
}

async function createSnapshot() {
  try {
    await api.post("/network/snapshot", { reason: "手动备份快照" });
    toast("快照已创建", "当前网络状态与代理配置已保存");
    await loadSnapshots();
  } catch (err) {
    reportError(err, "创建快照失败");
  }
}

async function rollbackSnapshot(id) {
  if (!confirm("确定要将网络配置回滚到该快照的状态吗？")) return;
  try {
    const report = await api.post("/network/restore", { snapshotId: id });
    if (!report.success) throw new Error("回滚未完整成功，请检查逐项结果");
    toast("回滚成功", "网络配置已成功恢复");
    await loadDoctorStatus();
    await loadSnapshots();
  } catch (err) {
    reportError(err, "回滚快照失败");
  }
}

// --- Config Studio ---
async function discoverConfigs() {
  const container = $("discoveredConfigList");
  if (!container) return;
  container.innerHTML = `<div class="loading-state"><span></span><span>${escapeHtml(t("studio.scanning"))}</span></div>`;
  try {
    const list = await api.post("/configs/discover", {});
    state.studioConfigs = list || [];
    renderDiscoveredConfigs(state.studioConfigs);
    if (state.studioConfigs.length > 0 && !state.studioActivePath) {
      inspectConfig(state.studioConfigs[0].path);
    }
  } catch (err) {
    reportError(err, "配置扫描失败");
    container.innerHTML = `<div class="empty-state compact"><div><svg><use href="#i-alert"/></svg><strong>扫描失败</strong><span>${escapeHtml(normalizeError(err))}</span></div></div>`;
  }
}

function renderDiscoveredConfigs(configs) {
  const container = $("discoveredConfigList");
  if (!container) return;
  if (!configs || configs.length === 0) {
    container.innerHTML = `<div class="empty-state compact"><div><svg><use href="#i-folder"/></svg><strong>${escapeHtml(t("studio.noConfigs"))}</strong><span>未检测到 Clash/sing-box 等配置文件</span></div></div>`;
    return;
  }
  container.innerHTML = configs.map((c) => {
    const activeClass = c.path === state.studioActivePath ? " active" : "";
    const formatName = c.format === "yaml" ? "Clash YAML" : c.format === "json" ? "sing-box JSON" : c.format?.toUpperCase();
    return `<div class="config-file-card${activeClass}" data-inspect-path="${escapeHtml(c.path)}">
      <div class="config-file-path" title="${escapeHtml(c.path)}">${escapeHtml(fileName(c.path))}</div>
      <div class="config-file-meta">
        <span>${escapeHtml(formatName)}</span>
        <span>${formatTime(c.mtimeRfc3339)}</span>
      </div>
    </div>`;
  }).join("");
}

async function inspectConfig(path) {
  state.studioActivePath = path;
  renderDiscoveredConfigs(state.studioConfigs);
  $("studioFilePath").textContent = fileName(path);
  $("studioFilePath").title = path;
  try {
    const doc = await api.post("/configs/inspect", { path });
    state.studioActiveDoc = doc;
    $("studioFileMeta").textContent = `${doc.format?.toUpperCase()} · SHA: ${(doc.sha256 || "").slice(0, 8)}`;
    $("studioRawEditor").value = doc.rawContent || "";

    const listeners = (doc.semantic?.inboundListeners || []).map((l) => `${l.name || l.protocol}:${l.port}`).join(", ") || "未检测到";
    $("pillListeners").innerHTML = `<span>监听端口: <strong>${escapeHtml(listeners)}</strong></span>`;
    $("pillEndpoints").innerHTML = `<span>节点数: <strong>${doc.semantic?.outboundEndpoints?.length || 0}</strong></span>`;
    $("pillRules").innerHTML = `<span>规则数: <strong>${doc.semantic?.routingRulesCount || 0}</strong></span>`;

    const conflicts = doc.conflicts || [];
    const conflictBox = $("studioConflictAlert");
    if (conflicts.length > 0) {
      conflictBox.classList.remove("hidden");
      const c = conflicts[0];
      $("studioConflictText").textContent = `端口 ${c.port} 与进程 ${c.process_name || c.pid} 冲突！`;
    } else {
      conflictBox.classList.add("hidden");
    }

    const firstPort = doc.semantic?.inboundListeners?.[0]?.port || 7890;
    $("visualPortInput").value = firstPort;

    $("studioDiffViewer").innerHTML = `<p class="diff-empty-note">尚未做出修改</p>`;
  } catch (err) {
    reportError(err, "加载配置文件失败");
  }
}

function switchStudioTab(tab) {
  state.studioCurrentTab = tab;
  document.querySelectorAll("[data-studio-tab]").forEach((btn) => btn.classList.toggle("active", btn.dataset.studioTab === tab));
  $("tabContentVisual")?.classList.toggle("active", tab === "visual");
  $("tabContentRaw")?.classList.toggle("active", tab === "raw");
  $("tabContentDiff")?.classList.toggle("active", tab === "diff");

  if (tab === "diff" && state.studioActiveDoc) {
    updateStudioDiff();
  }
}

function updateStudioDiff() {
  if (!state.studioActiveDoc) return;
  const original = state.studioActiveDoc.rawContent || "";
  let current = $("studioRawEditor").value;

  const visualPort = $("visualPortInput")?.value;
  if (visualPort && state.studioActiveDoc.semantic?.inboundListeners?.[0]?.port && Number(visualPort) !== state.studioActiveDoc.semantic.inboundListeners[0].port) {
    const oldP = String(state.studioActiveDoc.semantic.inboundListeners[0].port);
    current = current.replace(oldP, visualPort);
  }

  const origLines = original.split("\n");
  const currLines = current.split("\n");
  const diffLines = [];
  const max = Math.max(origLines.length, currLines.length);
  for (let i = 0; i < max; i++) {
    const o = origLines[i];
    const c = currLines[i];
    if (o !== c) {
      if (o !== undefined) diffLines.push(`<span class="diff-remove">- ${escapeHtml(o)}</span>`);
      if (c !== undefined) diffLines.push(`<span class="diff-add">+ ${escapeHtml(c)}</span>`);
    }
  }
  if (diffLines.length === 0) {
    $("studioDiffViewer").innerHTML = `<p class="diff-empty-note">内容与原文件完全一致，无修改</p>`;
  } else {
    $("studioDiffViewer").innerHTML = diffLines.join("\n");
  }
}

async function validateCurrentConfig() {
  if (!state.studioActiveDoc) return;
  const content = $("studioRawEditor").value;
  try {
    const res = await api.post("/configs/validate", {
      path: state.studioActivePath,
      content,
      format: state.studioActiveDoc.format
    });
    if (res.valid && !res.portConflicts?.some((item) => item.inUse)) {
      toast("校验通过", t("studio.validationPass"));
    } else {
      const issues = [];
      if (!res.valid) issues.push(`语法错误: ${(res.errors || []).join("；")}`);
      const conflicts = (res.portConflicts || []).filter((item) => item.inUse);
      if (conflicts.length) issues.push(`发现 ${conflicts.length} 处端口冲突`);
      toast("校验发现问题", issues.join("; "), "error");
    }
  } catch (err) {
    reportError(err, "校验失败");
  }
}

async function saveCurrentConfig() {
  if (!state.studioActiveDoc) return;
  const content = $("studioRawEditor").value;
  try {
    const res = await api.post("/configs/save", {
      path: state.studioActivePath,
      content,
      expectedSha256: state.studioActiveDoc.sha256,
      format: state.studioActiveDoc.format
    });
    toast(t("studio.saveSuccess"), `备份保存在: ${fileName(res.backupPath || "")}`);
    await inspectConfig(state.studioActivePath);
  } catch (err) {
    reportError(err, "保存失败");
  }
}

// --- Diagnostic History ---
async function loadDiagnosticHistory() {
  const container = $("historyList");
  if (!container) return;
  container.innerHTML = `<div class="loading-state"><span></span><span>正在加载历史记录…</span></div>`;
  try {
    const list = await api.get("/network/history");
    state.historyRuns = list || [];
    renderDiagnosticHistory(state.historyRuns);
  } catch (err) {
    reportError(err, "获取诊断历史失败");
  }
}

function renderDiagnosticHistory(runs) {
  const container = $("historyList");
  if (!container) return;
  if (!runs || runs.length === 0) {
    container.innerHTML = `<div class="empty-state compact"><div><svg><use href="#i-history"/></svg><strong>${escapeHtml(t("history.noHistory"))}</strong><span>尚未记录网络诊断结果</span></div></div>`;
    return;
  }
  container.innerHTML = runs.map((r) => {
    const tone = r.status === "normal" ? "success" : r.status === "warning" ? "warning" : "danger";
    const statusText = r.status === "normal" ? "正常" : r.status === "warning" ? "存在风险" : "严重受损";
    return `<div class="data-list history-columns" style="align-items:center;">
      <span>${escapeHtml(formatTime(r.timestamp))}</span>
      <span>${statusBadge(statusText, tone)}</span>
      <span>${r.issuesCount || 0} 项</span>
      <span>诊断摘要</span>
      <button class="button small ghost" data-view-history-detail="${escapeHtml(r.timestamp)}">${escapeHtml(t("history.viewDetails"))}</button>
    </div>`;
  }).join("");
}

function bindEvents() {
  document.body.addEventListener("click", (event) => {
    const button = event.target.closest("button");
    if (!button) return;
    if (button.dataset.view) switchView(button.dataset.view);
    if (button.dataset.viewJump) switchView(button.dataset.viewJump);
    if (button.dataset.openModal) openModal(button.dataset.openModal);
    if (button.hasAttribute("data-modal-close")) button.closest("dialog")?.close();
    if (button.dataset.action) runAction(button, () => handleAction(button));
  });
  document.body.addEventListener("change", (event) => {
    const control = event.target.closest('input[type="checkbox"][data-action]');
    if (!control) return;
    const previousChecked = !control.checked;
    runAction(control, () => handleAction(control)).then((succeeded) => {
      if (!succeeded && control.isConnected) control.checked = previousChecked;
    });
  });
  $("themeBtn").addEventListener("click", toggleTheme);
  $("languageSelect").addEventListener("change", (event) => switchLanguage(event.currentTarget.value));
  $("engineMode").addEventListener("change", (event) => {
    const control = event.currentTarget;
    const previousMode = state.config?.engineMode;
    runAction(control, () => switchEngineMode(control)).then((succeeded) => {
      if (!succeeded && control.isConnected) {
        control.value = previousMode;
        renderCapabilities();
      }
    });
  });
  $("refreshBtn").addEventListener("click", () => refreshAll().catch(() => {}));
  $("retryBtn").addEventListener("click", () => connectWithRetry());
  $("ruleSearch").addEventListener("input", renderRules);
  $("processSearch").addEventListener("input", renderProcesses);
  $("refreshLogsBtn").addEventListener("click", () => loadLiveData().catch((error) => reportError(error, t("toast.logsFailed"))));
  $("dismissOnboardingBtn").addEventListener("click", () => { localStorage.setItem("proxyduck-onboarding-dismissed", "1"); renderOnboarding(); });
  $("exportConfigBtn").addEventListener("click", exportConfig);
  $("exportDiagnosticsBtn").addEventListener("click", exportDiagnostics);
  $("importConfigBtn").addEventListener("click", () => $("importConfigFile").click());
  $("importConfigFile").addEventListener("change", (event) => runAction($("importConfigBtn"), () => importConfigFile(event.currentTarget.files?.[0])).finally(() => { event.currentTarget.value = ""; }));
  $("importProxiesBtn").addEventListener("click", () => $("importProxiesFile").click());
  $("importProxiesFile").addEventListener("change", (event) => runAction($("importProxiesBtn"), () => importProxyFile(event.currentTarget.files?.[0])).finally(() => { event.currentTarget.value = ""; }));
  $("runtimeToggle").addEventListener("click", () => runAction($("runtimeToggle"), async () => {
    if (!state.config) return;
    const enabled = !state.config.runtime.enabled;
    const runtime = await api.post("/runtime", { enabled });
    state.config.runtime = runtime;
    if (window.__TAURI__) await invokeTauri("sync_runtime_enabled", { enabled });
    await loadLiveData({ includeHealth: false });
    renderAll();
    toast(t(enabled ? "runtime.enabledToast" : "runtime.pausedToast"));
  }));
  $("saveSettingsBtn").addEventListener("click", () => runAction($("saveSettingsBtn"), async () => {
    const next = structuredClone(state.config);
    next.engineMode = $("engineMode").value;
    next.runtime.logLevel = $("logLevel").value;
    next.runtime.leakProtectionMode = $("leakProtectionMode").value;
    next.runtime.dnsEnforced = $("dnsEnforced").checked;
    next.runtime.ipv6Blocked = $("ipv6Blocked").checked;
    next.runtime.dohBlocked = $("dohBlocked").checked;
    state.config = await api.put("/config", next);
    syncApiDiagnostics();
    renderAll();
    toast(t("toast.settingsSaved"), t("toast.settingsSavedDescription"));
  }));
  $("applyTemplateBtn").addEventListener("click", () => runAction($("applyTemplateBtn"), async () => {
    const proxy = state.config?.proxies.find((item) => item.enabled);
    if (!proxy) throw new Error(t("validation.addProxyFirst"));
    const templateId = $("templateSelect").value || "ai-dev";
    const result = await api.post(templateId === "ai-dev" ? "/templates/ai-dev" : `/templates/${templateId}`, { proxyProfile: proxy.id });
    await loadConfig();
    toast(t("toast.templateImported"), t("toast.templateResult", { added: result.addedRules, updated: result.updatedRules }));
  }));
  $("ruleBatchEnableBtn").addEventListener("click", () => runAction($("ruleBatchEnableBtn"), () => batchEnableRules(true)));
  $("ruleBatchDisableBtn").addEventListener("click", () => runAction($("ruleBatchDisableBtn"), () => batchEnableRules(false)));
  $("browseExeBtn").addEventListener("click", () => runAction($("browseExeBtn"), async () => {
    if (!window.__TAURI__) throw new Error(t("toast.filePickerDesktopOnly"));
    const path = await invokeTauri("choose_executable");
    if (path) {
      $("launchExe").value = path;
      if (!$("launchName").value) $("launchName").value = fileName(path).replace(/\.exe$/i, "");
    }
  }));
  $("proxyKind").addEventListener("change", syncProxyEndpointState);
  $("ruleAction").addEventListener("change", syncRuleActionState);
  bindForm("proxyForm", submitProxy);
  bindForm("ruleForm", submitRule);
  bindForm("launchForm", submitLaunch);

  $("runDiagnoseBtn")?.addEventListener("click", () => runDiagnose());
  $("runRepairBtn")?.addEventListener("click", () => runRepair());
  $("createSnapshotBtn")?.addEventListener("click", () => createSnapshot());
  $("refreshSnapshotsBtn")?.addEventListener("click", () => loadSnapshots());
  $("doctorSnapshotList")?.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-rollback-snapshot]");
    if (btn) rollbackSnapshot(btn.dataset.rollbackSnapshot);
  });

  $("scanConfigsBtn")?.addEventListener("click", () => discoverConfigs());
  $("validateConfigBtn")?.addEventListener("click", () => validateCurrentConfig());
  $("saveConfigBtn")?.addEventListener("click", () => saveCurrentConfig());
  document.querySelectorAll("[data-studio-tab]").forEach((btn) => {
    btn.addEventListener("click", () => switchStudioTab(btn.dataset.studioTab));
  });
  $("discoveredConfigList")?.addEventListener("click", (e) => {
    const card = e.target.closest("[data-inspect-path]");
    if (card) inspectConfig(card.dataset.inspectPath);
  });
  $("visualPortInput")?.addEventListener("input", () => updateStudioDiff());
  $("studioRawEditor")?.addEventListener("input", () => updateStudioDiff());

  $("refreshHistoryBtn")?.addEventListener("click", () => loadDiagnosticHistory());

  $("overviewActivityTab")?.addEventListener("click", () => switchOverviewTab("recent"));
  $("overviewConnectionsTab")?.addEventListener("click", () => switchOverviewTab("connections"));
  $("liveConnectionsList")?.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-explain-conn]");
    if (btn) {
      openExplainModal({
        process: btn.dataset.process,
        pid: btn.dataset.pid,
        target: btn.dataset.target,
        dest: btn.dataset.dest,
        port: btn.dataset.port,
        proto: btn.dataset.proto
      });
    }
  });

  $("runSimulationBtn")?.addEventListener("click", () => runSimulation());

  $("startDiscoveryBtn")?.addEventListener("click", () => runEndpointDiscovery());
  $("discoveredEndpointsList")?.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-add-endpoint-client]");
    if (btn) {
      addDiscoveredEndpointItem(
        btn.dataset.addEndpointClient,
        btn.dataset.addEndpointPort,
        btn.dataset.addEndpointProto
      );
    }
  });

  $("refreshTimelineBtn")?.addEventListener("click", () => loadTimelineEvents());
  $("clearTimelineBtn")?.addEventListener("click", () => clearTimelineEvents());

  $("autostartEnabled")?.addEventListener("change", () => handleAutostartChange());
  $("autostartSilent")?.addEventListener("change", () => handleAutostartChange());

  $("checkForUpdatesBtn")?.addEventListener("click", () => checkAppUpdates());
  $("confirmInstallUpdateBtn")?.addEventListener("click", () => installAppUpdate());

  const contextMenu = $("appContextMenu");
  const closeContextMenu = () => { contextMenu.hidden = true; };
  document.addEventListener("contextmenu", (event) => {
    event.preventDefault();
    if (event.target.closest("dialog[open]")) {
      closeContextMenu();
      return;
    }
    contextMenu.querySelector('[data-context-action="add-rule"]').disabled = !state.config;
    contextMenu.hidden = false;
    contextMenu.style.visibility = "hidden";
    contextMenu.style.left = "0px";
    contextMenu.style.top = "0px";
    const bounds = contextMenu.getBoundingClientRect();
    contextMenu.style.left = `${Math.max(8, Math.min(event.clientX, window.innerWidth - bounds.width - 8))}px`;
    contextMenu.style.top = `${Math.max(8, Math.min(event.clientY, window.innerHeight - bounds.height - 8))}px`;
    contextMenu.style.visibility = "visible";
    contextMenu.querySelector("button:not(:disabled)")?.focus();
  });
  contextMenu.addEventListener("click", (event) => {
    const item = event.target.closest("button[data-context-action]");
    if (!item) return;
    closeContextMenu();
    if (item.dataset.contextAction === "refresh") refreshAll().catch(() => {});
    if (item.dataset.contextAction === "add-rule") openModal("rule");
    if (item.dataset.contextAction === "overview") switchView("overview");
    if (item.dataset.contextAction === "settings") switchView("settings");
  });
  document.addEventListener("pointerdown", (event) => {
    if (!contextMenu.hidden && !contextMenu.contains(event.target)) closeContextMenu();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") closeContextMenu();
    if (event.key === "F5") {
      event.preventDefault();
      closeContextMenu();
      refreshAll().catch(() => {});
    }
  });
  $("refreshActivityBtn").addEventListener("click", () => runAction($("refreshActivityBtn"), async () => {
    await loadLiveData({ includeHealth: false });
    renderAllActivity();
  }));
  $("appContextMenu").addEventListener("focusout", (event) => {
    if (!contextMenu.contains(event.relatedTarget)) closeContextMenu();
  });
  document.querySelector(".workspace").addEventListener("scroll", closeContextMenu);
  window.addEventListener("blur", closeContextMenu);
  window.addEventListener("resize", closeContextMenu);
}

async function init() {
  initLanguage();
  initTheme();
  bindEvents();
  try {
    await api.initializeSession();
    state.preflight = window.__TAURI__
      ? await invokeTauri("get_system_preflight")
      : { platform: navigator.platform, desktopBridge: false, webviewReady: true, elevated: false };
  } catch (error) {
    reportError(error, t("toast.bridgeFailed"));
  }
  $("coreUrlValue").textContent = api.baseUrl;
  $("coreStatus").querySelector("small").textContent = api.baseUrl.replace(/^https?:\/\//, "");
  if (window.__TAURI__) loadAutostartConfig().catch(() => {});
  await connectWithRetry();
  window.setInterval(() => {
    if (document.hidden || state.refreshing) return;
    if (!state.online) {
      scheduleReconnect();
      return;
    }
    loadLiveData().catch((error) => {
      setOnline(false, normalizeError(error));
      scheduleReconnect();
    });
  }, 3500);
}

init().catch((error) => reportError(error, t("toast.initFailed")));
