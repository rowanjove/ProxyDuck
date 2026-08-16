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
  editingRuleId: null,
  preflight: null,
  testedProxyIds: new Set()
};

const viewMeta = {
  overview: "page.overview",
  rules: "page.rules",
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
}

function proxyName(id) {
  return state.config?.proxies.find((proxy) => proxy.id === id)?.name || id || "—";
}

function enabledProxyOptions(selected = "") {
  const proxies = (state.config?.proxies || []).filter((proxy) => proxy.enabled);
  return proxies.map((proxy) => `<option value="${escapeHtml(proxy.id)}"${proxy.id === selected ? " selected" : ""}>${escapeHtml(proxy.name)} · ${escapeHtml(proxyKindText(proxy.kind))}</option>`).join("");
}

function currentEngineCapability() {
  const mode = state.config?.engineMode || "win_divert";
  return state.capabilities.find((capability) => capability.mode === mode) || null;
}

function renderCapabilities() {
  if (!state.capabilities.length) return;
  const selectedMode = state.config?.engineMode || "win_divert";
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
    const proxy = state.config.proxies.find((item) => item.id === rule.proxyProfile);
    const dataPlaneRunning = state.runtimeStatus?.dataPlane?.phase === "running";
    const status = !state.config.runtime.enabled
      ? statusBadge(t("common.paused"), "neutral")
      : proxy?.enabled && dataPlaneRunning
        ? statusBadge(t("common.routing"), "success")
        : statusBadge(t(`runtimePhase.${state.runtimeStatus?.dataPlane?.phase || "starting"}`), "neutral");
    return `<div class="data-list data-row overview-rule-columns"><div class="cell-main"><strong>${escapeHtml(rule.name)}</strong><small title="${escapeHtml(matcherSummary(rule.matcher))}">${escapeHtml(matcherSummary(rule.matcher))}</small></div><div class="cell-main"><strong>${escapeHtml(proxyName(rule.proxyProfile))}</strong><small>${escapeHtml(protocolText(rule.protocols))}</small></div>${status}<time class="metadata">${lastHit ? escapeHtml(formatTime(lastHit.ts)) : "—"}</time></div>`;
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

function renderRules() {
  if (!state.config) return;
  const query = $("ruleSearch").value.trim().toLowerCase();
  const rules = state.config.rules.filter((rule) => {
    const haystack = `${rule.name} ${matcherSummary(rule.matcher)} ${proxyName(rule.proxyProfile)}`.toLowerCase();
    return !query || haystack.includes(query);
  });
  $("ruleList").innerHTML = rules.length ? rules.map((rule) => {
    const managed = rule.source === "quick_bar";
    const conflict = state.ruleConflicts.some((item) => item.firstRuleId === rule.id || item.secondRuleId === rule.id);
    const index = state.config.rules.findIndex((item) => item.id === rule.id);
    return `<div class="data-list data-row rule-columns"><div class="cell-main"><strong>${escapeHtml(rule.name)}</strong><small>${escapeHtml(ruleSourceText(rule.source))}${conflict ? ` · ${escapeHtml(t("rules.conflict"))}` : ""}</small></div><div class="cell-main"><strong title="${escapeHtml(matcherSummary(rule.matcher))}">${escapeHtml(matcherSummary(rule.matcher))}</strong><small>${escapeHtml(t(rule.autoBindChildren ? "rules.childProcesses" : "rules.currentProcess"))}</small></div><span class="tag">${escapeHtml(proxyName(rule.proxyProfile))}</span><span class="tag">${escapeHtml(protocolText(rule.protocols))}</span>${managed ? statusBadge(t(rule.enabled ? "common.enabled" : "common.paused"), rule.enabled ? "success" : "neutral") : `<span class="switch-control compact"><input class="inline-switch" type="checkbox" data-action="toggle-rule" data-id="${escapeHtml(rule.id)}" ${rule.enabled ? "checked" : ""} aria-label="${escapeHtml(t(rule.enabled ? "common.enabled" : "common.disabled"))}: ${escapeHtml(rule.name)}"/><span class="switch-track" aria-hidden="true"></span></span>`}<div class="row-actions">${managed ? "" : `<button class="mini-button" data-action="move-rule-up" data-id="${escapeHtml(rule.id)}" ${index <= 0 ? "disabled" : ""} title="${escapeHtml(t("rules.moveUp"))}">↑</button><button class="mini-button" data-action="move-rule-down" data-id="${escapeHtml(rule.id)}" ${index >= state.config.rules.length - 1 ? "disabled" : ""} title="${escapeHtml(t("rules.moveDown"))}">↓</button><button class="mini-button" data-action="edit-rule" data-id="${escapeHtml(rule.id)}" title="${escapeHtml(t("common.edit"))}"><svg><use href="#i-settings"/></svg></button><button class="mini-button" data-action="duplicate-rule" data-id="${escapeHtml(rule.id)}" title="${escapeHtml(t("common.duplicate"))}"><svg><use href="#i-plus"/></svg></button><button class="mini-button danger" data-action="delete-rule" data-id="${escapeHtml(rule.id)}" title="${escapeHtml(t("common.delete"))}"><svg><use href="#i-trash"/></svg></button>`}</div></div>`;
  }).join("") : emptyState(t(query ? "empty.noMatchingRules" : "empty.noRules"), t(query ? "empty.changeSearch" : "empty.createFirstRule"));
}

function renderProxies() {
  const proxies = state.config?.proxies || [];
  $("proxyGrid").innerHTML = proxies.length ? proxies.map((proxy) => `<div class="data-list data-row proxy-columns"><div class="proxy-identity"><svg><use href="#i-server"/></svg><div><strong>${escapeHtml(proxy.name)}</strong><small>${escapeHtml(proxy.id)}</small></div></div><span class="tag">${escapeHtml(proxyKindText(proxy.kind))}</span><code class="endpoint" title="${escapeHtml(proxy.endpoint)}">${escapeHtml(proxy.kind === "direct" ? t("common.direct") : proxy.endpoint)}</code><div class="status-control">${statusBadge(t(proxy.enabled ? "common.enabled" : "common.disabled"), proxy.enabled ? "success" : "neutral")}<span class="switch-control compact"><input class="inline-switch" type="checkbox" data-action="toggle-proxy" data-id="${escapeHtml(proxy.id)}" ${proxy.enabled ? "checked" : ""} aria-label="${escapeHtml(t(proxy.enabled ? "common.enabled" : "common.disabled"))}: ${escapeHtml(proxy.name)}"/><span class="switch-track" aria-hidden="true"></span></span></div><div class="row-actions"><button class="mini-button" data-action="test-proxy" data-id="${escapeHtml(proxy.id)}" title="${escapeHtml(t("proxies.test"))}"><svg><use href="#i-pulse"/></svg></button><button class="mini-button danger" data-action="delete-proxy" data-id="${escapeHtml(proxy.id)}" title="${escapeHtml(t("common.delete"))}"><svg><use href="#i-trash"/></svg></button></div></div>`).join("") : emptyState(t("empty.noProxies"), t("empty.noProxiesDescription"));
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
  $("processList").innerHTML = processes.length ? processes.map((process) => `<div class="data-list data-row process-columns"><div class="cell-main"><strong>${escapeHtml(process.name)}</strong><small>${escapeHtml(fileName(process.exe))}</small></div><span class="tag">${escapeHtml(process.pid)}</span><div class="path-cell" title="${escapeHtml(process.exe)}">${escapeHtml(process.exe || t("processes.systemPath"))}</div><div class="row-actions"><button class="button ghost small" data-action="evaluate-process" data-pid="${escapeHtml(process.pid)}">${escapeHtml(t("processes.evaluate"))}</button><button class="button ghost small" data-action="rule-from-process" data-name="${escapeHtml(encodeURIComponent(process.name))}" data-exe="${escapeHtml(encodeURIComponent(process.exe || ""))}" data-pid="${escapeHtml(process.pid)}"><svg><use href="#i-plus"/></svg>${escapeHtml(t("common.rule"))}</button></div></div>`).join("") : emptyState(t(query ? "empty.noMatchingProcesses" : "empty.noProcesses"), t(query ? "empty.changeSearch" : "empty.waitForScan"));
}

function renderDiagnostics() {
  const renderRank = (items, nameKey, detail) => items.length ? items.slice(0, 10).map((item, index) => `<div class="rank-row"><span>${index + 1}</span><div><strong>${escapeHtml(item[nameKey])}</strong><small>${escapeHtml(detail(item))}</small></div><b>${formatNumber(item.hits)}</b></div>`).join("") : emptyState(t("empty.noStats"), t("empty.noStatsDescription"), true);
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
}

function renderAll() {
  syncProxySelects();
  renderOverview();
  renderRules();
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
  setOnline(true);
  renderOverview();
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
    if (!quiet) reportError(error, t("toast.refreshFailed"));
    throw error;
  } finally {
    state.refreshing = false;
    $("refreshBtn").disabled = false;
  }
}

async function connectWithRetry() {
  let lastError;
  for (let attempt = 0; attempt < 24; attempt += 1) {
    try {
      await refreshAll({ quiet: true });
      return;
    } catch (error) {
      lastError = error;
      $("connectionMessage").textContent = t("connection.starting", { attempt: attempt + 1 });
      await new Promise((resolve) => window.setTimeout(resolve, 250));
    }
  }
  reportError(lastError, t("toast.coreFailed"));
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
  if ((type === "rule" || type === "launch") && !(state.config?.proxies || []).some((proxy) => proxy.enabled)) {
    toast(t("toast.proxyRequired"), t("toast.proxyRequiredDescription"), "error");
    switchView("proxies");
    return;
  }
  const modal = $(`${type}Modal`);
  if (type === "activity") {
    renderAllActivity();
    modal.showModal();
    return;
  }
  const form = $(`${type}Form`);
  form.reset();
  if (type === "rule") {
    const rule = defaults.rule || null;
    state.editingRuleId = rule?.id || null;
    const matcher = rule?.matcher || {};
    const matchType = matcher.pids?.length ? "pids" : matcher.exePaths?.length ? "exePaths" : matcher.appNames?.length ? "appNames" : "wildcard";
    const matchValue = matchType === "wildcard" ? matcher.wildcard : matcher[matchType]?.[0];
    $("ruleTcp").checked = rule ? rule.protocols.includes("tcp") : true;
    $("ruleUdp").checked = rule ? rule.protocols.includes("udp") : true;
    $("ruleDns").checked = rule ? rule.protocols.includes("dns") : true;
    $("ruleChildren").checked = Boolean(rule?.autoBindChildren);
    $("ruleName").value = rule?.name || defaults.name || "";
    $("ruleMatchType").value = rule ? matchType : defaults.matchType || "appNames";
    $("ruleMatchValue").value = rule ? matchValue || "" : defaults.matchValue || "";
    $("ruleProxy").innerHTML = enabledProxyOptions(rule?.proxyProfile || defaults.proxy || "");
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

function syncProxyEndpointState() {
  const direct = $("proxyKind").value === "direct";
  $("proxyEndpoint").disabled = direct;
  $("proxyEndpoint").required = !direct;
  $("proxyEndpoint").placeholder = direct ? t("modal.directPlaceholder") : "127.0.0.1:7897";
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
  for (const proxy of config?.proxies || []) proxy.password = null;
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

function exportDiagnostics() {
  downloadJson(`proxyduck-diagnostics-${new Date().toISOString().replace(/[:.]/g, "-")}.json`, {
    generatedAt: new Date().toISOString(), health: state.health, runtimeStatus: state.runtimeStatus,
    capabilities: state.capabilities, config: sanitizedConfig(), ruleConflicts: state.ruleConflicts,
    ruleStats: state.ruleStats, proxyStats: state.proxyStats, recentHits: state.hits, logs: state.logs
  });
  toast(t("toast.diagnosticsExported"));
}

async function importConfigFile(file) {
  if (!file) return;
  const parsed = JSON.parse(await file.text());
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.rules) || !Array.isArray(parsed.proxies)) throw new Error(t("validation.configFile"));
  if (!await confirmAction(t("confirm.importConfig"), t("confirm.importConfigDescription"))) return;
  state.config = await api.put("/config", parsed);
  await loadConfig();
  toast(t("toast.configImported"));
}

async function submitProxy() {
  const kind = $("proxyKind").value;
  const endpoint = $("proxyEndpoint").value.trim();
  if (!validateEndpoint(kind, endpoint)) throw new Error(t("validation.endpoint"));
  await api.post("/proxies", { name: $("proxyName").value.trim(), kind, endpoint: kind === "direct" ? "direct" : endpoint, enabled: true });
  $("proxyModal").close();
  await loadConfig();
  toast(t("toast.proxyAdded"));
}

async function submitRule() {
  const matchType = $("ruleMatchType").value;
  const rawValue = $("ruleMatchValue").value.trim();
  const matcher = { appNames: [], exePaths: [], pids: [], hashes: [], wildcard: null };
  if (matchType === "pids") {
    const pid = Number(rawValue);
    if (!Number.isInteger(pid) || pid <= 0) throw new Error(t("validation.pid"));
    matcher.pids = [pid];
  } else if (matchType === "wildcard") {
    matcher.wildcard = rawValue;
  } else {
    matcher[matchType] = [rawValue];
  }
  const protocols = [["tcp", $("ruleTcp")], ["udp", $("ruleUdp")], ["dns", $("ruleDns")]].filter(([, input]) => input.checked).map(([protocol]) => protocol);
  if (!protocols.length) throw new Error(t("validation.protocol"));
  const existing = state.editingRuleId ? state.config.rules.find((rule) => rule.id === state.editingRuleId) : null;
  const payload = {
    name: $("ruleName").value.trim(), matcher, proxyProfile: $("ruleProxy").value,
    protocols, enabled: existing?.enabled ?? true, autoBindChildren: $("ruleChildren").checked,
    forceDns: protocols.includes("dns"), blockIpv6: existing?.blockIpv6 ?? true, blockDoh: existing?.blockDoh ?? true
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
    await api.post(`/quickbar/${id}/launch`, {});
    toast(t("toast.launchSent"));
    return;
  }
  if (action === "rule-from-process") {
    const name = decodeURIComponent(button.dataset.name || "");
    const exe = decodeURIComponent(button.dataset.exe || "");
    openModal("rule", { name: getLanguage() === "en" ? `Route ${name}` : `${name} 路由`, matchType: exe ? "exePaths" : "appNames", matchValue: exe || name });
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
    "delete-launch": [t("confirm.deleteLaunch"), t("confirm.deleteLaunchDescription"), `/quickbar/${id}`]
  };
  if (descriptors[action]) {
    const [title, message, path] = descriptors[action];
    if (!await confirmAction(title, message)) return;
    await api.delete(path);
    await loadConfig();
    toast(t("toast.deleted"));
  }
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
    renderAll();
    toast(t("toast.settingsSaved"), t("toast.settingsSavedDescription"));
  }));
  $("applyTemplateBtn").addEventListener("click", () => runAction($("applyTemplateBtn"), async () => {
    const proxy = state.config?.proxies.find((item) => item.enabled);
    if (!proxy) throw new Error(t("validation.addProxyFirst"));
    const result = await api.post("/templates/ai-dev", { proxyProfile: proxy.id });
    await loadConfig();
    toast(t("toast.templateImported"), t("toast.templateResult", { added: result.addedRules, updated: result.updatedRules }));
  }));
  $("browseExeBtn").addEventListener("click", () => runAction($("browseExeBtn"), async () => {
    if (!window.__TAURI__) throw new Error(t("toast.filePickerDesktopOnly"));
    const path = await invokeTauri("choose_executable");
    if (path) {
      $("launchExe").value = path;
      if (!$("launchName").value) $("launchName").value = fileName(path).replace(/\.exe$/i, "");
    }
  }));
  $("proxyKind").addEventListener("change", syncProxyEndpointState);
  bindForm("proxyForm", submitProxy);
  bindForm("ruleForm", submitRule);
  bindForm("launchForm", submitLaunch);

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
  await connectWithRetry();
  window.setInterval(() => {
    if (document.hidden || !state.online || state.refreshing) return;
    loadLiveData().catch((error) => setOnline(false, normalizeError(error)));
  }, 3500);
}

init().catch((error) => reportError(error, t("toast.initFailed")));
