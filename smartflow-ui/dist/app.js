let CORE_URL = "http://127.0.0.1:46666";
let AUTH_TOKEN = "";
let CONFIG_CACHE = null;
let PROCESS_LIST_LOADED = false;
let PROCESS_PANEL_OPEN = false;
const THEME_STORAGE_KEY = "smartflow-theme";
const QUICK_ICON_CACHE = new Map();
const QUICK_ICON_IN_FLIGHT = new Map();

const escapeHtml = (str) => {
  return String(str || "").replace(/[&<>"']/g, (m) => {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m];
  });
};

const $ = (id) => document.getElementById(id);

async function invokeTauri(command, args = {}) {
  const invoke = window.__TAURI__?.tauri?.invoke;
  if (!invoke) {
    throw new Error("Tauri invoke unavailable");
  }
  return invoke(command, args);
}

async function request(path, method = "GET", body = null) {
  const headers = {
    "Content-Type": "application/json"
  };
  if (AUTH_TOKEN) {
    headers["X-SmartFlow-Token"] = AUTH_TOKEN;
  }

  const response = await fetch(`${CORE_URL}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  const json = await response
    .json()
    .catch(() => ({ ok: false, error: "invalid response" }));

  if (!response.ok || !json.ok) {
    throw new Error(json.error || `request failed: ${response.status}`);
  }

  return json.data;
}

function setHealthBadge(status, text) {
  const badge = $("healthBadge");
  if (!badge) {
    return;
  }

  badge.textContent = text;
  badge.style.background = status ? "#1a9f57" : "#bc2f45";
}

function toast(message) {
  console.log(`[SmartFlow] ${message}`);
}

function getSystemTheme() {
  return window.matchMedia?.("(prefers-color-scheme: dark)")?.matches
    ? "dark"
    : "light";
}

function updateThemeToggleText(theme) {
  const button = $("themeToggleBtn");
  if (!button) {
    return;
  }

  const isDark = theme === "dark";
  button.textContent = isDark ? "浅色模式" : "深色模式";
  button.title = isDark ? "切换到浅色模式" : "切换到深色模式";
}

function applyTheme(theme) {
  const normalized = theme === "dark" ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", normalized);
  updateThemeToggleText(normalized);
}

function initTheme() {
  let storedTheme = null;
  try {
    storedTheme = localStorage.getItem(THEME_STORAGE_KEY);
  } catch {
    // Ignore storage errors and fallback to system theme.
  }

  applyTheme(storedTheme || getSystemTheme());
}

function toggleTheme() {
  const currentTheme =
    document.documentElement.getAttribute("data-theme") || "light";
  const nextTheme = currentTheme === "dark" ? "light" : "dark";
  applyTheme(nextTheme);

  try {
    localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
  } catch {
    // Ignore storage errors.
  }
}

function fillProxySelects(proxies) {
  const options = proxies
    .map(
      (proxy) =>
        `<option value="${escapeHtml(proxy.id)}">${escapeHtml(proxy.name)} (${escapeHtml(proxy.endpoint)})</option>`
    )
    .join("");

  if (!options) {
    $("ruleProxy").innerHTML = '<option value="">无可用代理</option>';
    $("qbProxy").innerHTML = '<option value="">无可用代理</option>';
    return;
  }

  $("ruleProxy").innerHTML = options;
  $("qbProxy").innerHTML = options;
}

function renderProxies(proxies) {
  fillProxySelects(proxies);

  const tbody = $("proxyTable").querySelector("tbody");
  tbody.innerHTML = "";

  for (const proxy of proxies) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(proxy.name)}</td>
      <td>${escapeHtml(proxy.kind)}</td>
      <td>${escapeHtml(proxy.endpoint)}</td>
      <td>${proxy.enabled ? "启用" : "禁用"}</td>
      <td>
        <button data-action="delete-proxy" data-id="${escapeHtml(proxy.id)}" class="danger">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

function renderRules(rules) {
  const tbody = $("ruleTable").querySelector("tbody");
  tbody.innerHTML = "";

  for (const rule of rules) {
    const managed = rule.source === "quick_bar";
    const matcher =
      [
        ...(rule.matcher?.appNames || []),
        ...(rule.matcher?.exePaths || []),
        ...(rule.matcher?.pids || [])
      ].join(", ") || rule.matcher?.wildcard || "-";

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(rule.name)}</td>
      <td>${escapeHtml(matcher)}</td>
      <td>${escapeHtml(rule.source || "user")}</td>
      <td>${escapeHtml(rule.proxyProfile)}</td>
      <td>${escapeHtml((rule.protocols || []).join("/"))}</td>
      <td>${rule.enabled ? "启用" : "禁用"}</td>
      <td>
        <button data-action="toggle-rule" data-id="${escapeHtml(rule.id)}" ${managed ? "disabled" : ""}>${managed ? "托管" : (rule.enabled ? "禁用" : "启用")}</button>
        <button data-action="delete-rule" data-id="${escapeHtml(rule.id)}" class="danger" ${managed ? "disabled" : ""}>${managed ? "托管" : "删除"}</button>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

function formatTopList(items, labelKey, countKey = "hits", limit = 5) {
  if (!items.length) {
    return "none";
  }

  return items
    .slice(0, limit)
    .map((item) => `${item[labelKey]} (${item[countKey]})`)
    .join("\n");
}

function renderStatsSummary(stats, ruleStats, proxyStats, recentHits) {
  const recent = recentHits
    .slice(-8)
    .reverse()
    .map((hit) => `${hit.processName} -> ${hit.ruleName} -> ${hit.proxyName} [${hit.matchKind}]`)
    .join("\n") || "none";

  const topProcesses = Object.entries(stats.processHits || {})
    .sort((left, right) => right[1] - left[1])
    .map(([name, hits]) => ({ name, hits }));

  return [
    `engine: ${stats.engineMode}`,
    `startedAt: ${stats.startedAt || "never"}`,
    `lastReloadAt: ${stats.lastReloadAt || "never"}`,
    "",
    "top rules:",
    formatTopList(ruleStats, "ruleName"),
    "",
    "top proxies:",
    formatTopList(proxyStats, "proxyName"),
    "",
    "top processes:",
    formatTopList(topProcesses, "name"),
    "",
    "recent hits:",
    recent
  ].join("\n");
}

function renderQuickBar(items) {
  const tbody = $("quickBarTable").querySelector("tbody");
  tbody.innerHTML = "";
  renderQuickLaunchRail(items);

  for (const item of items) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(item.name)}</td>
      <td>${escapeHtml(item.exePath)}</td>
      <td>${escapeHtml(item.proxyProfile)}</td>
      <td>${escapeHtml(item.startMode)}</td>
      <td>
        <button data-action="launch-quickbar" data-id="${escapeHtml(item.id)}">启动</button>
        <button data-action="delete-quickbar" data-id="${escapeHtml(item.id)}" class="danger">删除</button>
      </td>
    `;
    tbody.appendChild(tr);
  }
}

function quickLaunchGlyph(item) {
  const text = `${item?.name || ""}${item?.exePath || ""}`.trim();
  const matched = text.match(/[A-Za-z0-9\u4e00-\u9fff]/u);
  return matched ? matched[0].toUpperCase() : "•";
}

async function loadExeIconDataUrl(exePath) {
  if (!exePath) {
    return null;
  }

  const key = exePath.toLowerCase();

  if (QUICK_ICON_CACHE.has(key)) {
    return QUICK_ICON_CACHE.get(key);
  }

  if (!QUICK_ICON_IN_FLIGHT.has(key)) {
    const task = (async () => {
      const iconDataUrl = await request(
        `/icon/exe?exePath=${encodeURIComponent(exePath)}`
      ).catch(() => null);

      if (iconDataUrl) {
        QUICK_ICON_CACHE.set(key, iconDataUrl);
      }

      return iconDataUrl;
    })()
      .finally(() => {
        QUICK_ICON_IN_FLIGHT.delete(key);
      });

    QUICK_ICON_IN_FLIGHT.set(key, task);
  }

  return QUICK_ICON_IN_FLIGHT.get(key);
}

async function attachExeIcon(button, item) {
  const exePath = (item?.exePath || "").trim();
  if (!exePath) {
    return;
  }

  const iconDataUrl = await loadExeIconDataUrl(exePath);
  if (!iconDataUrl || !button.isConnected) {
    return;
  }

  button.textContent = "";
  button.classList.add("has-icon");

  const image = document.createElement("img");
  image.src = iconDataUrl;
  image.alt = item?.name || "启动图标";
  image.loading = "lazy";
  image.className = "quick-launch-icon-image";
  button.appendChild(image);
}

function renderQuickLaunchRail(items) {
  const icons = $("quickLaunchIcons");
  if (!icons) {
    return;
  }

  icons.innerHTML = "";

  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "quick-launch-empty";
    empty.textContent = "暂无";
    empty.title = "暂无可一键启动项";
    icons.appendChild(empty);
    return;
  }

  for (const item of items) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "quick-launch-btn";
    button.textContent = quickLaunchGlyph(item);
    button.dataset.action = "launch-quickbar";
    button.dataset.id = item.id;
    button.title = `${item.name} (${item.startMode})`;
    button.setAttribute("aria-label", `启动 ${item.name}`);
    icons.appendChild(button);

    attachExeIcon(button, item).catch(() => {
      // Keep glyph fallback when icon extraction fails.
    });
  }
}

function updateProcessSummary(total = null, visible = null) {
  const processCount = $("processCount");
  if (!processCount) {
    return;
  }

  if (total === null || visible === null) {
    processCount.textContent = PROCESS_PANEL_OPEN
      ? "已展开，点击刷新获取进程"
      : "已收起，点击按钮展开";
    return;
  }

  processCount.textContent = `共 ${total} 个，展示前 ${visible} 个`;
}

function setProcessPanelOpen(open) {
  PROCESS_PANEL_OPEN = open;

  const processBody = $("processBody");
  const toggleBtn = $("toggleProcessBtn");
  if (!processBody || !toggleBtn) {
    return;
  }

  processBody.classList.toggle("hidden", !open);
  toggleBtn.textContent = open ? "收起在线进程" : "在线进程";
}

function renderProcesses(processes) {
  const tbody = $("processTable").querySelector("tbody");
  tbody.innerHTML = "";

  const visibleProcesses = processes.slice(0, 200);
  updateProcessSummary(processes.length, visibleProcesses.length);

  for (const process of visibleProcesses) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(process.pid)}</td>
      <td>${escapeHtml(process.name)}</td>
      <td title="${escapeHtml(process.exe)}">${escapeHtml(process.exe)}</td>
      <td><button data-action="rule-from-process" data-name="${escapeHtml(encodeURIComponent(process.name))}">加入规则</button></td>
    `;
    tbody.appendChild(tr);
  }
}

async function loadRuntime() {
  const config = await request("/config");
  CONFIG_CACHE = config;

  const clashProxy =
    config.proxies.find((proxy) => proxy.id === "clash-socks") ||
    config.proxies[0];

  $("clashEndpoint").value = clashProxy?.endpoint || "127.0.0.1:7897";
  $("engineMode").value = config.engineMode;
  $("runtimeEnabled").checked = !!config.runtime.enabled;
  $("dnsEnforced").checked = !!config.runtime.dnsEnforced;
  $("ipv6Blocked").checked = !!config.runtime.ipv6Blocked;
  $("dohBlocked").checked = !!config.runtime.dohBlocked;

  renderProxies(config.proxies);
  renderRules(config.rules);
  renderQuickBar(config.quickBar);
}

async function loadProcessList() {
  const processes = await request("/processes");
  renderProcesses(processes);
  PROCESS_LIST_LOADED = true;
}

async function loadStatsAndLogs() {
  const [stats, ruleStats, proxyStats, recentHits, logs] = await Promise.all([
    request("/stats"),
    request("/stats/rules"),
    request("/stats/proxies"),
    request("/stats/hits"),
    request("/logs")
  ]);
  $("statsBox").textContent = renderStatsSummary(stats, ruleStats, proxyStats, recentHits);
  $("logBox").textContent = logs
    .slice(-80)
    .map((log) => `[${log.ts}] [${log.level}] [${log.source}] ${log.message}`)
    .join("\n");
}

async function refreshAll() {
  try {
    const health = await request("/health");
    setHealthBadge(true, `在线 / ${health.engineMode}`);

    await loadRuntime();

    if (PROCESS_PANEL_OPEN) {
      await loadProcessList();
    } else {
      updateProcessSummary();
    }

    await loadStatsAndLogs();
  } catch (error) {
    setHealthBadge(false, `离线: ${error.message}`);
  }
}

function bindEvents() {
  $("themeToggleBtn")?.addEventListener("click", () => {
    toggleTheme();
  });

  $("refreshBtn").addEventListener("click", async () => {
    await refreshAll();
  });

  $("toggleProcessBtn").addEventListener("click", async () => {
    const next = !PROCESS_PANEL_OPEN;
    setProcessPanelOpen(next);

    if (!next || PROCESS_LIST_LOADED) {
      updateProcessSummary();
      return;
    }

    try {
      await loadProcessList();
    } catch (error) {
      setHealthBadge(false, `进程加载失败: ${error.message}`);
    }
  });

  $("refreshProcessBtn").addEventListener("click", async () => {
    try {
      await loadProcessList();
    } catch (error) {
      setHealthBadge(false, `进程刷新失败: ${error.message}`);
    }
  });

  $("quickLaunchAddBtn")?.addEventListener("click", () => {
    $("quickBarCard")?.scrollIntoView({ behavior: "smooth", block: "start" });
    $("qbName")?.focus();
  });

  $("applyAiTemplateBtn")?.addEventListener("click", async () => {
    const proxyProfile = $("ruleProxy").value || $("qbProxy").value;
    if (!proxyProfile) {
      setHealthBadge(false, "请先创建可用代理");
      return;
    }

    await request("/templates/ai-dev", "POST", { proxyProfile });
    toast("AI 开发模板已导入");
    await refreshAll();
  });

  $("proxyForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const body = {
      name: $("proxyName").value.trim(),
      kind: $("proxyKind").value,
      endpoint: $("proxyEndpoint").value.trim(),
      enabled: true
    };

    await request("/proxies", "POST", body);
    toast("代理已添加");
    await refreshAll();
    event.target.reset();
  });

  $("ruleForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const proxyProfile = $("ruleProxy").value;
    if (!proxyProfile) {
      setHealthBadge(false, "请先创建可用代理");
      return;
    }

    const body = {
      name: $("ruleName").value.trim(),
      proxyProfile,
      matcher: {
        appNames: [$("ruleMatch").value.trim()]
      },
      protocols: ["tcp", "udp", "dns"],
      enabled: true,
      autoBindChildren: true,
      forceDns: true,
      blockIpv6: true,
      blockDoh: true
    };

    await request("/rules", "POST", body);
    toast("规则已添加");
    await refreshAll();
    event.target.reset();
  });

  $("quickBarForm").addEventListener("submit", async (event) => {
    event.preventDefault();

    const proxyProfile = $("qbProxy").value;
    if (!proxyProfile) {
      setHealthBadge(false, "请先创建可用代理");
      return;
    }

    const body = {
      name: $("qbName").value.trim(),
      exePath: $("qbExe").value.trim(),
      proxyProfile,
      startMode: $("qbStartMode").value,
      runAsAdmin: $("qbAdmin").checked,
      autoBindChildren: $("qbChildren").checked
    };

    await request("/quickbar", "POST", body);
    toast("Quick Bar 项已添加");
    await refreshAll();
    event.target.reset();
  });

  $("saveRuntimeBtn").addEventListener("click", async () => {
    const runtimeBody = {
      enabled: $("runtimeEnabled").checked,
      dnsEnforced: $("dnsEnforced").checked,
      ipv6Blocked: $("ipv6Blocked").checked,
      dohBlocked: $("dohBlocked").checked
    };

    await request("/runtime", "POST", runtimeBody);
    await request("/engine/mode", "POST", { mode: $("engineMode").value });

    const clash = CONFIG_CACHE?.proxies.find((proxy) => proxy.id === "clash-socks");
    if (clash) {
      await request(`/proxies/${clash.id}`, "PUT", {
        name: clash.name,
        kind: clash.kind,
        endpoint: $("clashEndpoint").value.trim(),
        enabled: true
      });
    }

    if (window.__TAURI__) {
      await invokeTauri("set_runtime_enabled", {
        enabled: $("runtimeEnabled").checked
      });
    }

    toast("运行配置已保存");
    await refreshAll();
  });

  document.body.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLButtonElement)) {
      return;
    }

    const action = target.dataset.action;
    const id = target.dataset.id;

    try {
      if (action === "delete-proxy" && id) {
        await request(`/proxies/${id}`, "DELETE");
      }

      if (action === "delete-rule" && id) {
        await request(`/rules/${id}`, "DELETE");
      }

      if (action === "toggle-rule" && id) {
        const rule = CONFIG_CACHE?.rules.find((item) => item.id === id);
        if (rule) {
          await request(`/rules/${id}`, "PUT", {
            name: rule.name,
            matcher: rule.matcher,
            proxyProfile: rule.proxyProfile,
            protocols: rule.protocols,
            enabled: !rule.enabled,
            autoBindChildren: rule.autoBindChildren,
            forceDns: rule.forceDns,
            blockIpv6: rule.blockIpv6,
            blockDoh: rule.blockDoh
          });
        }
      }

      if (action === "delete-quickbar" && id) {
        await request(`/quickbar/${id}`, "DELETE");
      }

      if (action === "launch-quickbar" && id) {
        await request(`/quickbar/${id}/launch`, "POST", {});
      }

      if (action === "rule-from-process") {
        const name = decodeURIComponent(target.dataset.name || "");
        if (!name) {
          return;
        }

        const proxyProfile = $("ruleProxy").value;
        if (!proxyProfile) {
          setHealthBadge(false, "请先创建可用代理");
          return;
        }

        await request("/rules", "POST", {
          name: `Auto ${name}`,
          proxyProfile,
          matcher: { appNames: [name] },
          protocols: ["tcp", "udp", "dns"],
          enabled: true,
          autoBindChildren: true,
          forceDns: true,
          blockIpv6: true,
          blockDoh: true
        });
      }

      await refreshAll();
    } catch (error) {
      setHealthBadge(false, `操作失败: ${error.message}`);
    }
  });
}

async function init() {
  initTheme();

  try {
    if (window.__TAURI__) {
      const session = await invokeTauri("get_core_session");
      CORE_URL = session.coreUrl;
      AUTH_TOKEN = session.token;
      const enabled = await invokeTauri("get_runtime_enabled");
      $("runtimeEnabled").checked = enabled;
    }
  } catch (error) {
    console.warn("failed to get core URL from tauri", error);
  }

  setProcessPanelOpen(false);
  updateProcessSummary();
  bindEvents();
  await refreshAll();
  setInterval(() => {
    loadStatsAndLogs().catch(() => {
      // Keep dashboard polling resilient if one request fails.
    });
  }, 2500);
}

init().catch((error) => {
  setHealthBadge(false, `初始化失败: ${error.message}`);
});
