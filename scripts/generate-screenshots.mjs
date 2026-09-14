import { createServer } from "node:http";
import { extname, resolve, sep } from "node:path";
import { readFile } from "node:fs/promises";
import { chromium } from "playwright";

const uiRoot = resolve("smartflow-ui/dist");
const types = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".ico": "image/x-icon",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".png": "image/png"
};

const config = {
  version: "1.1.0",
  schemaVersion: 5,
  engineMode: "proxifyre",
  runtime: {
    enabled: true,
    logLevel: "info",
    leakProtectionMode: "availability",
    dnsEnforced: true,
    ipv6Blocked: true,
    dohBlocked: true
  },
  proxies: [
    { id: "clash-local", name: "Clash 本地节点", kind: "socks5", endpoint: "127.0.0.1:7897", username: null, password: null, enabled: true },
    { id: "dev-socks", name: "开发环境 SOCKS5", kind: "socks5", endpoint: "127.0.0.1:1080", username: null, password: null, enabled: true }
  ],
  rules: [
    {
      id: "rule-browser", name: "日常浏览器流量", enabled: true, source: "user", group: "日常浏览", tags: ["web", "default"],
      matcher: { appNames: ["chrome.exe", "msedge.exe"], exePaths: [], pids: [], hashes: [], wildcard: null },
      action: { type: "proxy", proxyId: "clash-local" },
      proxyProfile: "clash-local", protocols: ["tcp", "udp"], autoBindChildren: false,
      forceDns: true, blockIpv6: true, blockDoh: true
    },
    {
      id: "rule-ai", name: "AI 编程与开发工具", enabled: true, source: "user", group: "开发环境", tags: ["ai", "ide"],
      matcher: { appNames: ["Code.exe", "cursor.exe"], exePaths: [], pids: [], hashes: [], wildcard: null },
      action: { type: "proxy", proxyId: "dev-socks" },
      proxyProfile: "dev-socks", protocols: ["tcp", "udp"], autoBindChildren: false,
      forceDns: true, blockIpv6: true, blockDoh: true
    },
    {
      id: "rule-meeting", name: "会议与即时通讯", enabled: false, source: "user", group: "办公会议", tags: ["chat"],
      matcher: { appNames: ["teams.exe", "discord.exe"], exePaths: [], pids: [], hashes: [], wildcard: null },
      action: { type: "proxy", proxyId: "clash-local" },
      proxyProfile: "clash-local", protocols: ["tcp", "udp"], autoBindChildren: false,
      forceDns: true, blockIpv6: true, blockDoh: true
    }
  ],
  quickBar: [
    { id: "qb-chrome", name: "Google Chrome", exePath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", args: [], workDir: null, proxyProfile: "clash-local", startMode: "start_and_bind", runAsAdmin: false, autoBindChildren: false },
    { id: "qb-vscode", name: "VS Code", exePath: "C:\\Program Files\\Microsoft VS Code\\Code.exe", args: [], workDir: null, proxyProfile: "dev-socks", startMode: "start_and_bind", runAsAdmin: false, autoBindChildren: false }
  ],
  profiles: [
    { id: "prof-default", name: "默认方案", description: "日常办公与开发代理方案", createdAt: "2026-09-14T08:00:00Z" }
  ],
  activeProfileId: "prof-default"
};

const snapshot = {
  health: { status: "ok", version: "1.1.0", engineMode: "proxifyre" },
  stats: {
    engineMode: "proxifyre", startedAt: "2026-09-14T08:00:00Z", lastReloadAt: "2026-09-14T09:15:00Z",
    ruleHits: { "rule-browser": 268, "rule-ai": 142 },
    processHits: { "chrome.exe": 182, "Code.exe": 96, "cursor.exe": 46 },
    proxyHits: { "clash-local": 268, "dev-socks": 142 }
  },
  runtimeStatus: {
    desiredEnabled: true,
    dataPlane: { phase: "running", childPid: 5412, proxyEndpointReachable: true, firewallRules: 3, failClosedActive: false, message: "ProxiFyre 正在转发已匹配进程流量" }
  },
  ruleStats: [
    { ruleId: "rule-browser", ruleName: "日常浏览器流量", proxyName: "Clash 本地节点", source: "user", hits: 268 },
    { ruleId: "rule-ai", ruleName: "AI 编程与开发工具", proxyName: "开发环境 SOCKS5", source: "user", hits: 142 }
  ],
  proxyStats: [
    { proxyId: "clash-local", proxyName: "Clash 本地节点", hits: 268 },
    { proxyId: "dev-socks", proxyName: "开发环境 SOCKS5", hits: 142 }
  ],
  recentHits: [
    { ts: "2026-09-14T09:50:22Z", processName: "chrome.exe", processPid: 4628, proxyName: "Clash 本地节点", ruleName: "日常浏览器流量", ruleId: "rule-browser", matchKind: "app_name" },
    { ts: "2026-09-14T09:49:15Z", processName: "cursor.exe", processPid: 8120, proxyName: "开发环境 SOCKS5", ruleName: "AI 编程与开发工具", ruleId: "rule-ai", matchKind: "app_name" },
    { ts: "2026-09-14T09:47:38Z", processName: "Code.exe", processPid: 6540, proxyName: "开发环境 SOCKS5", ruleName: "AI 编程与开发工具", ruleId: "rule-ai", matchKind: "app_name" }
  ],
  logs: [
    { ts: "2026-09-14T09:15:00Z", level: "info", source: "engine", message: "ProxiFyre 数据平面运行中" }
  ]
};

const capabilities = [
  { mode: "proxifyre", displayName: "ProxiFyre (驱动路由)", backendName: "proxifyre", available: true, unavailableReason: null, supportedProxyKinds: ["socks5", "direct"], supportedProtocols: ["tcp", "udp"], supportsChildInheritance: false, supportsHashMatching: false, supportsFirewallHardening: true },
  { mode: "sing_box", displayName: "sing-box TUN", backendName: "sing-box", available: true, unavailableReason: null, supportedProxyKinds: ["socks5", "direct"], supportedProtocols: ["tcp", "udp"], supportsChildInheritance: false, supportsHashMatching: false, supportsFirewallHardening: false }
];

const doctorDiag = {
  status: "normal",
  timestamp: "2026-09-14T09:50:00Z",
  adapters: { hasConnectedAdapter: true, activeAdapters: [{ name: "以太网", ip: "192.168.1.100", status: "Up" }] },
  routes: { hasDefaultRoute: true, defaultGateway: "192.168.1.1" },
  gateway: { reachable: true, rttMs: 1 },
  internet: { ipLevelConnected: true, dnsAccessible: true },
  dns: { allResolvesSucceeded: true, servers: ["223.5.5.5", "119.29.29.29"] },
  ncsi: { captivePortalDetected: false, webProbeSucceeded: true },
  proxy: { wininetAccessible: true, proxyPortReachable: true, systemProxyConfigured: false },
  dualPath: { directInternetOk: true, proxyChannelOk: true },
  winsock: { isHealthy: true, providerCount: 12 },
  hosts: { fileAccessible: true, customEntryCount: 0 },
  issues: []
};

const envelope = (data) => ({ ok: true, data });

const server = createServer(async (request, response) => {
  const pathname = new URL(request.url || "/", "http://127.0.0.1").pathname;
  const relative = pathname === "/" ? "index.html" : pathname.slice(1);
  const path = resolve(uiRoot, relative);
  if (path !== uiRoot && !path.startsWith(`${uiRoot}${sep}`)) {
    response.writeHead(403).end("Forbidden");
    return;
  }
  try {
    const body = await readFile(path);
    response.writeHead(200, { "Content-Type": types[extname(path)] || "application/octet-stream" });
    response.end(body);
  } catch {
    response.writeHead(404).end("Not found");
  }
});

server.listen(4176, "127.0.0.1", async () => {
  console.log("Serving UI on http://127.0.0.1:4176");
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1280, height: 750 },
    deviceScaleFactor: 1.5,
    colorScheme: "dark"
  });
  const page = await context.newPage();

  await page.addInitScript(() => {
    localStorage.setItem("proxyduck-theme", "dark");
    localStorage.setItem("proxyduck-onboarding-dismissed", "1");
  });

  await page.route("http://127.0.0.1:46666/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    let data;

    if (method === "GET" && path === "/config") data = config;
    else if (method === "GET" && path === "/capabilities") data = capabilities;
    else if (method === "GET" && path === "/rules/conflicts") data = [];
    else if (method === "GET" && path === "/snapshot") data = snapshot;
    else if (method === "GET" && path === "/processes") data = [];
    else if (method === "GET" && path === "/connections/summary") data = { totalCount: 18, activeCount: 5 };
    else if (method === "GET" && path.startsWith("/connections")) data = [];
    else if (method === "GET" && path.startsWith("/timeline")) data = [];
    else if (method === "GET" && path === "/rules/analyze") data = { deadRules: [], shadowedRules: [], redundantRules: [] };
    else if (method === "GET" && (path === "/network/status" || path === "/doctor/status")) data = doctorDiag;
    else if (method === "GET" && (path === "/network/snapshots" || path === "/doctor/snapshots")) data = [];
    else if (method === "GET" && (path === "/network/repair-plan" || path === "/doctor/repair-plan")) data = { planId: "plan-1", recommendedActions: [] };
    else if (method === "GET" && path === "/profiles") data = config.profiles;
    else {
      await route.fulfill({ status: 200, json: envelope({}) });
      return;
    }
    await route.fulfill({ status: 200, json: envelope(data) });
  });

  await page.goto("http://127.0.0.1:4176");
  await page.locator("#coreStatus strong").waitFor({ state: "visible" });
  await page.waitForTimeout(600);

  // 1. Overview screenshot
  await page.screenshot({ path: "docs/images/proxyduck-overview.png" });
  console.log("Captured docs/images/proxyduck-overview.png");

  // 2. Rules screenshot
  await page.locator('[data-view="rules"]').click();
  await page.waitForTimeout(600);
  await page.screenshot({ path: "docs/images/proxyduck-rules.png" });
  console.log("Captured docs/images/proxyduck-rules.png");

  // 3. Doctor screenshot
  await page.locator('[data-view="doctor"]').click();
  await page.waitForTimeout(600);
  await page.screenshot({ path: "docs/images/proxyduck-doctor.png" });
  console.log("Captured docs/images/proxyduck-doctor.png");

  await browser.close();
  server.close();
  console.log("Done generating screenshots.");
  process.exit(0);
});
