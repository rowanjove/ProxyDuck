import { expect, test } from "@playwright/test";

function envelope(data) {
  return { ok: true, data };
}

test("loads live state, verifies a proxy, and edits and duplicates a rule", async ({ page }) => {
  const config = {
    version: "1.0.0",
    schemaVersion: 3,
    engineMode: "win_divert",
    runtime: {
      enabled: false,
      logLevel: "info",
      leakProtectionMode: "availability",
      dnsEnforced: false,
      ipv6Blocked: false,
      dohBlocked: false
    },
    proxies: [{ id: "clash-socks", name: "Clash SOCKS", kind: "socks5", endpoint: "127.0.0.1:7897", username: null, password: null, enabled: true }],
    rules: [{
      id: "rule-1", name: "Browser", matcher: { appNames: ["browser.exe"], exePaths: [], pids: [], hashes: [], wildcard: null },
      proxyProfile: "clash-socks", protocols: ["tcp", "udp"], enabled: true, autoBindChildren: false,
      forceDns: false, blockIpv6: false, blockDoh: false, source: "user", managedByQuickbarId: null
    }],
    quickBar: []
  };

  await page.route("http://127.0.0.1:46666/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const method = request.method();
    let data;
    if (method === "GET" && path === "/config") data = config;
    else if (method === "GET" && path === "/capabilities") data = [
      { mode: "win_divert", displayName: "ProxiFyre", available: true, unavailableReason: null, supportedProxyKinds: ["socks5", "direct"], supportsChildInheritance: false },
      { mode: "sing_box", displayName: "sing-box TUN", available: true, unavailableReason: null, supportedProxyKinds: ["socks5", "direct"], supportsChildInheritance: false },
      { mode: "wfp", displayName: "WFP", available: false, unavailableReason: "WFP backend is not implemented", supportedProxyKinds: [], supportsChildInheritance: false }
    ];
    else if (method === "GET" && path === "/rules/conflicts") data = [];
    else if (method === "GET" && path === "/snapshot") data = {
      health: { status: "ok", version: "1.0.0" }, stats: { matched: 0 },
      runtimeStatus: { desiredEnabled: false, dataPlane: { phase: "paused", childPid: null, proxyEndpointReachable: null, firewallRules: 0, failClosedActive: false, message: null } },
      ruleStats: [], proxyStats: [], recentHits: [{
        ts: "2026-08-16T02:00:00Z", processName: "browser.exe", processPid: 4242,
        proxyName: "Clash SOCKS", ruleName: "Browser", ruleId: "rule-1", matchKind: "app_name"
      }], logs: []
    };
    else if (method === "POST" && path === "/proxies/clash-socks/test") data = { proxyId: "clash-socks", reachable: true, protocolAccepted: true, tcpSupported: true, tcpError: null, udpSupported: true, udpError: null, latencyMs: 4, error: null };
    else if (method === "POST" && path === "/engine/mode") {
      config.engineMode = request.postDataJSON().mode;
      data = "switched";
    }
    else if (method === "PUT" && path === "/rules/rule-1") {
      Object.assign(config.rules[0], request.postDataJSON());
      data = config.rules[0];
    } else if (method === "POST" && path === "/rules/rule-1/duplicate") {
      const duplicate = { ...structuredClone(config.rules[0]), id: "rule-2", name: `${config.rules[0].name} Copy` };
      config.rules.push(duplicate);
      data = duplicate;
    } else if (method === "POST" && path === "/rules/reorder") {
      const ids = request.postDataJSON().ruleIds;
      config.rules.sort((left, right) => ids.indexOf(left.id) - ids.indexOf(right.id));
      data = config.rules;
    } else {
      await route.fulfill({ status: 404, json: { ok: false, error: `Unhandled ${method} ${path}` } });
      return;
    }
    await route.fulfill({ status: 200, json: envelope(data) });
  });

  await page.goto("/");
  await expect(page.locator("#coreStatus strong")).toHaveText("核心服务在线");
  await expect(page.locator("#overviewRuleList")).toContainText("Browser");

  await page.getByRole("button", { name: "查看全部" }).click();
  await expect(page.locator("#activityModal")).toBeVisible();
  await expect(page.locator("#allActivity")).toContainText("browser.exe");
  await page.locator("#activityModal [data-modal-close]").click();

  await page.locator("body").click({ button: "right", position: { x: 420, y: 180 } });
  await expect(page.locator("#appContextMenu")).toBeVisible();
  await page.getByRole("menuitem", { name: "打开设置" }).click();
  await expect(page.locator("#pageTitle")).toHaveText("设置");
  await page.locator("#engineMode").selectOption("sing_box");
  await expect(page.locator("#engineMode")).toHaveValue("sing_box");
  await expect(page.locator("#toastStack")).toContainText("路由引擎已切换");
  await page.locator("#engineMode").selectOption("wfp");
  await expect(page.locator("#toastStack")).toContainText("WFP backend is not implemented");
  await expect(page.locator("#engineMode")).toHaveValue("sing_box");

  await page.locator('[data-view="proxies"]').click();
  await page.locator('[data-action="test-proxy"]').click();
  await expect(page.locator("#toastStack")).toContainText("TCP CONNECT 可用");
  await expect(page.locator("#toastStack")).toContainText("UDP ASSOCIATE 可用");

  await page.locator('[data-view="rules"]').click();
  await page.locator('[data-action="edit-rule"]').click();
  await page.locator("#ruleName").fill("Browser updated");
  await page.getByRole("button", { name: "保存" }).click();
  await expect(page.locator("#ruleList")).toContainText("Browser updated");

  await page.locator('[data-action="duplicate-rule"]').first().click();
  await expect(page.locator("#ruleList")).toContainText("Browser updated Copy");
});
