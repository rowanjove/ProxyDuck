import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { CoreApi } from "../dist/api.mjs";

const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");
const app = readFileSync(new URL("../dist/app.js", import.meta.url), "utf8");

test("new observability, simulator, discovery, and timeline APIs are wired", async () => {
  const api = new CoreApi();
  let requested = [];
  api.request = async (path, options = {}) => {
    requested.push({ path, options });
    if (path.startsWith("/connections?")) return [{ id: "conn-1", pid: 1234, processName: "test.exe" }];
    if (path === "/connections/summary") return { totalCount: 1, activeCount: 1 };
    if (path === "/endpoints/discover") return [{ clientName: "Clash", port: 7890, protocol: "socks5" }];
    if (path === "/endpoints/discover/add") return { id: "p-disc", name: "Discovered" };
    if (path.startsWith("/timeline?")) return [{ id: "t-1", category: "config_change", summary: "Rule updated" }];
    if (path === "/timeline/clear") return { ok: true };
    if (path === "/rules/simulate") return { action: "proxy", matched_rule_id: "r-1", matched_rule_name: "Test Rule" };
    return {};
  };

  const conns = await api.getConnections({ limit: 50 });
  assert.equal(conns.length, 1);
  assert.equal(conns[0].processName, "test.exe");

  const summary = await api.getConnectionsSummary();
  assert.equal(summary.activeCount, 1);

  const discovered = await api.discoverEndpoints(0);
  assert.equal(discovered[0].clientName, "Clash");

  const addRes = await api.addDiscoveredEndpoint({ name: "Clash (7890)", kind: "socks5", endpoint: "127.0.0.1:7890" });
  assert.equal(addRes.id, "p-disc");

  const timeline = await api.getTimeline({ limit: 20 });
  assert.equal(timeline[0].category, "config_change");

  const clearRes = await api.clearTimeline();
  assert.equal(clearRes.ok, true);

  const simRes = await api.simulateRule({ process_name: "test.exe", dest_port: 443 });
  assert.equal(simRes.action, "proxy");
  assert.equal(simRes.matched_rule_name, "Test Rule");
});

test("Tauri IPC bridge methods for autostart and updater exist and dispatch", async () => {
  let invoked = [];
  globalThis.window = {
    __TAURI__: {
      tauri: {
        invoke: async (cmd, args) => {
          invoked.push({ cmd, args });
          if (cmd === "get_autostart_status") return { enabled: true, silent: true, method: "task_scheduler", isElevated: true };
          if (cmd === "set_autostart_config") return { enabled: args.enabled, silent: args.silent, method: "task_scheduler", isElevated: true };
          if (cmd === "check_update") return { hasUpdate: true, latestVersion: "0.2.0", currentVersion: "0.1.0" };
          if (cmd === "install_update") return { ok: true };
          return {};
        }
      }
    }
  };

  try {
    const api = new CoreApi();
    const autoStatus = await api.getAutostartStatus();
    assert.equal(autoStatus.enabled, true);
    assert.equal(autoStatus.method, "task_scheduler");

    const setStatus = await api.setAutostartConfig(false, false);
    assert.equal(setStatus.enabled, false);

    const updateCheck = await api.checkForAppUpdates();
    assert.equal(updateCheck.hasUpdate, true);
    assert.equal(updateCheck.latestVersion, "0.2.0");

    const installRes = await api.installAppUpdate("https://example.com/installer.exe");
    assert.equal(installRes.ok, true);
  } finally {
    delete globalThis.window;
  }
});

test("HTML and App components for Explain Route, Policy Simulator, Discovery, Timeline, Autostart and Updater are integrated", () => {
  assert.match(html, /id="explainModal"/);
  assert.match(html, /id="simulatorModal"/);
  assert.match(html, /id="discoveryModal"/);
  assert.match(html, /id="timelineModal"/);
  assert.match(html, /id="updateModal"/);

  assert.match(html, /id="openSimulatorBtn"/);
  assert.match(html, /id="openDiscoveryBtn"/);
  assert.match(html, /id="openTimelineBtn"/);
  assert.match(html, /id="overviewActivityTab"/);
  assert.match(html, /id="overviewConnectionsTab"/);
  assert.match(html, /id="liveConnectionsTable"/);
  assert.match(html, /id="autostartEnabled"/);
  assert.match(html, /id="autostartSilent"/);
  assert.match(html, /id="checkForUpdatesBtn"/);

  assert.match(app, /function switchOverviewTab\(/);
  assert.match(app, /function renderLiveConnections\(/);
  assert.match(app, /async function openExplainModal\(/);
  assert.match(app, /async function runSimulation\(/);
  assert.match(app, /async function runEndpointDiscovery\(/);
  assert.match(app, /async function loadTimelineEvents\(/);
  assert.match(app, /async function loadAutostartConfig\(/);
  assert.match(app, /async function checkAppUpdates\(/);
  assert.match(app, /async function installAppUpdate\(/);
  assert.match(app, /res\.hasUpdate/);
  assert.match(app, /state\.updateInfo\.downloadUrl/);
  assert.match(app, /plan\.recommendedActions/);
  assert.match(app, /planId: state\.doctorRepairPlan\.planId/);
  assert.match(app, /snapshotId: id/);
  assert.match(app, /expectedSha256: state\.studioActiveDoc\.sha256/);
  assert.doesNotMatch(app, /state\.updateInfo\.download_url/);
});
