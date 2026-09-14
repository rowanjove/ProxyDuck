import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");
const css = readFileSync(new URL("../dist/styles.css", import.meta.url), "utf8");
const app = readFileSync(new URL("../dist/app.js", import.meta.url), "utf8");
const api = readFileSync(new URL("../dist/api.mjs", import.meta.url), "utf8");
const frontend = `${api}\n${app}`;

test("desktop shell keeps the requested navigation hierarchy", () => {
  const views = [...html.matchAll(/data-view="([^"]+)"/g)].map((match) => match[1]);
  assert.deepEqual(views, ["overview", "rules", "doctor", "studio", "history", "profiles", "proxies", "processes", "launch", "settings"]);
  assert.doesNotMatch(html, /data-view="diagnostics"/);
  assert.match(css, /grid-template-columns:\s*168px minmax\(0, 1fr\)/);
});

test("shared desktop components are present", () => {
  for (const className of [
    "app-shell",
    "sidebar",
    "page-heading",
    "desktop-section",
    "data-table",
    "data-list",
    "status-badge",
    "runtime-switch",
    "empty-state"
  ]) {
    assert.match(css, new RegExp(`\\.${className}\\b`));
  }
});

test("visual system avoids dashboard decoration", () => {
  assert.doesNotMatch(css, /(?:linear|radial)-gradient/);
  assert.doesNotMatch(html, /runtime-hero|metric-grid|metric-card|proxy-card|launch-card/);
  assert.match(css, /--radius-sm:\s*6px/);
  assert.match(css, /--radius-md:\s*8px/);
  assert.match(css, /--radius-lg:\s*10px/);
});

test("switch thumbs stay clipped inside a non-replaced visual track", () => {
  assert.doesNotMatch(css, /\.(?:inline-switch|switch)::after/);
  assert.match(css, /\.switch-track\s*\{[^}]*overflow:\s*hidden/s);
  assert.match(css, /\.switch-track::after/);
  assert.match(html, /class="switch-control"/);
  assert.match(app, /class="switch-control compact"/);
});

test("dynamic rule and proxy switches dispatch their data actions", () => {
  assert.match(app, /addEventListener\("change"/);
  assert.match(app, /input\[type="checkbox"\]\[data-action\]/);
  assert.match(app, /handleAction\(control\)/);
  assert.match(app, /control\.checked = previousChecked/);
});

test("proxy modal restores endpoint input state and overview reports truthful routing status", () => {
  assert.match(app, /function syncProxyEndpointState\(\)/);
  assert.match(app, /\$\("proxyKind"\)\.addEventListener\("change", syncProxyEndpointState\)/);
  assert.match(app, /state\.config\.runtime\.enabled/);
  assert.match(app, /proxy\?\.enabled/);
});

test("existing API and IPC boundaries remain wired", () => {
  for (const contract of [
    'invokeTauri("refresh_core_session")',
    'invokeTauri("get_system_preflight")',
    'invokeTauri("sync_runtime_enabled"',
    'invokeTauri("choose_executable")',
    'api.get("/config")',
    'api.get("/capabilities")',
    'api.get("/snapshot")',
    'api.get("/processes"',
    'api.post("/runtime"',
    'api.post(`/proxies/${id}/test`',
    'api.get("/rules/conflicts")',
    'api.get(`/rules/evaluate/${button.dataset.pid}`)',
    'api.post(`/rules/${id}/duplicate`',
    'api.post("/rules/reorder"',
    'api.put("/config"',
    'api.post(templateId === "ai-dev"'
  ]) {
    assert.ok(frontend.includes(contract), `missing contract: ${contract}`);
  }
  assert.match(app, /function scheduleReconnect\(\)/);
  assert.match(app, /state\.reconnectInFlight/);
  assert.match(api, /class CoreApiError extends Error/);
  assert.match(api, /details\?\.diagnostics/);
  assert.match(api, /payload\?\.diagnostics/);
  assert.match(api, /requestNamedPipe\(method, path, body, timeout\)/);
});

test("rule workbench supports editing duplication ordering and dry runs", () => {
  assert.match(app, /state\.editingRuleId/);
  assert.match(app, /data-action="edit-rule"/);
  assert.match(app, /data-action="duplicate-rule"/);
  assert.match(app, /data-action="move-rule-up"/);
  assert.match(app, /data-action="evaluate-process"/);
  assert.match(html, /id="ruleModalTitle"/);
});

test("rule workbench exposes grouping, tags, and batch state controls", () => {
  assert.match(html, /id="ruleGroup"/);
  assert.match(html, /id="ruleTags"/);
  assert.match(html, /id="ruleBatchEnableBtn"/);
  assert.match(html, /id="ruleBatchDisableBtn"/);
  assert.match(app, /api\.post\("\/rules\/batch-enabled"/);
  assert.match(app, /data-rule-select/);
  assert.match(app, /templateSelect/);
  assert.match(html, /value="browser"/);
});

test("profile workbench exposes snapshot lifecycle actions", () => {
  assert.match(html, /id="view-profiles"/);
  assert.match(html, /data-action="create-profile"/);
  for (const action of ["diff-profile", "clone-profile", "activate-profile", "delete-profile"]) {
    assert.match(app, new RegExp(`data-action=\\"${action}\\"`));
  }
  for (const contract of [
    'api.post("/profiles"',
    'api.post(`/profiles/${id}/activate`',
    'api.post(`/profiles/${id}/clone`',
    'api.get(`/profiles/${id}/diff`'
  ]) {
    assert.ok(frontend.includes(contract), `missing profile contract: ${contract}`);
  }
});

test("settings provide redacted config and diagnostics portability", () => {
  assert.match(app, /function sanitizedConfig\(\)/);
  assert.match(app, /proxy\.password = null/);
  assert.match(app, /function exportDiagnostics\(\)/);
  assert.match(app, /async function importConfigFile\(file\)/);
  assert.match(html, /id="importConfigFile"/);
});

test("configuration import previews replacement scope before applying", () => {
  assert.match(app, /api\.post\("\/config\/import\/preview"/);
  assert.match(app, /preview\.changedSections/);
  assert.match(app, /preview\.validationError/);
  assert.match(app, /operation: t\(`confirm\.importOperation/);
});

test("proxy endpoint import previews and applies common client files", () => {
  assert.match(html, /id="importProxiesBtn"/);
  assert.match(html, /id="importProxiesFile"/);
  assert.match(app, /api\.post\("\/proxies\/import\/preview"/);
  assert.match(app, /api\.post\("\/proxies\/import"/);
  assert.match(app, /preview\.items \|\| \[\]/);
  assert.match(app, /confirm\.importProxiesPreviewDescription/);
});

test("first-run setup verifies desktop prerequisites and an actively tested proxy", () => {
  assert.match(html, /id="onboardingPanel"/);
  assert.match(app, /function renderOnboarding\(\)/);
  assert.match(app, /proxyduck-onboarding-dismissed/);
  assert.match(app, /proxydock-onboarding-dismissed/);
  assert.match(app, /state\.preflight\?\.desktopBridge/);
  assert.match(app, /state\.testedProxyIds\.has\(proxy\.id\)/);
  assert.match(app, /dataPlane\?\.phase === "running"/);
});

test("engine and proxy choices follow core capability declarations", () => {
  assert.match(app, /function renderCapabilities\(\)/);
  assert.match(app, /capability\.available/);
  assert.match(app, /capability\.supportedProxyKinds/);
  assert.match(app, /supportsChildInheritance/);
  assert.match(app, /api\.post\("\/engine\/mode", \{ mode: nextMode \}\)/);
  assert.match(app, /engineMode"\)\.addEventListener\("change"/);
  assert.doesNotMatch(html, /<option value="http">HTTP<\/option>/);
});

test("desktop right click opens an application menu instead of the browser menu", () => {
  assert.match(html, /id="appContextMenu"/);
  assert.match(html, /data-context-action="refresh"/);
  assert.match(html, /data-context-action="add-rule"/);
  assert.match(app, /addEventListener\("contextmenu"/);
  assert.match(app, /event\.preventDefault\(\)/);
});

test("view all recent activity opens the complete activity dialog", () => {
  assert.match(html, /data-open-modal="activity"/);
  assert.match(html, /id="activityModal"/);
  assert.match(html, /id="allActivity"/);
  assert.doesNotMatch(html, /data-view-jump="settings"[^>]*>[^<]*<span data-i18n="overview\.viewAll"/);
  assert.match(app, /function renderAllActivity\(\)/);
});

test("overview routing badges use actual data-plane state", () => {
  assert.match(app, /state\.runtimeStatus\?\.dataPlane\?\.phase/);
  assert.match(app, /dataPlaneRunning/);
  assert.match(html, /id="dataPlaneStatusValue"/);
  assert.match(html, /id="leakProtectionMode"/);
  assert.match(app, /failClosedActive/);
});

test("runtime diagnostics expose strict blockers and compatibility warnings", () => {
  assert.match(html, /id="compileDiagnosticsValue"/);
  assert.match(app, /runtimeStatus\?\.compileDiagnostics/);
  assert.match(app, /diagnostic-error/);
  assert.match(app, /diagnostic-warning/);
});
