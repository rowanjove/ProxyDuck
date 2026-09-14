import test from "node:test";
import assert from "node:assert/strict";

import {
  engineLabel,
  escapeHtml,
  matcherSummary,
  normalizeError,
  protectionSummary,
  totalHits,
  validateEndpoint
} from "../dist/lib.mjs";

test("escapeHtml protects dynamic table content", () => {
  assert.equal(escapeHtml(`<img src=x onerror="boom">`), "&lt;img src=x onerror=&quot;boom&quot;&gt;");
});

test("matcherSummary follows matcher priority fields", () => {
  assert.equal(matcherSummary({ pids: [42], exePaths: ["C:\\App.exe"], appNames: ["app.exe"] }), "PID 42 · C:\\App.exe · app.exe");
  assert.equal(matcherSummary({ wildcard: "cursor" }), "*cursor*");
});

test("endpoint validation rejects missing or invalid ports", () => {
  assert.equal(validateEndpoint("socks5", "127.0.0.1:7897"), true);
  assert.equal(validateEndpoint("http", "localhost:0"), false);
  assert.equal(validateEndpoint("socks5", "localhost"), false);
  assert.equal(validateEndpoint("direct", ""), true);
});

test("dashboard summaries are stable", () => {
  assert.equal(totalHits({ processHits: { node: 2, cursor: 3 } }), 5);
  assert.equal(protectionSummary({ dnsEnforced: true, ipv6Blocked: true, dohBlocked: false }), "2/3 已启用");
  assert.equal(engineLabel("win_divert"), "ProxiFyre");
});

test("normalizeError preserves structured routing diagnostics", () => {
  const error = new Error("配置应用失败");
  error.diagnostics = [
    { code: "PD-RULE-DESTINATION-UNSUPPORTED", remediation: "切换到 sing-box" },
    { code: "PD-RULE-NETWORK-UNSUPPORTED", message: "规则已降级" },
    { code: "PD-THIRD", effective: "仅匹配进程" },
    { code: "PD-FOURTH", message: "不应展开" }
  ];
  const message = normalizeError(error);
  assert.match(message, /PD-RULE-DESTINATION-UNSUPPORTED/);
  assert.match(message, /切换到 sing-box/);
  assert.match(message, /PD-RULE-NETWORK-UNSUPPORTED/);
  assert.match(message, /\+1/);
  assert.doesNotMatch(message, /PD-FOURTH/);
});
