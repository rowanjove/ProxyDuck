import test from "node:test";
import assert from "node:assert/strict";

import {
  engineLabel,
  escapeHtml,
  matcherSummary,
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
  assert.equal(engineLabel("win_divert"), "WinDivert");
});
