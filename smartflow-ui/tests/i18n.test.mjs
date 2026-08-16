import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { getLanguage, initializeLanguage, setLanguage, t } from "../dist/i18n.mjs";

const html = readFileSync(new URL("../dist/index.html", import.meta.url), "utf8");

test("Simplified Chinese is the default interface language", () => {
  initializeLanguage();
  assert.equal(getLanguage(), "zh-CN");
  assert.equal(t("nav.overview"), "概览");
  assert.equal(t("settings.protection"), "防泄漏保护");
});

test("English translations can be selected without changing application data", () => {
  setLanguage("en");
  assert.equal(getLanguage(), "en");
  assert.equal(t("nav.overview"), "Overview");
  assert.equal(t("settings.protection"), "Leak Protection");
  assert.equal(
    t("overview.summary", { rules: 1, proxies: 1, hits: 6, ruleLabel: t("overview.ruleSingular"), proxyLabel: t("overview.proxySingular") }),
    "1 active rule · 1 proxy · 6 hits this session"
  );
  setLanguage("zh-CN");
});

test("every static translation key exists in both languages", () => {
  const keys = [...html.matchAll(/data-i18n(?:-placeholder|-title|-aria-label)?="([^"]+)"/g)].map((match) => match[1]);
  for (const language of ["zh-CN", "en"]) {
    setLanguage(language);
    for (const key of keys) assert.notEqual(t(key), key, `missing ${language} translation: ${key}`);
  }
  setLanguage("zh-CN");
});

test("overview labels in-memory counters as session totals", () => {
  setLanguage("zh-CN");
  assert.match(t("overview.summary"), /本次运行/);
  setLanguage("en");
  assert.match(t("overview.summary"), /this session/);
  setLanguage("zh-CN");
});
