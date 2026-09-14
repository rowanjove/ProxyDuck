import test from "node:test";
import assert from "node:assert/strict";

import { CoreApi, CoreApiError } from "../dist/api.mjs";

function installTauriSession() {
  let refreshes = 0;
  globalThis.window = {
    __TAURI__: {
      tauri: {
        invoke: async () => {
          refreshes += 1;
          return { coreUrl: "http://127.0.0.1:46666", token: "token", transport: "named_pipe" };
        }
      }
    }
  };
  return () => refreshes;
}

test("Named Pipe API errors are returned once with diagnostics", async () => {
  const refreshes = installTauriSession();
  try {
    const api = new CoreApi();
    api.transport = "named_pipe";
    const expected = new CoreApiError("strict config rejected", [{ code: "PD-RULE-DESTINATION-UNSUPPORTED" }], 400);
    let calls = 0;
    api.requestNamedPipe = async () => {
      calls += 1;
      throw expected;
    };

    await assert.rejects(api.put("/config", {}), (error) => error === expected);
    assert.equal(calls, 1);
    assert.equal(refreshes(), 0);
  } finally {
    delete globalThis.window;
  }
});

test("uncertain Named Pipe writes are not replayed", async () => {
  const refreshes = installTauriSession();
  try {
    const api = new CoreApi();
    api.transport = "named_pipe";
    let calls = 0;
    api.requestNamedPipe = async () => {
      calls += 1;
      throw new Error("pipe closed after write");
    };

    await assert.rejects(api.post("/rules", {}), /pipe closed after write/);
    assert.equal(calls, 1);
    assert.equal(refreshes(), 0);
  } finally {
    delete globalThis.window;
  }
});

test("idempotent Named Pipe reads may reconnect once", async () => {
  const refreshes = installTauriSession();
  try {
    const api = new CoreApi();
    api.transport = "named_pipe";
    let calls = 0;
    api.requestNamedPipe = async () => {
      calls += 1;
      if (calls === 1) throw new Error("pipe disconnected");
      return { data: { ok: true } };
    };

    const result = await api.get("/snapshot");
    assert.deepEqual(result, { data: { ok: true } });
    assert.equal(calls, 2);
    assert.equal(refreshes(), 1);
  } finally {
    delete globalThis.window;
  }
});

test("successful Named Pipe responses expose top-level diagnostics", async () => {
  globalThis.window = {
    __TAURI__: {
      tauri: {
        invoke: async () => ({
          status: 200,
          body: {
            ok: true,
            data: { id: "config" },
            diagnostics: [{ code: "PD-RULE-DESTINATION-UNSUPPORTED", severity: "warning" }]
          }
        })
      }
    }
  };
  try {
    const api = new CoreApi();
    api.transport = "named_pipe";
    assert.deepEqual(await api.get("/config"), { id: "config" });
    assert.deepEqual(api.lastDiagnostics, [{ code: "PD-RULE-DESTINATION-UNSUPPORTED", severity: "warning" }]);
  } finally {
    delete globalThis.window;
  }
});
