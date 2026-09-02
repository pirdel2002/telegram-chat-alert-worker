import assert from "node:assert/strict";
import worker from "../src/index.js";

class MemoryKV {
  constructor() { this.data = new Map(); }
  async get(key, type) {
    const value = this.data.get(key);
    if (value == null) return null;
    return type === "json" ? JSON.parse(value) : value;
  }
  async put(key, value) { this.data.set(key, String(value)); }
  async delete(key) { this.data.delete(key); }
}

const env = {
  CONFIG_STORE: new MemoryKV(),
  ADMIN_PASSWORD: "correct horse battery staple",
};

const telegramCalls = [];
const originalFetch = globalThis.fetch;
globalThis.fetch = async (url, options) => {
  const method = String(url).split("/").at(-1);
  const body = JSON.parse(options.body);
  telegramCalls.push({ method, body });
  if (method === "getMe") {
    return new Response(JSON.stringify({ ok: true, result: { id: 999, username: "AlertBot" } }), { status: 200 });
  }
  return new Response(JSON.stringify({ ok: true, result: true }), { status: 200 });
};

const waiters = [];
const ctx = { waitUntil(promise) { waiters.push(promise); } };

try {
  const loginForm = new URLSearchParams({ password: env.ADMIN_PASSWORD });
  const loginResponse = await worker.fetch(new Request("https://worker.example/login", {
    method: "POST",
    headers: {
      referer: "https://worker.example/login",
      "sec-fetch-site": "same-origin",
      "content-type": "application/x-www-form-urlencoded",
    },
    body: loginForm,
  }), env, ctx);
  assert.equal(loginResponse.status, 303);
  const cookie = loginResponse.headers.get("set-cookie").split(";")[0];
  assert.match(cookie, /^ta_session=/);

  const crossOriginLogin = await worker.fetch(new Request("https://worker.example/login", {
    method: "POST",
    headers: {
      origin: "https://attacker.example",
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({ password: env.ADMIN_PASSWORD }),
  }), env, ctx);
  assert.equal(crossOriginLogin.status, 403);

  const adminResponse = await worker.fetch(new Request("https://worker.example/admin", {
    headers: { cookie },
  }), env, ctx);
  assert.equal(adminResponse.status, 200);

  const saveForm = new URLSearchParams({
    bot_token: "999:TEST_TOKEN",
    watched_sender_id: "123456789",
    alert_message: "سایت قطع شد",
    cooldown_seconds: "300",
    enabled: "on",
  });
  const saveResponse = await worker.fetch(new Request("https://worker.example/admin/save", {
    method: "POST",
    headers: {
      cookie,
      origin: "https://worker.example",
      "content-type": "application/x-www-form-urlencoded",
    },
    body: saveForm,
  }), env, ctx);
  assert.equal(saveResponse.status, 303);
  assert.deepEqual(telegramCalls.slice(0, 2).map((call) => call.method), ["getMe", "setWebhook"]);
  assert.equal(telegramCalls[1].body.url, "https://worker.example/telegram-webhook");

  const config = await env.CONFIG_STORE.get("telegram-alert:config:v1", "json");
  assert.equal(config.watchedSenderId, "123456789");
  assert.notEqual(config.tokenCipher, "999:TEST_TOKEN");

  const connectionResponse = await worker.fetch(new Request("https://worker.example/telegram-webhook", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Telegram-Bot-Api-Secret-Token": config.webhookSecret,
    },
    body: JSON.stringify({
      update_id: 1,
      business_connection: {
        id: "business-connection-1",
        user: { id: 555 },
        user_chat_id: 555,
        is_enabled: true,
      },
    }),
  }), env, ctx);
  assert.equal(connectionResponse.status, 200);

  const alertResponse = await worker.fetch(new Request("https://worker.example/telegram-webhook", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Telegram-Bot-Api-Secret-Token": config.webhookSecret,
    },
    body: JSON.stringify({
      update_id: 2,
      business_message: {
        message_id: 77,
        from: { id: 123456789 },
        chat: { id: 123456789, type: "private" },
        text: "monitor event",
      },
    }),
  }), env, ctx);
  assert.equal(alertResponse.status, 200);
  await Promise.all(waiters.splice(0));

  const sendCall = telegramCalls.find((call) => call.method === "sendMessage");
  assert.ok(sendCall);
  assert.equal(String(sendCall.body.chat_id), "555");
  assert.equal(sendCall.body.text, "سایت قطع شد");

  const sendsBeforeDuplicate = telegramCalls.filter((call) => call.method === "sendMessage").length;
  await worker.fetch(new Request("https://worker.example/telegram-webhook", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Telegram-Bot-Api-Secret-Token": config.webhookSecret,
    },
    body: JSON.stringify({
      update_id: 3,
      business_message: { message_id: 78, from: { id: 123456789 }, chat: { id: 123456789 } },
    }),
  }), env, ctx);
  await Promise.all(waiters.splice(0));
  assert.equal(telegramCalls.filter((call) => call.method === "sendMessage").length, sendsBeforeDuplicate);

  const forbidden = await worker.fetch(new Request("https://worker.example/telegram-webhook", {
    method: "POST",
    headers: { "content-type": "application/json", "X-Telegram-Bot-Api-Secret-Token": "wrong" },
    body: "{}",
  }), env, ctx);
  assert.equal(forbidden.status, 403);

  console.log("All worker flow tests passed.");
} finally {
  globalThis.fetch = originalFetch;
}
