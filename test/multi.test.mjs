import assert from "node:assert/strict";
import worker from "../src/multi.js";

class MemoryKV {
  constructor() { this.data = new Map(); }
  async get(key, type) {
    const value = this.data.get(key);
    if (value == null) return null;
    return type === "json" ? JSON.parse(value) : value;
  }
  async put(key, value) { this.data.set(key, String(value)); }
  async delete(key) { this.data.delete(key); }
  async list(options) {
    const prefix = String((options && options.prefix) || "");
    const limit = Number((options && options.limit) || 1000);
    const offset = Number(String((options && options.cursor) || "0").replace("cursor_", "")) || 0;
    const names = Array.from(this.data.keys()).filter(function (key) {
      return key.startsWith(prefix);
    }).sort();
    const page = names.slice(offset, offset + limit);
    const nextOffset = offset + page.length;
    return {
      keys: page.map(function (name) { return { name: name }; }),
      list_complete: nextOffset >= names.length,
      cursor: nextOffset < names.length ? "cursor_" + nextOffset : "",
    };
  }
}

const env = {
  CONFIG_STORE: new MemoryKV(),
  ADMIN_PASSWORD: "correct horse battery staple",
};

const telegramCalls = [];
const originalFetch = globalThis.fetch;
globalThis.fetch = async function (url, options) {
  const match = String(url).match(/\/bot([^/]+)\/([^/]+)$/);
  const token = match[1];
  const method = match[2];
  const body = JSON.parse(options.body);
  telegramCalls.push({ token: token, method: method, body: body });
  if (method === "getMe") {
    const first = token.startsWith("999");
    return new Response(JSON.stringify({
      ok: true,
      result: { id: first ? 999 : 888, username: first ? "AlertBotOne" : "AlertBotTwo" },
    }), { status: 200 });
  }
  return new Response(JSON.stringify({ ok: true, result: true }), { status: 200 });
};

const waiters = [];
const ctx = { waitUntil: function (promise) { waiters.push(promise); } };
async function drainWaiters() {
  await Promise.all(waiters.splice(0));
}

async function post(path, cookie, csrf, fields) {
  const body = new URLSearchParams(Object.assign({ _csrf: csrf }, fields));
  return worker.fetch(new Request("https://worker.example" + path, {
    method: "POST",
    headers: { cookie: cookie },
    body: body,
  }), env, ctx);
}

async function webhook(bot, payload, secret) {
  return worker.fetch(new Request("https://worker.example/telegram-webhook/" + bot.id, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "X-Telegram-Bot-Api-Secret-Token": secret || bot.webhookSecret,
    },
    body: JSON.stringify(payload),
  }), env, ctx);
}

try {
  const migrationEnv = {
    CONFIG_STORE: new MemoryKV(),
    ADMIN_PASSWORD: env.ADMIN_PASSWORD,
  };
  await migrationEnv.CONFIG_STORE.put("telegram-alert:config:v1", JSON.stringify({
    tokenCipher: "encrypted-token-placeholder",
    botId: "777",
    botUsername: "LegacyBot",
    enabled: true,
    webhookSecret: "legacy-secret",
    webhookUrl: "https://worker.example/telegram-webhook",
    ownerChatId: "444",
  }));
  const migrationHealth = await worker.fetch(new Request("https://worker.example/health"), migrationEnv, ctx);
  assert.deepEqual(await migrationHealth.json(), { ok: true, bots: 1, enabledBots: 1, senders: 0, rules: 0 });

  const v2Env = { CONFIG_STORE: new MemoryKV(), ADMIN_PASSWORD: env.ADMIN_PASSWORD };
  await v2Env.CONFIG_STORE.put("telegram-alert:state:v2", JSON.stringify({
    version: 2,
    bots: [{
      id: "bot_v2test",
      label: "بات نسخه دو",
      tokenCipher: "cipher",
      telegramBotId: "111",
      botUsername: "V2Bot",
      enabled: true,
      webhookSecret: "secret",
      webhookUrl: "https://worker.example/telegram-webhook/bot_v2test",
      ownerChatId: "222",
      connectionEnabled: true,
      rules: [{
        id: "rule_v2test",
        keyword: "قطع شد",
        alertMessage: "هشدار",
        cooldownSeconds: 300,
        enabled: true,
      }],
    }],
  }));
  const v2Health = await worker.fetch(new Request("https://worker.example/health"), v2Env, ctx);
  assert.deepEqual(await v2Health.json(), { ok: true, bots: 1, enabledBots: 1, senders: 0, rules: 1 });
  const migratedV3 = await v2Env.CONFIG_STORE.get("telegram-alert:state:v3", "json");
  assert.equal(migratedV3.bots[0].rules[0].senderRef, "*");
  assert.equal(migratedV3.bots[0].rules[0].matchType, "contains");

  const loginResponse = await worker.fetch(new Request("https://worker.example/login", {
    method: "POST",
    headers: { origin: "null" },
    body: new URLSearchParams({ password: env.ADMIN_PASSWORD }),
  }), env, ctx);
  assert.equal(loginResponse.status, 303);
  const cookie = loginResponse.headers.get("set-cookie").split(";")[0];

  const adminResponse = await worker.fetch(new Request("https://worker.example/admin", {
    headers: { cookie: cookie },
  }), env, ctx);
  assert.equal(adminResponse.status, 200);
  const adminHtml = await adminResponse.text();
  const csrf = adminHtml.match(/name='_csrf' value='([^']+)'/)?.[1];
  assert.ok(csrf);
  assert.match(adminHtml, /دسترسی سریع/);
  assert.match(adminHtml, /افزودن بات/);

  const rejectedCsrf = await post("/admin/bot/save", cookie, "wrong", {
    label: "نباید ذخیره شود",
    bot_token: "777:BAD",
    enabled: "on",
  });
  assert.equal(rejectedCsrf.status, 403);

  const firstBotResponse = await post("/admin/bot/save", cookie, csrf, {
    label: "هشدار سایت",
    bot_token: "999:ONE",
    enabled: "on",
  });
  assert.equal(firstBotResponse.status, 303);

  const secondBotResponse = await post("/admin/bot/save", cookie, csrf, {
    label: "هشدار شبکه",
    bot_token: "888:TWO",
    enabled: "on",
  });
  assert.equal(secondBotResponse.status, 303);

  let state = await env.CONFIG_STORE.get("telegram-alert:state:v3", "json");
  assert.equal(state.bots.length, 2);
  const firstBot = state.bots.find(function (bot) { return bot.telegramBotId === "999"; });
  const secondBot = state.bots.find(function (bot) { return bot.telegramBotId === "888"; });
  assert.ok(firstBot && secondBot);
  assert.notEqual(firstBot.webhookUrl, secondBot.webhookUrl);
  assert.notEqual(firstBot.tokenCipher, "999:ONE");
  assert.notEqual(secondBot.tokenCipher, "888:TWO");

  const webhookCalls = telegramCalls.filter(function (call) { return call.method === "setWebhook"; });
  assert.equal(webhookCalls.length, 2);
  assert.match(webhookCalls[0].body.url, /\/telegram-webhook\/bot_/);

  const firstSenderResponse = await post("/admin/sender/save", cookie, csrf, {
    bot_id: firstBot.id,
    label: "مانیتور سایت",
    telegram_id: "12345",
    enabled: "on",
  });
  assert.equal(firstSenderResponse.status, 303);

  const secondSenderResponse = await post("/admin/sender/save", cookie, csrf, {
    bot_id: firstBot.id,
    label: "مانیتور پشتیبان",
    telegram_id: "54321",
    enabled: "on",
  });
  assert.equal(secondSenderResponse.status, 303);

  state = await env.CONFIG_STORE.get("telegram-alert:state:v3", "json");
  const configuredFirst = state.bots.find(function (bot) { return bot.id === firstBot.id; });
  assert.equal(configuredFirst.senders.length, 2);
  const monitoredSender = configuredFirst.senders.find(function (sender) { return sender.telegramId === "12345"; });
  assert.ok(monitoredSender);

  const firstRule = await post("/admin/rule/save", cookie, csrf, {
    bot_id: firstBot.id,
    sender_ref: monitoredSender.id,
    match_type: "any",
    keyword: "",
    alert_message: "هشدار اول",
    cooldown_seconds: "300",
    enabled: "on",
  });
  assert.equal(firstRule.status, 303);

  const secondRule = await post("/admin/rule/save", cookie, csrf, {
    bot_id: firstBot.id,
    sender_ref: monitoredSender.id,
    match_type: "contains",
    keyword: "DOWN",
    alert_message: "هشدار دوم",
    cooldown_seconds: "300",
    enabled: "on",
  });
  assert.equal(secondRule.status, 303);

  const thirdRule = await post("/admin/rule/save", cookie, csrf, {
    bot_id: secondBot.id,
    sender_ref: "*",
    match_type: "contains",
    keyword: "خطای شبکه",
    alert_message: "هشدار بات دوم",
    cooldown_seconds: "0",
    enabled: "on",
  });
  assert.equal(thirdRule.status, 303);

  state = await env.CONFIG_STORE.get("telegram-alert:state:v3", "json");
  const currentFirst = state.bots.find(function (bot) { return bot.id === firstBot.id; });
  const currentSecond = state.bots.find(function (bot) { return bot.id === secondBot.id; });
  assert.equal(currentFirst.rules.length, 2);
  assert.equal(currentSecond.rules.length, 1);

  const rulesPage = await worker.fetch(new Request(
    "https://worker.example/admin?tab=rules&bot=" + currentFirst.id,
    { headers: { cookie: cookie } },
  ), env, ctx);
  const rulesHtml = await rulesPage.text();
  assert.match(rulesHtml, /name='sender_ref'/);
  assert.match(rulesHtml, /هر پیام/);
  assert.match(rulesHtml, /شامل عبارت/);
  assert.match(rulesHtml, /افزودن هشدار/);

  const sendersPage = await worker.fetch(new Request(
    "https://worker.example/admin?tab=senders&bot=" + currentFirst.id,
    { headers: { cookie: cookie } },
  ), env, ctx);
  const sendersHtml = await sendersPage.text();
  assert.match(sendersHtml, /افزودن فرستنده/);
  assert.match(sendersHtml, /مانیتور سایت/);

  const connectionOne = await webhook(currentFirst, {
    update_id: 1,
    business_connection: {
      id: "business-one",
      user: { id: 555 },
      user_chat_id: 555,
      is_enabled: true,
    },
  });
  assert.equal(connectionOne.status, 200);

  const connectionTwo = await webhook(currentSecond, {
    update_id: 2,
    business_connection: {
      id: "business-two",
      user: { id: 666 },
      user_chat_id: 666,
      is_enabled: true,
    },
  });
  assert.equal(connectionTwo.status, 200);

  state = await env.CONFIG_STORE.get("telegram-alert:state:v3", "json");
  const readyFirst = state.bots.find(function (bot) { return bot.id === firstBot.id; });
  const readySecond = state.bots.find(function (bot) { return bot.id === secondBot.id; });

  const firstAlert = await webhook(readyFirst, {
    update_id: 3,
    business_message: {
      message_id: 10,
      date: 1780000010,
      from: { id: 12345, first_name: "سامانه", last_name: "مانیتورینگ" },
      chat: { id: 12345, type: "private", first_name: "سامانه", last_name: "مانیتورینگ" },
      text: "Monitoring: SERVICE DOWN",
    },
  });
  assert.equal(firstAlert.status, 200);
  await drainWaiters();

  const firstSends = telegramCalls.filter(function (call) {
    return call.method === "sendMessage" && call.token === "999:ONE";
  });
  assert.equal(firstSends.length, 2);
  assert.deepEqual(firstSends.map(function (call) { return call.body.text; }).sort(), ["هشدار اول", "هشدار دوم"]);
  assert.ok(firstSends.every(function (call) { return String(call.body.chat_id) === "555"; }));

  await webhook(readyFirst, {
    update_id: 4,
    business_message: {
      message_id: 11,
      date: 1780000020,
      from: { id: 12345, first_name: "سامانه", last_name: "مانیتورینگ" },
      chat: { id: 12345, type: "private", first_name: "سامانه", last_name: "مانیتورینگ" },
      text: "down",
    },
  });
  await drainWaiters();
  assert.equal(telegramCalls.filter(function (call) {
    return call.method === "sendMessage" && call.token === "999:ONE";
  }).length, 2);

  await webhook(readyFirst, {
    update_id: 41,
    business_message: {
      message_id: 14,
      date: 1780000030,
      from: { id: 54321, first_name: "پشتیبان" },
      chat: { id: 54321, type: "private", first_name: "پشتیبان" },
      text: "down",
    },
  });
  await drainWaiters();
  assert.equal(telegramCalls.filter(function (call) {
    return call.method === "sendMessage" && call.token === "999:ONE";
  }).length, 2);

  await webhook(readySecond, {
    update_id: 5,
    business_message: {
      message_id: 12,
      date: 1780000040,
      from: { id: 98765, first_name: "علی", last_name: "احمدی" },
      chat: { id: 98765, type: "private", first_name: "علی", last_name: "احمدی" },
      caption: "خطای شبکه رخ داد",
    },
  });
  await drainWaiters();
  const secondSend = telegramCalls.find(function (call) {
    return call.method === "sendMessage" && call.token === "888:TWO";
  });
  assert.ok(secondSend);
  assert.equal(String(secondSend.body.chat_id), "666");
  assert.equal(secondSend.body.text, "هشدار بات دوم");

  const noMatchCount = telegramCalls.filter(function (call) { return call.method === "sendMessage"; }).length;
  await webhook(readySecond, {
    update_id: 6,
    business_message: {
      message_id: 13,
      date: 1780000050,
      from: { id: 98765, first_name: "علی", last_name: "احمدی" },
      chat: { id: 98765, type: "private", first_name: "علی", last_name: "احمدی" },
      text: "همه چیز عادی است",
    },
  });
  await drainWaiters();
  assert.equal(telegramCalls.filter(function (call) { return call.method === "sendMessage"; }).length, noMatchCount);

  await webhook(readyFirst, {
    update_id: 7,
    business_message: {
      message_id: 15,
      date: 1780000060,
      from: { id: 555, first_name: "محمد" },
      chat: { id: 12345, type: "private", first_name: "سامانه", last_name: "مانیتورینگ" },
      text: "پیام خروجی مالک",
    },
  });
  await drainWaiters();
  assert.equal(telegramCalls.filter(function (call) { return call.method === "sendMessage"; }).length, noMatchCount);

  const historyKeysBeforeRetry = (await env.CONFIG_STORE.list({ prefix: "telegram-alert:message:v1:" })).keys;
  assert.equal(historyKeysBeforeRetry.length, 6);
  const encryptedHistoryValue = await env.CONFIG_STORE.get(historyKeysBeforeRetry[0].name);
  assert.doesNotMatch(encryptedHistoryValue, /همه چیز عادی|Monitoring|پیام خروجی مالک/);
  await webhook(readySecond, {
    update_id: 6,
    business_message: {
      message_id: 13,
      date: 1780000050,
      from: { id: 98765, first_name: "علی", last_name: "احمدی" },
      chat: { id: 98765, type: "private", first_name: "علی", last_name: "احمدی" },
      text: "همه چیز عادی است",
    },
  });
  assert.equal((await env.CONFIG_STORE.list({ prefix: "telegram-alert:message:v1:" })).keys.length, 6);

  const messagesPage = await worker.fetch(new Request("https://worker.example/admin?tab=messages", {
    headers: { cookie: cookie },
  }), env, ctx);
  const messagesHtml = await messagesPage.text();
  assert.match(messagesHtml, /پیام خروجی مالک/);
  assert.match(messagesHtml, /علی احمدی/);
  assert.match(messagesHtml, /مانیتور سایت/);
  assert.match(messagesHtml, /class='bubble incoming'/);
  assert.match(messagesHtml, /class='bubble outgoing'/);

  const overviewAfterMessages = await worker.fetch(new Request("https://worker.example/admin", {
    headers: { cookie: cookie },
  }), env, ctx);
  const overviewAfterMessagesHtml = await overviewAfterMessages.text();
  assert.match(overviewAfterMessagesHtml, /آخرین پیام/);
  assert.match(overviewAfterMessagesHtml, /پیام خروجی مالک/);

  const forbidden = await webhook(readyFirst, {}, "wrong-secret");
  assert.equal(forbidden.status, 403);

  const health = await worker.fetch(new Request("https://worker.example/health"), env, ctx);
  assert.deepEqual(await health.json(), { ok: true, bots: 2, enabledBots: 2, senders: 2, rules: 3 });

  const crossOriginLogin = await worker.fetch(new Request("https://worker.example/login", {
    method: "POST",
    headers: { origin: "https://attacker.example" },
    body: new URLSearchParams({ password: env.ADMIN_PASSWORD }),
  }), env, ctx);
  assert.equal(crossOriginLogin.status, 403);

  console.log("All multi-bot worker tests passed.");
} finally {
  globalThis.fetch = originalFetch;
}
