import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import worker from "../src/multi.js";

class MemoryKV {
  constructor() {
    this.data = new Map();
    this.readCount = 0;
    this.writeCount = 0;
    this.deleteCount = 0;
    this.listCount = 0;
  }
  async get(key, type) {
    this.readCount += 1;
    const value = this.data.get(key);
    if (value == null) return null;
    return type === "json" ? JSON.parse(value) : value;
  }
  async put(key, value) {
    this.writeCount += 1;
    this.data.set(key, String(value));
  }
  async delete(key) {
    this.deleteCount += 1;
    this.data.delete(key);
  }
  async list(options) {
    this.listCount += 1;
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

class TestD1Statement {
  constructor(database, sql, values) {
    this.database = database;
    this.sql = sql;
    this.values = values || [];
  }
  bind(...values) { return new TestD1Statement(this.database, this.sql, values); }
  async run() {
    const statement = this.database.prepare(this.sql);
    if (/\bRETURNING\b/i.test(this.sql)) {
      const results = statement.all(...this.values);
      return { success: true, results: results, meta: { changes: results.length } };
    }
    const result = statement.run(...this.values);
    return { success: true, results: [], meta: { changes: Number(result.changes) } };
  }
  async first() {
    return this.database.prepare(this.sql).get(...this.values) || null;
  }
  async all() {
    return { success: true, results: this.database.prepare(this.sql).all(...this.values), meta: {} };
  }
}

class TestD1 {
  constructor() { this.database = new DatabaseSync(":memory:"); }
  async exec(sql) { this.database.exec(sql); return { count: 1, duration: 0 }; }
  prepare(sql) { return new TestD1Statement(this.database, sql); }
  async batch(statements) { return Promise.all(statements.map(function (statement) { return statement.run(); })); }
}

const env = {
  CONFIG_STORE: new MemoryKV(),
  MESSAGE_DB: new TestD1(),
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
    MESSAGE_DB: new TestD1(),
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
  assert.deepEqual(await migrationHealth.json(), {
    ok: true, version: "4.3.0", runtimeStore: "d1", bots: 1, enabledBots: 1, senders: 0, rules: 0,
  });

  const v2Env = { CONFIG_STORE: new MemoryKV(), MESSAGE_DB: new TestD1(), ADMIN_PASSWORD: env.ADMIN_PASSWORD };
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
  assert.deepEqual(await v2Health.json(), {
    ok: true, version: "4.3.0", runtimeStore: "d1", bots: 1, enabledBots: 1, senders: 0, rules: 1,
  });
  const migratedV4 = await v2Env.CONFIG_STORE.get("telegram-alert:state:v4", "json");
  assert.equal(migratedV4.bots[0].rules[0].senderRef, "*");
  assert.equal(migratedV4.bots[0].rules[0].matchType, "contains");

  const v3Env = { CONFIG_STORE: new MemoryKV(), MESSAGE_DB: new TestD1(), ADMIN_PASSWORD: env.ADMIN_PASSWORD };
  await v3Env.CONFIG_STORE.put("telegram-alert:state:v3", JSON.stringify({
    version: 3,
    bots: [{
      id: "bot_oldone", label: "اول", tokenCipher: "cipher", rules: [{
        id: "rule_oldone", senderRef: "sender_oldone", matchType: "any", alertMessage: "الف", enabled: true,
      }],
      senders: [{ id: "sender_oldone", telegramId: "12345", label: "فرستنده مشترک", enabled: true }],
    }, {
      id: "bot_oldtwo", label: "دوم", tokenCipher: "cipher", rules: [{
        id: "rule_oldtwo", senderRef: "sender_oldtwo", matchType: "any", alertMessage: "ب", enabled: true,
      }],
      senders: [{ id: "sender_oldtwo", telegramId: "12345", label: "نام تکراری", enabled: true }],
    }],
  }));
  await worker.fetch(new Request("https://worker.example/health"), v3Env, ctx);
  const sharedMigration = await v3Env.CONFIG_STORE.get("telegram-alert:state:v4", "json");
  assert.equal(sharedMigration.senders.length, 1);
  assert.equal(sharedMigration.bots[0].rules[0].senderRef, sharedMigration.senders[0].id);
  assert.equal(sharedMigration.bots[1].rules[0].senderRef, sharedMigration.senders[0].id);

  await v3Env.CONFIG_STORE.put("telegram-alert:status:v2:bot_oldone", JSON.stringify({
    connection: "connected",
    lastAction: "وضعیت قدیمی",
  }));
  await v3Env.CONFIG_STORE.put("telegram-alert:cooldown:v2:bot_oldone:rule_oldone", "1");
  const v3Login = await worker.fetch(new Request("https://worker.example/login", {
    method: "POST",
    headers: { origin: "null" },
    body: new URLSearchParams({ password: env.ADMIN_PASSWORD }),
  }), v3Env, ctx);
  const v3Cookie = v3Login.headers.get("set-cookie").split(";")[0];
  const v3Admin = await worker.fetch(new Request("https://worker.example/admin", {
    headers: { cookie: v3Cookie },
  }), v3Env, ctx);
  assert.equal(v3Admin.status, 200);
  assert.ok(await v3Env.MESSAGE_DB.prepare(
    "SELECT payload_cipher FROM runtime_status WHERE bot_id = ?",
  ).bind("bot_oldone").first());
  assert.ok(await v3Env.MESSAGE_DB.prepare(
    "SELECT expires_at FROM rule_cooldowns WHERE bot_id = ? AND rule_id = ?",
  ).bind("bot_oldone", "rule_oldone").first());

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

  let state = await env.CONFIG_STORE.get("telegram-alert:state:v4", "json");
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
    label: "مانیتور سایت",
    telegram_id: "12345",
    enabled: "on",
  });
  assert.equal(firstSenderResponse.status, 303);

  const secondSenderResponse = await post("/admin/sender/save", cookie, csrf, {
    label: "مانیتور پشتیبان",
    telegram_id: "54321",
    enabled: "on",
  });
  assert.equal(secondSenderResponse.status, 303);

  const sharedSenderResponse = await post("/admin/sender/save", cookie, csrf, {
    label: "علی احمدی",
    telegram_id: "98765",
    enabled: "on",
  });
  assert.equal(sharedSenderResponse.status, 303);

  const ownerSenderResponse = await post("/admin/sender/save", cookie, csrf, {
    label: "محمد",
    telegram_id: "555",
    enabled: "on",
  });
  assert.equal(ownerSenderResponse.status, 303);

  state = await env.CONFIG_STORE.get("telegram-alert:state:v4", "json");
  const configuredFirst = state.bots.find(function (bot) { return bot.id === firstBot.id; });
  assert.equal(state.senders.length, 4);
  const monitoredSender = state.senders.find(function (sender) { return sender.telegramId === "12345"; });
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

  state = await env.CONFIG_STORE.get("telegram-alert:state:v4", "json");
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

  state = await env.CONFIG_STORE.get("telegram-alert:state:v4", "json");
  let readyFirst = state.bots.find(function (bot) { return bot.id === firstBot.id; });
  const readySecond = state.bots.find(function (bot) { return bot.id === secondBot.id; });
  assert.equal(readyFirst.connections.length, 1);
  assert.equal(readySecond.connections.length, 1);

  const connectionOneOtherSide = await webhook(readyFirst, {
    update_id: 21,
    business_connection: {
      id: "business-one-other-side",
      user: { id: 12345, first_name: "سامانه", last_name: "مانیتورینگ" },
      user_chat_id: 12345,
      is_enabled: true,
    },
  });
  assert.equal(connectionOneOtherSide.status, 200);
  state = await env.CONFIG_STORE.get("telegram-alert:state:v4", "json");
  readyFirst = state.bots.find(function (bot) { return bot.id === firstBot.id; });
  assert.equal(readyFirst.connections.length, 2);

  const kvWritesBeforeMessages = env.CONFIG_STORE.writeCount;
  const kvDeletesBeforeMessages = env.CONFIG_STORE.deleteCount;

  const firstAlert = await webhook(readyFirst, {
    update_id: 3,
    business_message: {
      message_id: 10,
      business_connection_id: "business-one",
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
  assert.ok(await env.MESSAGE_DB.prepare(
    "SELECT payload_cipher FROM runtime_status WHERE bot_id = ?",
  ).bind(readyFirst.id).first());
  assert.equal(Number((await env.MESSAGE_DB.prepare(
    "SELECT COUNT(*) AS count FROM rule_cooldowns WHERE bot_id = ?",
  ).bind(readyFirst.id).first()).count), 2);

  await webhook(readyFirst, {
    update_id: 22,
    business_message: {
      message_id: 110,
      business_connection_id: "business-one-other-side",
      date: 1780000010,
      from: { id: 12345, first_name: "سامانه", last_name: "مانیتورینگ" },
      chat: { id: 555, type: "private", first_name: "محمد" },
      text: "Monitoring: SERVICE DOWN",
    },
  });
  await drainWaiters();
  assert.equal(telegramCalls.filter(function (call) {
    return call.method === "sendMessage" && call.token === "999:ONE";
  }).length, 2);

  await webhook(readyFirst, {
    update_id: 4,
    business_message: {
      message_id: 11,
      business_connection_id: "business-one",
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
      business_connection_id: "business-one",
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
      business_connection_id: "business-two",
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
      business_connection_id: "business-two",
      date: 1780000050,
      from: { id: 98765, first_name: "علی", last_name: "احمدی" },
      chat: { id: 98765, type: "private", first_name: "علی", last_name: "احمدی" },
      text: "همه چیز عادی است",
    },
  });
  await drainWaiters();
  assert.equal(telegramCalls.filter(function (call) { return call.method === "sendMessage"; }).length, noMatchCount);

  const countBeforeUnknownChat = Number((await env.MESSAGE_DB.prepare("SELECT COUNT(*) AS count FROM messages").first()).count);
  await webhook(readySecond, {
    update_id: 61,
    business_message: {
      message_id: 131,
      business_connection_id: "business-two",
      date: 1780000055,
      from: { id: 77777, first_name: "Zari" },
      chat: { id: 77777, type: "private", first_name: "Zari" },
      text: "پیام چت تعریف‌نشده",
    },
  });
  await drainWaiters();
  assert.equal(Number((await env.MESSAGE_DB.prepare("SELECT COUNT(*) AS count FROM messages").first()).count), countBeforeUnknownChat);
  assert.equal(await env.MESSAGE_DB.prepare("SELECT source_key FROM chat_sources WHERE chat_id = ?").bind("77777").first(), null);

  await webhook(readyFirst, {
    update_id: 7,
    business_message: {
      message_id: 15,
      business_connection_id: "business-one",
      date: 1780000060,
      from: { id: 555, first_name: "محمد" },
      chat: { id: 12345, type: "private", first_name: "سامانه", last_name: "مانیتورینگ" },
      text: "پیام خروجی مالک",
    },
  });
  await drainWaiters();
  assert.equal(telegramCalls.filter(function (call) { return call.method === "sendMessage"; }).length, noMatchCount);

  const historyCountBeforeRetry = await env.MESSAGE_DB.prepare("SELECT COUNT(*) AS count FROM messages").first();
  assert.equal(Number(historyCountBeforeRetry.count), 7);
  const encryptedHistory = await env.MESSAGE_DB.prepare("SELECT payload_cipher FROM messages LIMIT 1").first();
  assert.doesNotMatch(encryptedHistory.payload_cipher, /همه چیز عادی|Monitoring|پیام خروجی مالک/);
  await webhook(readySecond, {
    update_id: 6,
    business_message: {
      message_id: 13,
      business_connection_id: "business-two",
      date: 1780000050,
      from: { id: 98765, first_name: "علی", last_name: "احمدی" },
      chat: { id: 98765, type: "private", first_name: "علی", last_name: "احمدی" },
      text: "همه چیز عادی است",
    },
  });
  const historyCountAfterRetry = await env.MESSAGE_DB.prepare("SELECT COUNT(*) AS count FROM messages").first();
  assert.equal(Number(historyCountAfterRetry.count), 7);

  const messagesPage = await worker.fetch(new Request("https://worker.example/admin?tab=messages", {
    headers: { cookie: cookie },
  }), env, ctx);
  const messagesHtml = await messagesPage.text();
  assert.match(messagesHtml, /پیام خروجی مالک/);
  assert.match(messagesHtml, /علی احمدی/);
  assert.doesNotMatch(messagesHtml, /Zari|پیام چت تعریف‌نشده/);
  assert.match(messagesHtml, /مانیتور سایت/);
  assert.match(messagesHtml, /class='bubble incoming'/);
  assert.match(messagesHtml, /class='bubble outgoing'/);
  assert.match(messagesHtml, /کنترل لاگ چت‌ها/);
  assert.match(messagesHtml, /غیرفعال‌کردن لاگ این سمت/);
  assert.match(messagesHtml, /دو سمت این گفتگو شناسایی شده/);
  assert.match(messagesHtml, /فیلتر و جستجو/);
  assert.match(messagesHtml, /name='page_size'/);
  assert.match(messagesHtml, /حذف یک یا چند پیام انتخاب‌شده/);
  assert.match(messagesHtml, /\.sidebar\{display:none\}/);
  assert.match(messagesHtml, /font-family:'Vazirmatn'/);
  assert.match(messagesHtml, /class='message-select' title='انتخاب برای حذف'/);
  assert.doesNotMatch(messagesHtml, /<span>انتخاب<\/span>/);
  assert.match(messagesPage.headers.get("content-security-policy"), /font-src 'self' https:\/\/cdn\.jsdelivr\.net/);

  const filteredPage = await worker.fetch(new Request(
    "https://worker.example/admin?tab=messages&q=%D8%B4%D8%A8%DA%A9%D9%87&sender=" + monitoredSender.id + "&page_size=20",
    { headers: { cookie: cookie } },
  ), env, ctx);
  const filteredHtml = await filteredPage.text();
  assert.doesNotMatch(filteredHtml, /خطای شبکه رخ داد/);
  assert.match(filteredHtml, /option value='20' selected/);

  const secondSource = await env.MESSAGE_DB.prepare(
    "SELECT source_key FROM chat_sources WHERE bot_id = ? AND chat_id = ?",
  ).bind(readySecond.id, "98765").first();
  assert.ok(secondSource);
  const rejectedToggle = await post("/admin/chat-log/toggle", cookie, csrf, {
    source_key: secondSource.source_key,
  });
  assert.equal(rejectedToggle.status, 400);
  const disableLog = await post("/admin/chat-log/toggle", cookie, csrf, {
    source_key: secondSource.source_key,
    confirm: "on",
  });
  assert.equal(disableLog.status, 303);
  const countBeforeDisabledMessage = Number((await env.MESSAGE_DB.prepare("SELECT COUNT(*) AS count FROM messages").first()).count);
  await webhook(readySecond, {
    update_id: 8,
    business_message: {
      message_id: 16,
      business_connection_id: "business-two",
      date: 1780000070,
      from: { id: 98765, first_name: "علی", last_name: "احمدی" },
      chat: { id: 98765, type: "private", first_name: "علی", last_name: "احمدی" },
      text: "خطای شبکه دوباره رخ داد",
    },
  });
  await drainWaiters();
  assert.equal(
    Number((await env.MESSAGE_DB.prepare("SELECT COUNT(*) AS count FROM messages").first()).count),
    countBeforeDisabledMessage,
  );
  assert.equal(telegramCalls.filter(function (call) {
    return call.method === "sendMessage" && call.token === "888:TWO";
  }).length, 2);
  assert.equal(env.CONFIG_STORE.writeCount, kvWritesBeforeMessages);
  assert.equal(env.CONFIG_STORE.deleteCount, kvDeletesBeforeMessages);

  const overviewAfterMessages = await worker.fetch(new Request("https://worker.example/admin", {
    headers: { cookie: cookie },
  }), env, ctx);
  const overviewAfterMessagesHtml = await overviewAfterMessages.text();
  assert.match(overviewAfterMessagesHtml, /آخرین پیام/);
  assert.match(overviewAfterMessagesHtml, /پیام خروجی مالک/);

  const oneMessage = await env.MESSAGE_DB.prepare("SELECT id FROM messages ORDER BY id ASC LIMIT 1").first();
  const deleteMessage = await post("/admin/message/delete", cookie, csrf, {
    message_ids: String(oneMessage.id),
    confirm_delete: "on",
    return_to: "/admin?tab=messages&page=1&page_size=20",
  });
  assert.equal(deleteMessage.status, 303);
  assert.match(deleteMessage.headers.get("location"), /notice=messages-deleted/);
  assert.equal(await env.MESSAGE_DB.prepare("SELECT id FROM messages WHERE id = ?").bind(oneMessage.id).first(), null);

  const forbidden = await webhook(readyFirst, {}, "wrong-secret");
  assert.equal(forbidden.status, 403);

  const health = await worker.fetch(new Request("https://worker.example/health"), env, ctx);
  assert.deepEqual(await health.json(), {
    ok: true, version: "4.3.0", runtimeStore: "d1", bots: 2, enabledBots: 2, senders: 4, rules: 3,
  });

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
