const STATE_KEY = "telegram-alert:state:v2";
const LEGACY_CONFIG_KEY = "telegram-alert:config:v1";
const STATUS_PREFIX = "telegram-alert:status:v2:";
const SESSION_SECONDS = 12 * 60 * 60;
const LOGIN_WINDOW_SECONDS = 10 * 60;
const MAX_LOGIN_ATTEMPTS = 5;

export default {
  async fetch(request, env, ctx) {
    try {
      assertBindings(env);
      const url = new URL(request.url);
      const webhookMatch = url.pathname.match(/^\/telegram-webhook\/([A-Za-z0-9_-]{4,80})$/);

      if (webhookMatch) return await handleTelegramWebhook(request, env, ctx, webhookMatch[1]);
      if (url.pathname === "/telegram-webhook") return await handleTelegramWebhook(request, env, ctx, "");

      if (url.pathname === "/login") {
        if (request.method === "GET") return html(loginPage());
        if (request.method === "POST") return await handleLogin(request, env);
        return methodNotAllowed();
      }

      if (url.pathname === "/" || url.pathname === "/admin") {
        if (!(await isAuthenticated(request, env))) return redirect("/login");
        if (request.method !== "GET") return methodNotAllowed();
        return await renderAdmin(request, env);
      }

      if (url.pathname === "/health") {
        const state = await loadState(env);
        return json({
          ok: true,
          bots: state.bots.length,
          enabledBots: state.bots.filter(function (bot) { return bot.enabled; }).length,
          rules: state.bots.reduce(function (count, bot) { return count + bot.rules.length; }, 0),
        });
      }

      const adminActions = {
        "/admin/bot/save": saveBot,
        "/admin/bot/test": testBot,
        "/admin/bot/disable": disableBot,
        "/admin/bot/delete": deleteBot,
        "/admin/rule/save": saveRule,
        "/admin/rule/delete": deleteRule,
      };
      if (adminActions[url.pathname] && request.method === "POST") {
        await requireAdmin(request, env);
        await requireCsrf(request, env);
        return await adminActions[url.pathname](request, env);
      }

      if (url.pathname === "/logout" && request.method === "POST") {
        await requireAdmin(request, env);
        await requireCsrf(request, env);
        return redirect("/login", expiredSessionCookie());
      }

      return new Response("Not found", { status: 404 });
    } catch (error) {
      console.error(error);
      const status = Number(error && error.status) || 500;
      if (status === 401) return redirect("/login");
      return html(messagePage("خطا", (error && error.message) || "خطای ناشناخته رخ داد."), status);
    }
  },
};

async function handleLogin(request, env) {
  requireLoginFormRequest(request);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const rateKey = "telegram-alert:login:" + ip;
  const attempts = Number((await env.CONFIG_STORE.get(rateKey)) || "0");
  if (attempts >= MAX_LOGIN_ATTEMPTS) {
    return html(loginPage("تلاش‌های ناموفق زیاد بود؛ ۱۰ دقیقه دیگر امتحان کن."), 429);
  }

  const form = await request.formData();
  const password = String(form.get("password") || "");
  if (!constantTimeEqual(password, env.ADMIN_PASSWORD)) {
    await env.CONFIG_STORE.put(rateKey, String(attempts + 1), { expirationTtl: LOGIN_WINDOW_SECONDS });
    return html(loginPage("رمز عبور نادرست است."), 401);
  }

  await env.CONFIG_STORE.delete(rateKey);
  return redirect("/admin", await createSessionCookie(sessionSecret(env)));
}

async function renderAdmin(request, env) {
  const state = await loadState(env);
  const statuses = {};
  await Promise.all(state.bots.map(async function (bot) {
    statuses[bot.id] = (await env.CONFIG_STORE.get(statusKey(bot.id), "json")) || {};
  }));
  const noticeCode = new URL(request.url).searchParams.get("notice") || "";
  const notices = {
    "bot-saved": "بات ذخیره شد و وب‌هوک آن فعال است.",
    "bot-tested": "پیام آزمایشی ارسال شد.",
    "bot-disabled": "وب‌هوک بات غیرفعال شد.",
    "bot-deleted": "بات و قوانین آن حذف شد.",
    "rule-saved": "قانون ذخیره شد.",
    "rule-deleted": "قانون حذف شد.",
  };
  const csrfToken = await csrfTokenForRequest(request, env);
  return html(adminPage(state, statuses, notices[noticeCode] || "", csrfToken));
}

async function saveBot(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const submittedId = String(form.get("bot_id") || "");
  const id = submittedId ? requireSafeId(submittedId, "شناسه بات") : "bot_" + randomToken(9);
  const existingIndex = state.bots.findIndex(function (bot) { return bot.id === id; });
  const existing = existingIndex >= 0 ? state.bots[existingIndex] : null;
  const label = String(form.get("label") || "").trim();
  const enteredToken = String(form.get("bot_token") || "").trim();
  const enabled = form.get("enabled") === "on";

  if (!label || label.length > 80) throw badRequest("نام نمایشی بات باید بین ۱ تا ۸۰ نویسه باشد.");

  let token = enteredToken;
  if (!token && existing && existing.tokenCipher) {
    token = await decryptSecret(existing.tokenCipher, encryptionSecret(env));
  }
  if (!token) throw badRequest("توکن بات را وارد کن.");

  const telegramBot = await telegramApi(token, "getMe", {});
  if (!telegramBot || !telegramBot.id || !telegramBot.username) {
    throw badRequest("پاسخ getMe تلگرام معتبر نبود.");
  }

  if (enteredToken && existing && existing.tokenCipher) {
    const oldToken = await decryptSecret(existing.tokenCipher, encryptionSecret(env));
    if (oldToken !== token) {
      await telegramApi(oldToken, "deleteWebhook", { drop_pending_updates: false }).catch(function (error) {
        console.warn("Could not detach old bot webhook", error);
      });
    }
  }

  const sameTelegramBot = existing && existing.telegramBotId === String(telegramBot.id);
  const webhookSecret = (sameTelegramBot && existing.webhookSecret) || randomToken(40);
  const webhookUrl = new URL(request.url).origin + "/telegram-webhook/" + id;
  await telegramApi(token, "setWebhook", {
    url: webhookUrl,
    secret_token: webhookSecret,
    allowed_updates: ["business_connection", "business_message", "message"],
    drop_pending_updates: false,
  });

  const bot = {
    id: id,
    label: label,
    tokenCipher: enteredToken
      ? await encryptSecret(token, encryptionSecret(env))
      : existing.tokenCipher,
    telegramBotId: String(telegramBot.id),
    botUsername: telegramBot.username,
    enabled: enabled,
    webhookSecret: webhookSecret,
    webhookUrl: webhookUrl,
    ownerChatId: sameTelegramBot ? (existing.ownerChatId || "") : "",
    businessConnectionId: sameTelegramBot ? (existing.businessConnectionId || "") : "",
    connectionEnabled: sameTelegramBot ? existing.connectionEnabled !== false : false,
    rules: existing ? existing.rules : [],
    updatedAt: new Date().toISOString(),
  };

  if (existingIndex >= 0) state.bots[existingIndex] = bot;
  else state.bots.push(bot);
  await saveState(env, state);
  await saveStatus(env, id, {
    webhook: "active",
    lastAction: "بات ذخیره و وب‌هوک فعال شد",
    lastActionAt: new Date().toISOString(),
  });
  return redirect("/admin?notice=bot-saved");
}

async function testBot(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const bot = requireBot(state, form.get("bot_id"));
  if (!bot.ownerChatId) {
    throw badRequest("هنوز حساب مالک برای این بات ثبت نشده است. بات را در Chat Automation متصل کن.");
  }
  const token = await decryptSecret(bot.tokenCipher, encryptionSecret(env));
  await telegramApi(token, "sendMessage", {
    chat_id: bot.ownerChatId,
    text: "🧪 پیام آزمایشی از " + bot.label,
    disable_notification: false,
  });
  await saveStatus(env, bot.id, {
    lastAction: "پیام آزمایشی ارسال شد",
    lastActionAt: new Date().toISOString(),
  });
  return redirect("/admin?notice=bot-tested");
}

async function disableBot(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const bot = requireBot(state, form.get("bot_id"));
  const token = await decryptSecret(bot.tokenCipher, encryptionSecret(env));
  await telegramApi(token, "deleteWebhook", { drop_pending_updates: false });
  bot.enabled = false;
  bot.updatedAt = new Date().toISOString();
  await saveState(env, state);
  await saveStatus(env, bot.id, {
    webhook: "disabled",
    lastAction: "وب‌هوک بات غیرفعال شد",
    lastActionAt: new Date().toISOString(),
  });
  return redirect("/admin?notice=bot-disabled");
}

async function deleteBot(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const bot = requireBot(state, form.get("bot_id"));
  const token = await decryptSecret(bot.tokenCipher, encryptionSecret(env));
  await telegramApi(token, "deleteWebhook", { drop_pending_updates: false });
  state.bots = state.bots.filter(function (item) { return item.id !== bot.id; });
  await saveState(env, state);
  await env.CONFIG_STORE.delete(statusKey(bot.id));
  return redirect("/admin?notice=bot-deleted");
}

async function saveRule(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const bot = requireBot(state, form.get("bot_id"));
  const submittedRuleId = String(form.get("rule_id") || "");
  const ruleId = submittedRuleId ? requireSafeId(submittedRuleId, "شناسه قانون") : "rule_" + randomToken(9);
  const keyword = String(form.get("keyword") || "").trim();
  const alertMessage = String(form.get("alert_message") || "").trim();
  const cooldownSeconds = clampInteger(form.get("cooldown_seconds"), 0, 86400, 300);
  const enabled = form.get("enabled") === "on";

  if (!keyword || keyword.length > 200) throw badRequest("عبارت تریگر باید بین ۱ تا ۲۰۰ نویسه باشد.");
  if (!alertMessage || alertMessage.length > 4096) {
    throw badRequest("متن پیام هشدار باید بین ۱ تا ۴۰۹۶ نویسه باشد.");
  }

  const rule = {
    id: ruleId,
    keyword: keyword,
    alertMessage: alertMessage,
    cooldownSeconds: cooldownSeconds,
    enabled: enabled,
    updatedAt: new Date().toISOString(),
  };
  const ruleIndex = bot.rules.findIndex(function (item) { return item.id === ruleId; });
  if (ruleIndex >= 0) bot.rules[ruleIndex] = rule;
  else bot.rules.push(rule);
  bot.updatedAt = new Date().toISOString();
  await saveState(env, state);
  return redirect("/admin?notice=rule-saved");
}

async function deleteRule(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const bot = requireBot(state, form.get("bot_id"));
  const ruleId = requireSafeId(String(form.get("rule_id") || ""), "شناسه قانون");
  if (!bot.rules.some(function (rule) { return rule.id === ruleId; })) {
    throw badRequest("قانون پیدا نشد.");
  }
  bot.rules = bot.rules.filter(function (rule) { return rule.id !== ruleId; });
  bot.updatedAt = new Date().toISOString();
  await saveState(env, state);
  await env.CONFIG_STORE.delete(cooldownKey(bot.id, ruleId));
  return redirect("/admin?notice=rule-deleted");
}

async function handleTelegramWebhook(request, env, ctx, requestedBotId) {
  if (request.method !== "POST") return methodNotAllowed();
  const state = await loadState(env);
  const suppliedSecret = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
  let bot = requestedBotId
    ? state.bots.find(function (item) { return item.id === requestedBotId; })
    : state.bots.find(function (item) { return constantTimeEqual(suppliedSecret, item.webhookSecret || ""); });

  if (!bot || !bot.tokenCipher || !bot.webhookSecret) return new Response("Not configured", { status: 503 });
  if (!constantTimeEqual(suppliedSecret, bot.webhookSecret)) return new Response("Forbidden", { status: 403 });

  let update;
  try {
    update = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  if (update.business_connection) {
    const connection = update.business_connection;
    bot.ownerChatId = String(connection.user_chat_id || (connection.user && connection.user.id) || "");
    bot.businessConnectionId = String(connection.id || "");
    bot.connectionEnabled = Boolean(connection.is_enabled);
    bot.updatedAt = new Date().toISOString();
    await saveState(env, state);
    await saveStatus(env, bot.id, {
      connection: connection.is_enabled ? "connected" : "disconnected",
      ownerChatId: bot.ownerChatId,
      lastAction: connection.is_enabled ? "حساب تلگرام متصل شد" : "اتصال حساب تلگرام قطع شد",
      lastActionAt: new Date().toISOString(),
    });
    return new Response("OK");
  }

  if (update.message && update.message.chat && update.message.chat.type === "private"
      && String(update.message.text || "").startsWith("/start")) {
    const senderId = String((update.message.from && update.message.from.id) || "");
    const token = await decryptSecret(bot.tokenCipher, encryptionSecret(env));
    const isOwner = Boolean(bot.ownerChatId) && senderId === bot.ownerChatId;
    ctx.waitUntil(telegramApi(token, "sendMessage", {
      chat_id: String(update.message.chat.id),
      text: isOwner
        ? "✅ بات اعلان آماده است."
        : "برای فعال‌شدن اعلان، مالک حساب باید این بات را از Settings → Chat Automation متصل کند.",
    }));
    return new Response("OK");
  }

  const message = update.business_message;
  if (!message || !bot.enabled) return new Response("OK");
  const senderId = String((message.from && message.from.id) || "");
  const incomingText = String(message.text || message.caption || "");
  const normalizedIncoming = normalizeText(incomingText);
  const matchedRules = bot.rules.filter(function (rule) {
    return rule.enabled && normalizedIncoming.includes(normalizeText(rule.keyword));
  });

  if (!matchedRules.length) {
    await saveStatus(env, bot.id, {
      lastSenderId: senderId,
      lastAction: "پیام دریافت شد؛ هیچ تریگری منطبق نبود",
      lastActionAt: new Date().toISOString(),
    });
    return new Response("OK");
  }

  if (!bot.ownerChatId) {
    await saveStatus(env, bot.id, {
      lastSenderId: senderId,
      lastAction: "تریگر منطبق شد، اما شناسه مالک هنوز ثبت نشده بود",
      lastActionAt: new Date().toISOString(),
    });
    return new Response("OK");
  }

  const readyRules = [];
  for (const rule of matchedRules) {
    const key = cooldownKey(bot.id, rule.id);
    if (rule.cooldownSeconds > 0 && (await env.CONFIG_STORE.get(key))) continue;
    if (rule.cooldownSeconds > 0) {
      await env.CONFIG_STORE.put(key, "1", { expirationTtl: Math.max(60, rule.cooldownSeconds) });
    }
    readyRules.push(rule);
  }
  if (!readyRules.length) {
    await saveStatus(env, bot.id, {
      lastSenderId: senderId,
      lastAction: "تریگر منطبق شد، اما در فاصله جلوگیری از تکرار بود",
      lastActionAt: new Date().toISOString(),
    });
    return new Response("OK");
  }

  const token = await decryptSecret(bot.tokenCipher, encryptionSecret(env));
  const alertPromise = Promise.allSettled(readyRules.map(async function (rule) {
    try {
      await telegramApiWithRetry(token, "sendMessage", {
        chat_id: bot.ownerChatId,
        text: rule.alertMessage,
        disable_notification: false,
      });
      return rule.id;
    } catch (error) {
      if (rule.cooldownSeconds > 0) await env.CONFIG_STORE.delete(cooldownKey(bot.id, rule.id));
      throw error;
    }
  })).then(async function (results) {
    const successCount = results.filter(function (result) { return result.status === "fulfilled"; }).length;
    const failureCount = results.length - successCount;
    await saveStatus(env, bot.id, {
      lastSenderId: senderId,
      lastMatchedRules: readyRules.length,
      lastAction: failureCount
        ? successCount + " هشدار ارسال شد و " + failureCount + " هشدار شکست خورد"
        : successCount + " هشدار ارسال شد",
      lastActionAt: new Date().toISOString(),
    });
    const rejected = results.find(function (result) { return result.status === "rejected"; });
    if (rejected) throw rejected.reason;
  });
  ctx.waitUntil(alertPromise);
  return new Response("OK");
}

async function loadState(env) {
  const stored = await env.CONFIG_STORE.get(STATE_KEY, "json");
  if (stored && Array.isArray(stored.bots)) return normalizeState(stored);

  const old = await env.CONFIG_STORE.get(LEGACY_CONFIG_KEY, "json");
  const state = { version: 2, bots: [], updatedAt: new Date().toISOString() };
  if (old && old.tokenCipher) {
    state.bots.push({
      id: "legacy_" + String(old.botId || "bot").replace(/[^A-Za-z0-9_-]/g, ""),
      label: old.botUsername ? "@" + old.botUsername : "بات قبلی",
      tokenCipher: old.tokenCipher,
      telegramBotId: String(old.botId || ""),
      botUsername: String(old.botUsername || ""),
      enabled: old.enabled !== false,
      webhookSecret: String(old.webhookSecret || ""),
      webhookUrl: String(old.webhookUrl || ""),
      ownerChatId: String(old.ownerChatId || ""),
      businessConnectionId: String(old.businessConnectionId || ""),
      connectionEnabled: old.connectionEnabled !== false,
      rules: [],
      updatedAt: new Date().toISOString(),
    });
  }
  await saveState(env, state);
  return state;
}

function normalizeState(state) {
  return {
    version: 2,
    updatedAt: state.updatedAt || "",
    bots: state.bots.map(function (bot) {
      return {
        id: String(bot.id),
        label: String(bot.label || bot.botUsername || "بات"),
        tokenCipher: String(bot.tokenCipher || ""),
        telegramBotId: String(bot.telegramBotId || ""),
        botUsername: String(bot.botUsername || ""),
        enabled: bot.enabled !== false,
        webhookSecret: String(bot.webhookSecret || ""),
        webhookUrl: String(bot.webhookUrl || ""),
        ownerChatId: String(bot.ownerChatId || ""),
        businessConnectionId: String(bot.businessConnectionId || ""),
        connectionEnabled: bot.connectionEnabled !== false,
        rules: Array.isArray(bot.rules) ? bot.rules.map(function (rule) {
          return {
            id: String(rule.id),
            keyword: String(rule.keyword || ""),
            alertMessage: String(rule.alertMessage || ""),
            cooldownSeconds: clampInteger(rule.cooldownSeconds, 0, 86400, 300),
            enabled: rule.enabled !== false,
            updatedAt: rule.updatedAt || "",
          };
        }) : [],
        updatedAt: bot.updatedAt || "",
      };
    }),
  };
}

async function saveState(env, state) {
  state.version = 2;
  state.updatedAt = new Date().toISOString();
  await env.CONFIG_STORE.put(STATE_KEY, JSON.stringify(state));
}

async function saveStatus(env, botId, patch) {
  const key = statusKey(botId);
  const current = (await env.CONFIG_STORE.get(key, "json")) || {};
  await env.CONFIG_STORE.put(key, JSON.stringify(Object.assign({}, current, patch)));
}

function requireBot(state, value) {
  const id = requireSafeId(String(value || ""), "شناسه بات");
  const bot = state.bots.find(function (item) { return item.id === id; });
  if (!bot) throw badRequest("بات پیدا نشد.");
  return bot;
}

function requireSafeId(value, label) {
  if (!/^[A-Za-z0-9_-]{4,80}$/.test(value)) throw badRequest(label + " نامعتبر است.");
  return value;
}

function statusKey(botId) {
  return STATUS_PREFIX + botId;
}

function cooldownKey(botId, ruleId) {
  return "telegram-alert:cooldown:v2:" + botId + ":" + ruleId;
}

function normalizeText(value) {
  return String(value || "")
    .normalize("NFKC")
    .replaceAll("ي", "ی")
    .replaceAll("ك", "ک")
    .replace(/\s+/g, " ")
    .trim()
    .toLocaleLowerCase("fa");
}

async function telegramApi(token, method, payload) {
  const response = await fetch("https://api.telegram.org/bot" + token + "/" + method, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(function () { return null; });
  if (!response.ok || !result || !result.ok) {
    const description = (result && result.description) || ("HTTP " + response.status);
    throw badRequest("خطای تلگرام در " + method + ": " + description);
  }
  return result.result;
}

async function telegramApiWithRetry(token, method, payload, attempts) {
  const totalAttempts = attempts || 3;
  let lastError;
  for (let attempt = 0; attempt < totalAttempts; attempt++) {
    try {
      return await telegramApi(token, method, payload);
    } catch (error) {
      lastError = error;
      if (attempt < totalAttempts - 1) {
        await new Promise(function (resolve) { setTimeout(resolve, 300 * (2 ** attempt)); });
      }
    }
  }
  throw lastError;
}

function assertBindings(env) {
  const missing = [];
  if (!env.CONFIG_STORE) missing.push("CONFIG_STORE (KV binding)");
  if (!env.ADMIN_PASSWORD) missing.push("ADMIN_PASSWORD");
  if (missing.length) throw new Error("تنظیمات Cloudflare ناقص است: " + missing.join(", "));
}

function sessionSecret(env) {
  return env.SESSION_SECRET || ("telegram-alert:session:" + env.ADMIN_PASSWORD);
}

function encryptionSecret(env) {
  return env.CONFIG_ENCRYPTION_KEY || ("telegram-alert:encryption:" + env.ADMIN_PASSWORD);
}

async function requireAdmin(request, env) {
  if (!(await isAuthenticated(request, env))) {
    const error = new Error("Unauthorized");
    error.status = 401;
    throw error;
  }
}

async function isAuthenticated(request, env) {
  const token = parseCookies(request.headers.get("cookie") || "").ta_session;
  if (!token) return false;
  const parts = token.split(".");
  const expiryText = parts[0];
  const signature = parts[1];
  const expiry = Number(expiryText);
  if (!expiry || expiry < Math.floor(Date.now() / 1000) || !signature) return false;
  return constantTimeEqual(signature, await hmacSign(expiryText, sessionSecret(env)));
}

async function createSessionCookie(secret) {
  const expiry = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const signature = await hmacSign(String(expiry), secret);
  return "ta_session=" + expiry + "." + signature
    + "; Max-Age=" + SESSION_SECONDS + "; Path=/; HttpOnly; Secure; SameSite=Strict";
}

function expiredSessionCookie() {
  return "ta_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict";
}

async function hmacSign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(signature));
}

async function encryptionKey(secret) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptSecret(value, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey(secret);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, new TextEncoder().encode(value));
  const combined = new Uint8Array(iv.length + cipher.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipher), iv.length);
  return bytesToBase64Url(combined);
}

async function decryptSecret(value, secret) {
  try {
    const bytes = base64UrlToBytes(value);
    const iv = bytes.slice(0, 12);
    const cipher = bytes.slice(12);
    const key = await encryptionKey(secret);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, cipher);
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error("رمزگشایی توکن شکست خورد؛ کلید رمزنگاری یا رمز مدیر تغییر کرده است.");
  }
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function base64UrlToBytes(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, function (char) { return char.charCodeAt(0); });
}

function randomToken(bytes) {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(bytes || 32)));
}

function constantTimeEqual(a, b) {
  const aa = new TextEncoder().encode(String(a));
  const bb = new TextEncoder().encode(String(b));
  let diff = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);
  for (let i = 0; i < length; i++) {
    diff |= (aa[i % (aa.length || 1)] || 0) ^ (bb[i % (bb.length || 1)] || 0);
  }
  return diff === 0;
}

function parseCookies(header) {
  const result = {};
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index > 0) result[part.slice(0, index).trim()] = part.slice(index + 1).trim();
  }
  return result;
}

function requireLoginFormRequest(request) {
  const expectedOrigin = new URL(request.url).origin;
  const origin = request.headers.get("origin");
  if (origin && origin !== "null" && origin !== expectedOrigin) throw invalidRequest();
  const referer = request.headers.get("referer");
  if (referer) {
    try {
      if (new URL(referer).origin !== expectedOrigin) throw invalidRequest();
    } catch (error) {
      if (error && error.status === 403) throw error;
      throw invalidRequest();
    }
  }
  if (request.headers.get("sec-fetch-site") === "cross-site") throw invalidRequest();
}

async function csrfTokenForRequest(request, env) {
  const session = parseCookies(request.headers.get("cookie") || "").ta_session;
  if (!session) throw invalidRequest();
  return hmacSign("csrf:" + session, sessionSecret(env));
}

async function requireCsrf(request, env) {
  const form = await request.clone().formData();
  const supplied = String(form.get("_csrf") || "");
  const expected = await csrfTokenForRequest(request, env);
  if (!supplied || !constantTimeEqual(supplied, expected)) throw invalidRequest();
}

function invalidRequest() {
  const error = new Error("درخواست نامعتبر است؛ صفحه را دوباره باز کن.");
  error.status = 403;
  return error;
}

function clampInteger(value, min, max, fallback) {
  const number = Number.parseInt(String(value == null ? "" : value), 10);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, number));
}

function badRequest(message) {
  const error = new Error(message);
  error.status = 400;
  return error;
}

function methodNotAllowed() {
  return new Response("Method not allowed", { status: 405 });
}

function redirect(location, cookie) {
  const headers = { location: location };
  if (cookie) headers["set-cookie"] = cookie;
  return new Response(null, { status: 303, headers: headers });
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function html(body, status) {
  return new Response(body, {
    status: status || 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  });
}

function layout(title, content) {
  const css = [
    ":root{color-scheme:dark;--bg:#07111f;--card:#101d30;--line:#243853;--text:#eef6ff;--muted:#9db0c9;--accent:#3aa0ff;--good:#2dd4a8;--bad:#ff647c}",
    "*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#102744 0,var(--bg) 48%);font-family:Tahoma,Arial,sans-serif;color:var(--text);min-height:100vh}",
    ".wrap{width:min(900px,calc(100% - 24px));margin:28px auto}.brand{display:flex;align-items:center;gap:12px;margin-bottom:18px}.logo{display:grid;place-items:center;width:50px;height:50px;border-radius:15px;background:linear-gradient(135deg,#2495ff,#2dd4a8);font-size:25px}",
    "h1{font-size:22px;margin:0}h2{font-size:19px;margin:0 0 16px}h3{font-size:16px;margin:0}.brand p{margin:5px 0 0;color:var(--muted);font-size:13px}",
    ".card{background:color-mix(in srgb,var(--card) 94%,transparent);border:1px solid var(--line);border-radius:20px;padding:20px;box-shadow:0 20px 50px #0005;margin-bottom:16px}.bot{border-color:#315477}",
    ".bothead{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:15px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.full{grid-column:1/-1}",
    "label{display:block;color:#c8d8eb;font-size:13px;margin:0 0 7px}input,textarea{width:100%;border:1px solid var(--line);background:#081525;color:var(--text);border-radius:12px;padding:12px 13px;font:inherit;outline:none}input:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px #3aa0ff22}textarea{min-height:86px;resize:vertical}",
    ".hint{color:var(--muted);font-size:12px;line-height:1.8;margin:6px 0 0}.check{display:flex;gap:9px;align-items:center}.check input{width:auto;accent-color:var(--accent)}button{border:0;border-radius:12px;padding:11px 15px;background:var(--accent);color:white;font:inherit;font-weight:bold;cursor:pointer}.secondary{background:#213752}.danger{background:#6b2533}",
    ".actions{display:flex;gap:9px;flex-wrap:wrap;margin-top:15px}.actions form{margin:0}.status{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}.stat{background:#091626;border:1px solid var(--line);padding:11px;border-radius:12px}.stat b{display:block;margin-top:5px;font-size:13px;word-break:break-word}.muted{color:var(--muted)}",
    ".notice{padding:13px 15px;border-radius:12px;margin-bottom:16px;background:#123b33;border:1px solid #1b6a58}.pill{display:inline-flex;padding:4px 9px;border-radius:999px;background:#174438;color:#8ef0d2;font-size:12px}.pill.off{background:#46232e;color:#ffb1bf}.divider{height:1px;background:var(--line);margin:18px 0}.rule{background:#0a1728;border:1px solid var(--line);border-radius:15px;padding:14px;margin-top:12px}",
    ".login{width:min(430px,calc(100% - 28px));margin:14vh auto}.login button{width:100%;margin-top:14px}.foot{color:var(--muted);text-align:center;font-size:11px;margin-top:16px}.empty{padding:15px;border:1px dashed var(--line);border-radius:12px;color:var(--muted)}",
    "@media(max-width:700px){.grid,.status{grid-template-columns:1fr}.full{grid-column:auto}.wrap{margin-top:16px}.card{padding:16px}.bothead{display:block}.bothead .pill{margin-top:8px}.actions button{width:100%}.actions form{flex:1 1 100%}}",
  ].join("");
  return "<!doctype html><html lang='fa' dir='rtl'><head><meta charset='utf-8'>"
    + "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    + "<title>" + escapeHtml(title) + "</title><style>" + css + "</style></head><body>"
    + content + "</body></html>";
}

function loginPage(error) {
  return layout("ورود به پنل هشدار",
    "<main class='login'><div class='brand'><div class='logo'>🔔</div><div><h1>پنل هشدار تلگرام</h1>"
    + "<p>ورود امن مدیر</p></div></div>"
    + (error ? "<div class='notice'>" + escapeHtml(error) + "</div>" : "")
    + "<section class='card'><form method='post' action='/login'><label for='password'>رمز مدیریت</label>"
    + "<input id='password' name='password' type='password' autocomplete='current-password' required autofocus>"
    + "<button type='submit'>ورود</button></form></section>"
    + "<p class='foot'>توکن بات‌ها به‌صورت رمزنگاری‌شده نگهداری می‌شود.</p></main>");
}

function adminPage(state, statuses, notice, csrfToken) {
  const csrf = csrfInput(csrfToken);
  const bots = state.bots.map(function (bot) {
    return botCard(bot, statuses[bot.id] || {}, csrf);
  }).join("");
  const content = "<main class='wrap'><div class='brand'><div class='logo'>🔔</div><div>"
    + "<h1>پنل چندبات هشدار تلگرام</h1><p>برای هر بات چند تریگر عبارتی و پیام مستقل تعریف کن.</p></div></div>"
    + (notice ? "<div class='notice'>" + escapeHtml(notice) + "</div>" : "")
    + "<section class='card'><h2>افزودن بات جدید</h2>"
    + botForm(null, csrf)
    + "</section>"
    + (bots || "<section class='card empty'>هنوز باتی اضافه نشده است.</section>")
    + "<section class='card'><h2>راهنمای سریع</h2><ol class='hint'>"
    + "<li>بات را با توکن BotFather اضافه کن.</li><li>Secretary Mode را برای همان بات فعال کن.</li>"
    + "<li>بات را در Telegram → Settings → Chat Automation متصل کن.</li>"
    + "<li>برای بات یک یا چند عبارت تریگر و پیام هشدار بساز.</li>"
    + "<li>بات فقط متن و کپشن پیام‌ها را بررسی می‌کند و متن دریافتی را ذخیره نمی‌کند.</li></ol>"
    + "<form method='post' action='/logout'>" + csrf + "<button class='secondary' type='submit'>خروج</button></form></section></main>";
  return layout("پنل چندبات هشدار تلگرام", content);
}

function botCard(bot, status, csrf) {
  const connected = Boolean(bot.ownerChatId && bot.connectionEnabled !== false);
  const rules = bot.rules.map(function (rule) { return ruleEditor(bot, rule, csrf); }).join("");
  return "<section class='card bot'><div class='bothead'><div><h2>" + escapeHtml(bot.label) + "</h2>"
    + "<div class='hint'>@" + escapeHtml(bot.botUsername || "نامشخص") + "</div></div>"
    + "<span class='pill" + (bot.enabled ? "" : " off") + "'>" + (bot.enabled ? "فعال" : "غیرفعال") + "</span></div>"
    + "<div class='status'>"
    + stat("Chat Automation", connected ? "<span class='pill'>متصل</span>" : "<span class='pill off'>منتظر اتصال</span>", true)
    + stat("شناسه مالک", escapeHtml(bot.ownerChatId || "ثبت نشده"), true)
    + stat("آخرین فرستنده", escapeHtml(status.lastSenderId || "هنوز پیامی نرسیده"), true)
    + stat("آخرین رویداد", escapeHtml(status.lastAction || "ثبت نشده"), true)
    + "</div><div class='divider'></div><h3>تنظیمات بات</h3>"
    + botForm(bot, csrf)
    + "<div class='divider'></div><h3>قوانین عبارتی</h3>"
    + (rules || "<div class='empty'>هنوز قانونی برای این بات تعریف نشده است.</div>")
    + "<div class='rule'><h3>افزودن قانون جدید</h3>" + ruleEditor(bot, null, csrf) + "</div>"
    + "<div class='divider'></div><div class='actions'>"
    + actionForm("/admin/bot/test", bot.id, csrf, "پیام آزمایشی", "secondary")
    + actionForm("/admin/bot/disable", bot.id, csrf, "غیرفعال‌کردن وب‌هوک", "danger")
    + actionForm("/admin/bot/delete", bot.id, csrf, "حذف کامل بات", "danger")
    + "</div></section>";
}

function botForm(bot, csrf) {
  const existing = Boolean(bot);
  return "<form method='post' action='/admin/bot/save'>" + csrf
    + (existing ? hidden("bot_id", bot.id) : "")
    + "<div class='grid'><div><label>نام نمایشی</label><input name='label' maxlength='80' required value='"
    + escapeHtml(existing ? bot.label : "") + "' placeholder='مثلاً هشدار سایت'></div>"
    + "<div><label>توکن بات</label><input name='bot_token' type='password' autocomplete='off' "
    + (existing ? "" : "required ") + "placeholder='" + (existing ? "برای حفظ توکن فعلی خالی بگذار" : "123456:ABC...") + "'></div>"
    + "<div class='full check'><input id='enabled_" + escapeHtml(existing ? bot.id : "new")
    + "' name='enabled' type='checkbox' " + (!existing || bot.enabled ? "checked" : "") + ">"
    + "<label for='enabled_" + escapeHtml(existing ? bot.id : "new") + "'>بات فعال باشد</label></div></div>"
    + "<div class='actions'><button type='submit'>" + (existing ? "ذخیره بات و وب‌هوک" : "افزودن بات") + "</button></div></form>";
}

function ruleEditor(bot, rule, csrf) {
  const existing = Boolean(rule);
  const idSuffix = existing ? rule.id : "new_" + bot.id;
  const form = "<form method='post' action='/admin/rule/save'>" + csrf + hidden("bot_id", bot.id)
    + (existing ? hidden("rule_id", rule.id) : "")
    + "<div class='grid'><div><label>عبارت تریگر</label><input name='keyword' maxlength='200' required value='"
    + escapeHtml(existing ? rule.keyword : "") + "' placeholder='مثلاً سایت قطع شد'></div>"
    + "<div><label>فاصله تکرار (ثانیه)</label><input name='cooldown_seconds' type='number' min='0' max='86400' value='"
    + escapeHtml(String(existing ? rule.cooldownSeconds : 300)) + "'></div>"
    + "<div class='full'><label>پیام هشدار</label><textarea name='alert_message' maxlength='4096' required>"
    + escapeHtml(existing ? rule.alertMessage : "سایت قطع شد") + "</textarea></div>"
    + "<div class='full check'><input id='rule_enabled_" + escapeHtml(idSuffix) + "' name='enabled' type='checkbox' "
    + (!existing || rule.enabled ? "checked" : "") + "><label for='rule_enabled_" + escapeHtml(idSuffix)
    + "'>این قانون فعال باشد</label></div></div><div class='actions'><button type='submit'>"
    + (existing ? "ذخیره قانون" : "افزودن قانون") + "</button></div></form>";
  if (!existing) return form;
  return "<div class='rule'>" + form
    + "<form method='post' action='/admin/rule/delete' class='actions'>" + csrf
    + hidden("bot_id", bot.id) + hidden("rule_id", rule.id)
    + "<button class='danger' type='submit'>حذف قانون</button></form></div>";
}

function actionForm(action, botId, csrf, label, className) {
  return "<form method='post' action='" + action + "'>" + csrf + hidden("bot_id", botId)
    + "<button class='" + className + "' type='submit'>" + label + "</button></form>";
}

function stat(label, value, raw) {
  return "<div class='stat'><span class='muted'>" + escapeHtml(label) + "</span><b>"
    + (raw ? value : escapeHtml(value)) + "</b></div>";
}

function csrfInput(value) {
  return hidden("_csrf", value);
}

function hidden(name, value) {
  return "<input type='hidden' name='" + escapeHtml(name) + "' value='" + escapeHtml(value) + "'>";
}

function messagePage(title, message) {
  return layout(title, "<main class='login'><div class='brand'><div class='logo'>⚠️</div><div><h1>"
    + escapeHtml(title) + "</h1></div></div><section class='card'><p>" + escapeHtml(message)
    + "</p><a href='/admin' style='color:#67b8ff'>بازگشت به پنل</a></section></main>");
}

function escapeHtml(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, function (char) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char];
  });
}
