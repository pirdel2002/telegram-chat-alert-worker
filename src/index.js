const CONFIG_KEY = "telegram-alert:config:v1";
const STATUS_KEY = "telegram-alert:status:v1";
const SESSION_SECONDS = 12 * 60 * 60;
const LOGIN_WINDOW_SECONDS = 10 * 60;
const MAX_LOGIN_ATTEMPTS = 5;

export default {
  async fetch(request, env, ctx) {
    try {
      assertBindings(env);
      const url = new URL(request.url);

      if (url.pathname === "/telegram-webhook") {
        return await handleTelegramWebhook(request, env, ctx);
      }

      if (url.pathname === "/login") {
        if (request.method === "GET") return html(loginPage());
        if (request.method === "POST") return await handleLogin(request, env);
        return methodNotAllowed();
      }

      if (url.pathname === "/logout" && request.method === "POST") {
        requireSameOrigin(request);
        return redirect("/login", expiredSessionCookie());
      }

      if (url.pathname === "/" || url.pathname === "/admin") {
        if (!(await isAuthenticated(request, env))) return redirect("/login");
        if (request.method !== "GET") return methodNotAllowed();
        return await renderAdmin(request, env);
      }

      if (url.pathname === "/admin/save" && request.method === "POST") {
        await requireAdmin(request, env);
        requireSameOrigin(request);
        return await saveSettings(request, env);
      }

      if (url.pathname === "/admin/test" && request.method === "POST") {
        await requireAdmin(request, env);
        requireSameOrigin(request);
        return await sendTestAlert(request, env);
      }

      if (url.pathname === "/admin/disable" && request.method === "POST") {
        await requireAdmin(request, env);
        requireSameOrigin(request);
        return await disableWebhook(request, env);
      }

      if (url.pathname === "/health") {
        const config = await loadConfig(env);
        return json({ ok: true, configured: Boolean(config?.tokenCipher), enabled: Boolean(config?.enabled) });
      }

      return new Response("Not found", { status: 404 });
    } catch (error) {
      console.error(error);
      const status = Number(error?.status) || 500;
      if (status === 401) return redirect("/login");
      return html(messagePage("خطا", error?.message || "خطای ناشناخته رخ داد."), status);
    }
  },
};

async function handleLogin(request, env) {
  requireSameOrigin(request);
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const rateKey = `telegram-alert:login:${ip}`;
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
  const cookie = await createSessionCookie(sessionSecret(env));
  return redirect("/admin", cookie);
}

async function renderAdmin(request, env, notice = "", isError = false) {
  const config = (await loadConfig(env)) || defaultConfig();
  const status = (await env.CONFIG_STORE.get(STATUS_KEY, "json")) || {};
  const noticeCode = new URL(request.url).searchParams.get("notice");
  const notices = {
    saved: "تنظیمات ذخیره شد و وب‌هوک تلگرام فعال است.",
    "test-sent": "پیام آزمایشی ارسال شد.",
    disabled: "وب‌هوک و ارسال هشدار غیرفعال شد.",
  };
  return html(adminPage(config, status, notice || notices[noticeCode] || "", isError));
}

async function saveSettings(request, env) {
  const form = await request.formData();
  const oldConfig = (await loadConfig(env)) || defaultConfig();
  const enteredToken = String(form.get("bot_token") || "").trim();
  const watchedSenderId = normalizeId(form.get("watched_sender_id"), "شناسه فرستنده");
  const alertMessage = String(form.get("alert_message") || "").trim();
  const cooldownSeconds = clampInteger(form.get("cooldown_seconds"), 0, 86400, 300);
  const enabled = form.get("enabled") === "on";

  if (!alertMessage || alertMessage.length > 4096) {
    throw badRequest("متن هشدار باید بین ۱ تا ۴۰۹۶ نویسه باشد.");
  }

  let token = enteredToken;
  if (!token && oldConfig.tokenCipher) token = await decryptSecret(oldConfig.tokenCipher, encryptionSecret(env));
  if (!token) throw badRequest("توکن ربات را وارد کن.");

  const bot = await telegramApi(token, "getMe", {});
  if (!bot?.id || !bot?.username) throw badRequest("پاسخ getMe تلگرام معتبر نبود.");

  if (enteredToken && oldConfig.tokenCipher) {
    try {
      const oldToken = await decryptSecret(oldConfig.tokenCipher, encryptionSecret(env));
      if (oldToken !== token) await telegramApi(oldToken, "deleteWebhook", { drop_pending_updates: false });
    } catch (error) {
      console.warn("Could not detach old bot webhook", error);
    }
  }

  const webhookSecret = oldConfig.webhookSecret || randomToken(40);
  const origin = new URL(request.url).origin;
  const webhookUrl = `${origin}/telegram-webhook`;
  await telegramApi(token, "setWebhook", {
    url: webhookUrl,
    secret_token: webhookSecret,
    allowed_updates: ["business_connection", "business_message", "message"],
    drop_pending_updates: false,
  });

  const tokenCipher = enteredToken
    ? await encryptSecret(token, encryptionSecret(env))
    : oldConfig.tokenCipher;

  const config = {
    version: 1,
    tokenCipher,
    watchedSenderId,
    alertMessage,
    cooldownSeconds,
    enabled,
    webhookSecret,
    webhookUrl,
    botId: String(bot.id),
    botUsername: bot.username,
    ownerChatId: oldConfig.ownerChatId || "",
    businessConnectionId: oldConfig.businessConnectionId || "",
    updatedAt: new Date().toISOString(),
  };
  await saveConfig(env, config);
  await saveStatus(env, {
    webhook: "active",
    lastAction: "تنظیمات ذخیره و وب‌هوک فعال شد",
    lastActionAt: new Date().toISOString(),
  });

  return redirect("/admin?notice=saved");
}

async function sendTestAlert(request, env) {
  const config = await requireConfigured(env);
  if (!config.ownerChatId) {
    throw badRequest("هنوز حساب تلگرام مالک ثبت نشده است. ربات را در Chat Automation متصل کن و صفحه را تازه‌سازی کن.");
  }
  const token = await decryptSecret(config.tokenCipher, encryptionSecret(env));
  await telegramApi(token, "sendMessage", {
    chat_id: config.ownerChatId,
    text: `🧪 تست هشدار\n\n${config.alertMessage}`,
    disable_notification: false,
  });
  await saveStatus(env, {
    lastAction: "پیام آزمایشی ارسال شد",
    lastActionAt: new Date().toISOString(),
  });
  return redirect("/admin?notice=test-sent");
}

async function disableWebhook(request, env) {
  const config = await requireConfigured(env);
  const token = await decryptSecret(config.tokenCipher, encryptionSecret(env));
  await telegramApi(token, "deleteWebhook", { drop_pending_updates: false });
  config.enabled = false;
  await saveConfig(env, config);
  await saveStatus(env, {
    webhook: "disabled",
    lastAction: "وب‌هوک غیرفعال شد",
    lastActionAt: new Date().toISOString(),
  });
  return redirect("/admin?notice=disabled");
}

async function handleTelegramWebhook(request, env, ctx) {
  if (request.method !== "POST") return methodNotAllowed();
  const config = await loadConfig(env);
  if (!config?.webhookSecret || !config?.tokenCipher) return new Response("Not configured", { status: 503 });

  const suppliedSecret = request.headers.get("X-Telegram-Bot-Api-Secret-Token") || "";
  if (!constantTimeEqual(suppliedSecret, config.webhookSecret)) return new Response("Forbidden", { status: 403 });

  let update;
  try {
    update = await request.json();
  } catch {
    return new Response("Invalid JSON", { status: 400 });
  }

  if (update.business_connection) {
    const connection = update.business_connection;
    config.ownerChatId = String(connection.user_chat_id || connection.user?.id || "");
    config.businessConnectionId = String(connection.id || "");
    config.connectionEnabled = Boolean(connection.is_enabled);
    await saveConfig(env, config);
    await saveStatus(env, {
      connection: connection.is_enabled ? "connected" : "disconnected",
      ownerChatId: config.ownerChatId,
      lastAction: connection.is_enabled ? "حساب تلگرام متصل شد" : "اتصال حساب تلگرام قطع شد",
      lastActionAt: new Date().toISOString(),
    });
    return new Response("OK");
  }

  // /start confirms that the owner can receive direct bot messages. Ownership
  // itself is learned only from Telegram's signed business_connection update.
  if (update.message?.chat?.type === "private" && update.message?.text?.startsWith("/start")) {
    const senderId = String(update.message.from?.id || "");
    const token = await decryptSecret(config.tokenCipher, encryptionSecret(env));
    const isOwner = Boolean(config.ownerChatId) && senderId === config.ownerChatId;
    ctx.waitUntil(telegramApi(token, "sendMessage", {
      chat_id: String(update.message.chat.id),
      text: isOwner
        ? "✅ ربات اعلان آماده است."
        : "برای فعال‌شدن اعلان، مالک حساب باید این ربات را از Settings → Chat Automation متصل کند.",
    }));
    return new Response("OK");
  }

  const message = update.business_message;
  if (!message || !config.enabled) return new Response("OK");
  const senderId = String(message.from?.id || "");
  if (!senderId || senderId !== config.watchedSenderId) return new Response("OK");
  if (!config.ownerChatId) {
    await saveStatus(env, {
      lastAction: "پیام هدف رسید، اما شناسه مالک هنوز ثبت نشده بود",
      lastActionAt: new Date().toISOString(),
      lastSenderId: senderId,
    });
    return new Response("OK");
  }

  const cooldownKey = `telegram-alert:cooldown:${senderId}`;
  if (config.cooldownSeconds > 0 && (await env.CONFIG_STORE.get(cooldownKey))) {
    await saveStatus(env, {
      lastAction: "پیام هدف به‌دلیل فاصله جلوگیری از تکرار نادیده گرفته شد",
      lastActionAt: new Date().toISOString(),
      lastSenderId: senderId,
    });
    return new Response("OK");
  }

  // Reserve the cooldown slot before sending to reduce duplicate alerts when
  // the monitored sender emits several messages almost simultaneously.
  if (config.cooldownSeconds > 0) {
    await env.CONFIG_STORE.put(cooldownKey, "1", { expirationTtl: Math.max(60, config.cooldownSeconds) });
  }

  const token = await decryptSecret(config.tokenCipher, encryptionSecret(env));
  const alertPromise = telegramApiWithRetry(token, "sendMessage", {
    chat_id: config.ownerChatId,
    text: config.alertMessage,
    disable_notification: false,
  }).then(async () => {
    await saveStatus(env, {
      lastAction: "هشدار ارسال شد",
      lastActionAt: new Date().toISOString(),
      lastSenderId: senderId,
      lastMessageId: String(message.message_id || ""),
    });
  }).catch(async (error) => {
    if (config.cooldownSeconds > 0) await env.CONFIG_STORE.delete(cooldownKey);
    await saveStatus(env, {
      lastAction: `ارسال هشدار شکست خورد: ${error.message}`,
      lastActionAt: new Date().toISOString(),
      lastSenderId: senderId,
    });
    throw error;
  });
  ctx.waitUntil(alertPromise);
  return new Response("OK");
}

async function telegramApi(token, method, payload) {
  const response = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const result = await response.json().catch(() => null);
  if (!response.ok || !result?.ok) {
    const description = result?.description || `HTTP ${response.status}`;
    throw badRequest(`خطای تلگرام در ${method}: ${description}`);
  }
  return result.result;
}

async function telegramApiWithRetry(token, method, payload, attempts = 3) {
  let lastError;
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      return await telegramApi(token, method, payload);
    } catch (error) {
      lastError = error;
      if (attempt < attempts - 1) await new Promise((resolve) => setTimeout(resolve, 300 * (2 ** attempt)));
    }
  }
  throw lastError;
}

async function loadConfig(env) {
  return await env.CONFIG_STORE.get(CONFIG_KEY, "json");
}

async function saveConfig(env, config) {
  await env.CONFIG_STORE.put(CONFIG_KEY, JSON.stringify(config));
}

async function saveStatus(env, patch) {
  const current = (await env.CONFIG_STORE.get(STATUS_KEY, "json")) || {};
  await env.CONFIG_STORE.put(STATUS_KEY, JSON.stringify({ ...current, ...patch }));
}

async function requireConfigured(env) {
  const config = await loadConfig(env);
  if (!config?.tokenCipher) throw badRequest("ابتدا تنظیمات ربات را ذخیره کن.");
  return config;
}

function defaultConfig() {
  return {
    watchedSenderId: "",
    alertMessage: "سایت قطع شد",
    cooldownSeconds: 300,
    enabled: true,
    ownerChatId: "",
    botUsername: "",
  };
}

function assertBindings(env) {
  const missing = [];
  if (!env.CONFIG_STORE) missing.push("CONFIG_STORE (KV binding)");
  if (!env.ADMIN_PASSWORD) missing.push("ADMIN_PASSWORD");
  if (missing.length) throw new Error(`تنظیمات Cloudflare ناقص است: ${missing.join(", ")}`);
}

// Optional dedicated secrets are supported for advanced deployments. The
// one-click deployment needs only ADMIN_PASSWORD and derives independent keys
// with domain-separated prefixes to keep mobile setup short.
function sessionSecret(env) {
  return env.SESSION_SECRET || `telegram-alert:session:${env.ADMIN_PASSWORD}`;
}

function encryptionSecret(env) {
  return env.CONFIG_ENCRYPTION_KEY || `telegram-alert:encryption:${env.ADMIN_PASSWORD}`;
}

async function requireAdmin(request, env) {
  if (!(await isAuthenticated(request, env))) {
    const error = new Error("Unauthorized");
    error.status = 401;
    throw error;
  }
}

async function isAuthenticated(request, env) {
  const cookies = parseCookies(request.headers.get("cookie") || "");
  const token = cookies.ta_session;
  if (!token) return false;
  const [expiryText, signature] = token.split(".");
  const expiry = Number(expiryText);
  if (!expiry || expiry < Math.floor(Date.now() / 1000) || !signature) return false;
  const expected = await hmacSign(expiryText, sessionSecret(env));
  return constantTimeEqual(signature, expected);
}

async function createSessionCookie(secret) {
  const expiry = Math.floor(Date.now() / 1000) + SESSION_SECONDS;
  const signature = await hmacSign(String(expiry), secret);
  return `ta_session=${expiry}.${signature}; Max-Age=${SESSION_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Strict`;
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
  return await crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptSecret(value, secret) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await encryptionKey(secret);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(value));
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
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, cipher);
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error("رمزگشایی توکن شکست خورد؛ CONFIG_ENCRYPTION_KEY احتمالاً تغییر کرده است.");
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
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function randomToken(bytes = 32) {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}

function constantTimeEqual(a, b) {
  const aa = new TextEncoder().encode(String(a));
  const bb = new TextEncoder().encode(String(b));
  let diff = aa.length ^ bb.length;
  const length = Math.max(aa.length, bb.length);
  for (let i = 0; i < length; i++) diff |= (aa[i % (aa.length || 1)] || 0) ^ (bb[i % (bb.length || 1)] || 0);
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

function requireSameOrigin(request) {
  const origin = request.headers.get("origin");
  if (!origin || origin !== new URL(request.url).origin) {
    const error = new Error("درخواست نامعتبر است؛ صفحه را دوباره باز کن.");
    error.status = 403;
    throw error;
  }
}

function normalizeId(value, label) {
  const text = String(value || "").trim();
  if (!/^-?\d{1,20}$/.test(text)) throw badRequest(`${label} باید عددی باشد، نه @username.`);
  return text;
}

function clampInteger(value, min, max, fallback) {
  const number = Number.parseInt(String(value || ""), 10);
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
  const headers = { location };
  if (cookie) headers["set-cookie"] = cookie;
  return new Response(null, { status: 303, headers });
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
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
  return `<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(title)}</title><style>
:root{color-scheme:dark;--bg:#07111f;--card:#101d30;--line:#243853;--text:#eef6ff;--muted:#9db0c9;--accent:#3aa0ff;--good:#2dd4a8;--bad:#ff647c}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#102744 0,var(--bg) 48%);font-family:Tahoma,Arial,sans-serif;color:var(--text);min-height:100vh}
.wrap{width:min(780px,calc(100% - 28px));margin:36px auto}.brand{display:flex;align-items:center;gap:12px;margin-bottom:20px}.logo{display:grid;place-items:center;width:50px;height:50px;border-radius:15px;background:linear-gradient(135deg,#2495ff,#2dd4a8);font-size:25px}.brand h1{font-size:22px;margin:0}.brand p{margin:5px 0 0;color:var(--muted);font-size:13px}
.card{background:color-mix(in srgb,var(--card) 94%,transparent);border:1px solid var(--line);border-radius:20px;padding:22px;box-shadow:0 20px 50px #0005;margin-bottom:16px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.full{grid-column:1/-1}label{display:block;color:#c8d8eb;font-size:13px;margin:0 0 7px}input,textarea{width:100%;border:1px solid var(--line);background:#081525;color:var(--text);border-radius:12px;padding:12px 13px;font:inherit;outline:none}input:focus,textarea:focus{border-color:var(--accent);box-shadow:0 0 0 3px #3aa0ff22}textarea{min-height:100px;resize:vertical}.hint{color:var(--muted);font-size:12px;line-height:1.8;margin:6px 0 0}.check{display:flex;gap:10px;align-items:center}.check input{width:auto;accent-color:var(--accent)}button{border:0;border-radius:12px;padding:12px 18px;background:var(--accent);color:white;font:inherit;font-weight:bold;cursor:pointer}button.secondary{background:#213752}button.danger{background:#6b2533}.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}.status{display:grid;grid-template-columns:repeat(2,1fr);gap:10px}.stat{background:#091626;border:1px solid var(--line);padding:13px;border-radius:13px}.stat b{display:block;margin-top:6px;font-size:14px;word-break:break-word}.muted{color:var(--muted)}.notice{padding:13px 15px;border-radius:12px;margin-bottom:16px;background:#123b33;border:1px solid #1b6a58}.notice.bad{background:#421d29;border-color:#803047}.pill{display:inline-flex;padding:4px 9px;border-radius:999px;background:#174438;color:#8ef0d2;font-size:12px}.pill.off{background:#46232e;color:#ffb1bf}.divider{height:1px;background:var(--line);margin:18px 0}.login{width:min(430px,calc(100% - 28px));margin:14vh auto}.login button{width:100%;margin-top:14px}.foot{color:var(--muted);text-align:center;font-size:11px;margin-top:16px}
@media(max-width:640px){.grid,.status{grid-template-columns:1fr}.full{grid-column:auto}.wrap{margin-top:20px}.card{padding:17px}}
</style></head><body>${content}</body></html>`;
}

function loginPage(error = "") {
  return layout("ورود به پنل هشدار", `<main class="login"><div class="brand"><div class="logo">🔔</div><div><h1>پنل هشدار تلگرام</h1><p>ورود امن مدیر</p></div></div>
${error ? `<div class="notice bad">${escapeHtml(error)}</div>` : ""}
<section class="card"><form method="post" action="/login"><label for="password">رمز مدیریت</label><input id="password" name="password" type="password" autocomplete="current-password" required autofocus><button type="submit">ورود</button></form></section>
<p class="foot">توکن ربات در این پنل به‌صورت رمزنگاری‌شده نگهداری می‌شود.</p></main>`);
}

function adminPage(config, status, notice, isError) {
  const noticeText = notice;
  const connected = Boolean(config.ownerChatId && config.connectionEnabled !== false);
  const botReady = Boolean(config.tokenCipher && config.botUsername);
  const enabled = Boolean(config.enabled);
  return layout("پنل هشدار تلگرام", `<main class="wrap"><div class="brand"><div class="logo">🔔</div><div><h1>پنل هشدار تلگرام</h1><p>اعلان پیام یک فرستنده مشخص از Chat Automation</p></div></div>
${noticeText ? `<div class="notice${isError ? " bad" : ""}">${escapeHtml(noticeText)}</div>` : ""}
<section class="card"><div class="status">
<div class="stat"><span class="muted">ربات</span><b>${botReady ? `@${escapeHtml(config.botUsername)}` : "تنظیم نشده"}</b></div>
<div class="stat"><span class="muted">Chat Automation</span><b>${connected ? `<span class="pill">متصل</span>` : `<span class="pill off">منتظر اتصال</span>`}</b></div>
<div class="stat"><span class="muted">شناسه حساب مالک</span><b>${escapeHtml(config.ownerChatId || "هنوز دریافت نشده")}</b></div>
<div class="stat"><span class="muted">آخرین رویداد</span><b>${escapeHtml(status.lastAction || "هنوز رویدادی ثبت نشده")}</b></div>
</div></section>
<section class="card"><form method="post" action="/admin/save"><div class="grid">
<div class="full"><label for="bot_token">توکن ربات</label><input id="bot_token" name="bot_token" type="password" autocomplete="off" placeholder="${config.tokenCipher ? "برای حفظ توکن فعلی خالی بگذار" : "123456:ABC..."}"><p class="hint">توکن بعد از ذخیره دوباره نمایش داده نمی‌شود.</p></div>
<div><label for="watched_sender_id">شناسه عددی فرستنده هدف</label><input id="watched_sender_id" name="watched_sender_id" inputmode="numeric" value="${escapeHtml(config.watchedSenderId || "")}" placeholder="123456789" required><p class="hint">@username قابل قبول نیست.</p></div>
<div><label for="cooldown_seconds">فاصله جلوگیری از تکرار (ثانیه)</label><input id="cooldown_seconds" name="cooldown_seconds" type="number" min="0" max="86400" value="${escapeHtml(String(config.cooldownSeconds ?? 300))}"><p class="hint">۰ یعنی هر پیام یک هشدار؛ پیشنهاد: ۳۰۰.</p></div>
<div class="full"><label for="alert_message">متن هشدار</label><textarea id="alert_message" name="alert_message" maxlength="4096" required>${escapeHtml(config.alertMessage || "سایت قطع شد")}</textarea></div>
<div class="full check"><input id="enabled" name="enabled" type="checkbox" ${enabled ? "checked" : ""}><label for="enabled">ارسال هشدار فعال باشد</label></div>
</div><div class="actions"><button type="submit">ذخیره و فعال‌سازی وب‌هوک</button></div></form>
<div class="divider"></div><div class="actions"><form method="post" action="/admin/test"><button class="secondary" type="submit">ارسال پیام آزمایشی</button></form><form method="post" action="/admin/disable"><button class="danger" type="submit">غیرفعال‌کردن وب‌هوک</button></form><form method="post" action="/logout"><button class="secondary" type="submit">خروج</button></form></div>
</section><section class="card"><b>ترتیب راه‌اندازی</b><ol class="hint"><li>تنظیمات بالا را ذخیره کن.</li><li>در BotFather برای ربات Secretary Mode را فعال کن.</li><li>در Telegram → Settings → Chat Automation ربات را وصل کن.</li><li>ترجیحاً Only selected chats را انتخاب و فقط چت هدف را اضافه کن.</li><li>به پنل برگرد و پیام آزمایشی بفرست.</li></ol></section></main>`);
}

function messagePage(title, message) {
  return layout(title, `<main class="login"><div class="brand"><div class="logo">⚠️</div><div><h1>${escapeHtml(title)}</h1></div></div><section class="card"><p>${escapeHtml(message)}</p><a href="/admin" style="color:#67b8ff">بازگشت به پنل</a></section></main>`);
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
}
