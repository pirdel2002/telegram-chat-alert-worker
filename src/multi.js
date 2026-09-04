const STATE_KEY = "telegram-alert:state:v4";
const V3_STATE_KEY = "telegram-alert:state:v3";
const V2_STATE_KEY = "telegram-alert:state:v2";
const LEGACY_CONFIG_KEY = "telegram-alert:config:v1";
const STATUS_PREFIX = "telegram-alert:status:v2:";
const MESSAGE_PREFIX = "telegram-alert:message:v1:";
const KV_HISTORY_MIGRATION_KEY = "telegram-alert:d1-migration:v1";
const MESSAGE_PAGE_SIZES = [20, 50, 100];
const DISPLAY_TIME_ZONE = "Asia/Tehran";
const SESSION_SECONDS = 12 * 60 * 60;
const LOGIN_WINDOW_SECONDS = 10 * 60;
const MAX_LOGIN_ATTEMPTS = 5;
const readyDatabases = new WeakSet();

export default {
  async fetch(request, env, ctx) {
    try {
      assertBindings(env);
      await ensureMessageDatabase(env);
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
          senders: state.senders.length,
          rules: state.bots.reduce(function (count, bot) { return count + bot.rules.length; }, 0),
        });
      }

      const adminActions = {
        "/admin/bot/save": saveBot,
        "/admin/bot/test": testBot,
        "/admin/bot/disable": disableBot,
        "/admin/bot/delete": deleteBot,
        "/admin/sender/save": saveSender,
        "/admin/sender/delete": deleteSender,
        "/admin/rule/save": saveRule,
        "/admin/rule/delete": deleteRule,
        "/admin/chat-log/toggle": toggleChatLog,
        "/admin/message/delete": deleteMessages,
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
  await migrateKvHistoryToD1(env);
  const url = new URL(request.url);
  const statuses = {};
  await Promise.all(state.bots.map(async function (bot) {
    const values = await Promise.all([
      env.CONFIG_STORE.get(statusKey(bot.id), "json"),
      loadLastMessageFromD1(env, bot.id),
    ]);
    statuses[bot.id] = Object.assign({}, values[0] || {}, values[1] || {});
  }));
  const noticeCode = url.searchParams.get("notice") || "";
  const notices = {
    "bot-saved": "بات ذخیره شد و وب‌هوک آن فعال است.",
    "bot-tested": "پیام آزمایشی ارسال شد.",
    "bot-disabled": "وب‌هوک بات غیرفعال شد.",
    "bot-deleted": "بات و قوانین آن حذف شد.",
    "sender-saved": "فرستنده ذخیره شد.",
    "sender-deleted": "فرستنده و قوانین مرتبط با آن حذف شد.",
    "rule-saved": "قانون ذخیره شد.",
    "rule-deleted": "قانون حذف شد.",
    "chat-log-enabled": "ثبت پیام‌های این سمت چت فعال شد.",
    "chat-log-disabled": "ثبت پیام‌های این سمت چت غیرفعال شد؛ هشدارها همچنان فعال‌اند.",
    "messages-deleted": "پیام‌های انتخاب‌شده حذف شدند.",
  };
  const csrfToken = await csrfTokenForRequest(request, env);
  const allowedTabs = ["overview", "messages", "bots", "bot-new", "bot-edit", "senders", "sender-new", "rules", "rule-new", "guide"];
  const requestedTab = url.searchParams.get("tab") || "overview";
  const activeTab = allowedTabs.includes(requestedTab) ? requestedTab : "overview";
  const selectedBotId = url.searchParams.get("bot") || "";
  const messageFilters = parseMessageFilters(url.searchParams);
  const messagePage = activeTab === "messages"
    ? await loadMessagePage(env, state, messageFilters)
    : { items: [], nextCursor: "", sources: [] };
  return html(adminPage(state, statuses, notices[noticeCode] || "", csrfToken, activeTab, selectedBotId, messagePage, messageFilters));
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
    connections: sameTelegramBot && Array.isArray(existing.connections) ? existing.connections : [],
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
  return redirect("/admin?tab=bots&notice=bot-saved");
}

async function testBot(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const bot = requireBot(state, form.get("bot_id"));
  const ownerChatIds = activeConnections(bot).map(function (connection) {
    return connection.ownerChatId;
  }).filter(Boolean).filter(function (value, index, list) {
    return list.indexOf(value) === index;
  });
  if (!ownerChatIds.length && bot.ownerChatId) ownerChatIds.push(bot.ownerChatId);
  if (!ownerChatIds.length) {
    throw badRequest("هنوز حساب مالک برای این بات ثبت نشده است. بات را در Chat Automation متصل کن.");
  }
  const token = await decryptSecret(bot.tokenCipher, encryptionSecret(env));
  await Promise.all(ownerChatIds.map(function (chatId) {
    return telegramApi(token, "sendMessage", {
      chat_id: chatId,
      text: "🧪 پیام آزمایشی از " + bot.label,
      disable_notification: false,
    });
  }));
  await saveStatus(env, bot.id, {
    lastAction: "پیام آزمایشی برای " + ownerChatIds.length + " حساب ارسال شد",
    lastActionAt: new Date().toISOString(),
  });
  return redirect("/admin?tab=overview&notice=bot-tested");
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
  return redirect("/admin?tab=bots&notice=bot-disabled");
}

async function deleteBot(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const bot = requireBot(state, form.get("bot_id"));
  const token = await decryptSecret(bot.tokenCipher, encryptionSecret(env));
  await telegramApi(token, "deleteWebhook", { drop_pending_updates: false });
  state.bots = state.bots.filter(function (item) { return item.id !== bot.id; });
  await saveState(env, state);
  await Promise.all([
    env.CONFIG_STORE.delete(statusKey(bot.id)),
    env.MESSAGE_DB.batch([
      env.MESSAGE_DB.prepare("DELETE FROM messages WHERE bot_id = ?").bind(bot.id),
      env.MESSAGE_DB.prepare("DELETE FROM chat_sources WHERE bot_id = ?").bind(bot.id),
    ]),
  ]);
  return redirect("/admin?tab=bots&notice=bot-deleted");
}

async function saveSender(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const submittedSenderId = String(form.get("sender_id") || "");
  const senderId = submittedSenderId
    ? requireSafeId(submittedSenderId, "شناسه داخلی فرستنده")
    : "sender_" + randomToken(9);
  const telegramId = normalizeTelegramId(form.get("telegram_id"));
  const label = String(form.get("label") || "").trim();
  const enabled = form.get("enabled") === "on";

  if (!label || label.length > 80) throw badRequest("نام فرستنده باید بین ۱ تا ۸۰ نویسه باشد.");
  const duplicate = state.senders.find(function (sender) {
    return sender.telegramId === telegramId && sender.id !== senderId;
  });
  if (duplicate) throw badRequest("این شناسه عددی قبلاً در فهرست مشترک فرستنده‌ها ثبت شده است.");

  const sender = {
    id: senderId,
    telegramId: telegramId,
    label: label,
    enabled: enabled,
    updatedAt: new Date().toISOString(),
  };
  const senderIndex = state.senders.findIndex(function (item) { return item.id === senderId; });
  if (senderIndex >= 0) state.senders[senderIndex] = sender;
  else state.senders.push(sender);
  await saveState(env, state);
  return redirect("/admin?tab=senders&notice=sender-saved");
}

async function deleteSender(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const senderId = requireSafeId(String(form.get("sender_id") || ""), "شناسه داخلی فرستنده");
  if (!state.senders.some(function (sender) { return sender.id === senderId; })) {
    throw badRequest("فرستنده پیدا نشد.");
  }
  const removedRules = [];
  state.bots.forEach(function (bot) {
    bot.rules.filter(function (rule) { return rule.senderRef === senderId; }).forEach(function (rule) {
      removedRules.push({ botId: bot.id, ruleId: rule.id });
    });
    bot.rules = bot.rules.filter(function (rule) { return rule.senderRef !== senderId; });
    bot.updatedAt = new Date().toISOString();
  });
  state.senders = state.senders.filter(function (sender) { return sender.id !== senderId; });
  await saveState(env, state);
  await Promise.all(removedRules.map(function (rule) {
    return env.CONFIG_STORE.delete(cooldownKey(rule.botId, rule.ruleId));
  }));
  return redirect("/admin?tab=senders&notice=sender-deleted");
}

async function saveRule(request, env) {
  const form = await request.formData();
  const state = await loadState(env);
  const bot = requireBot(state, form.get("bot_id"));
  const submittedRuleId = String(form.get("rule_id") || "");
  const ruleId = submittedRuleId ? requireSafeId(submittedRuleId, "شناسه قانون") : "rule_" + randomToken(9);
  const senderRef = String(form.get("sender_ref") || "*");
  const matchType = String(form.get("match_type") || "contains");
  const keyword = String(form.get("keyword") || "").trim();
  const alertMessage = String(form.get("alert_message") || "").trim();
  const cooldownSeconds = clampInteger(form.get("cooldown_seconds"), 0, 86400, 300);
  const enabled = form.get("enabled") === "on";

  if (senderRef !== "*" && !state.senders.some(function (sender) { return sender.id === senderRef; })) {
    throw badRequest("فرستنده انتخاب‌شده معتبر نیست.");
  }
  if (!["any", "contains"].includes(matchType)) throw badRequest("نوع فیلتر پیام معتبر نیست.");
  if (matchType === "contains" && (!keyword || keyword.length > 200)) {
    throw badRequest("عبارت فیلتر باید بین ۱ تا ۲۰۰ نویسه باشد.");
  }
  if (!alertMessage || alertMessage.length > 4096) {
    throw badRequest("متن پیام هشدار باید بین ۱ تا ۴۰۹۶ نویسه باشد.");
  }

  const rule = {
    id: ruleId,
    senderRef: senderRef,
    matchType: matchType,
    keyword: matchType === "contains" ? keyword : "",
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
  return redirect("/admin?tab=rules&bot=" + encodeURIComponent(bot.id) + "&notice=rule-saved");
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
  return redirect("/admin?tab=rules&bot=" + encodeURIComponent(bot.id) + "&notice=rule-deleted");
}

async function toggleChatLog(request, env) {
  const form = await request.formData();
  if (form.get("confirm") !== "on") throw badRequest("برای تغییر وضعیت لاگ، تأیید هشدار الزامی است.");
  const sourceKey = String(form.get("source_key") || "");
  if (!sourceKey || sourceKey.length > 500) throw badRequest("منبع چت معتبر نیست.");
  const enabled = form.get("log_enabled") === "on" ? 1 : 0;
  const result = await env.MESSAGE_DB.prepare(
    "UPDATE chat_sources SET log_enabled = ?, updated_at = ? WHERE source_key = ?",
  ).bind(enabled, Math.floor(Date.now() / 1000), sourceKey).run();
  if (!result.meta || Number(result.meta.changes) < 1) throw badRequest("منبع چت پیدا نشد.");
  return redirect("/admin?tab=messages&notice=" + (enabled ? "chat-log-enabled" : "chat-log-disabled"));
}

async function deleteMessages(request, env) {
  const form = await request.formData();
  if (form.get("confirm_delete") !== "on") throw badRequest("برای حذف پیام‌ها، تأیید حذف الزامی است.");
  const ids = form.getAll("message_ids").map(function (value) {
    return Number(value);
  }).filter(function (value) {
    return Number.isSafeInteger(value) && value > 0;
  }).filter(function (value, index, list) {
    return list.indexOf(value) === index;
  });
  if (!ids.length) throw badRequest("حداقل یک پیام را انتخاب کن.");
  if (ids.length > 100) throw badRequest("در هر بار حداکثر ۱۰۰ پیام قابل حذف است.");
  await env.MESSAGE_DB.batch(ids.map(function (id) {
    return env.MESSAGE_DB.prepare("DELETE FROM messages WHERE id = ?").bind(id);
  }));
  const returnTo = safeAdminReturnPath(String(form.get("return_to") || ""));
  return redirect(returnTo + (returnTo.includes("?") ? "&" : "?") + "notice=messages-deleted");
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
    const connectionId = String(connection.id || "");
    const ownerChatId = String(connection.user_chat_id || (connection.user && connection.user.id) || "");
    const storedConnection = {
      id: connectionId,
      ownerChatId: ownerChatId,
      ownerName: telegramDisplayName(connection.user, "حساب متصل"),
      enabled: Boolean(connection.is_enabled),
      updatedAt: new Date().toISOString(),
    };
    const connectionIndex = bot.connections.findIndex(function (item) { return item.id === connectionId; });
    if (connectionIndex >= 0) bot.connections[connectionIndex] = storedConnection;
    else bot.connections.push(storedConnection);
    bot.ownerChatId = ownerChatId;
    bot.businessConnectionId = connectionId;
    bot.connectionEnabled = activeConnections(bot).length > 0;
    bot.updatedAt = new Date().toISOString();
    await saveState(env, state);
    await saveStatus(env, bot.id, {
      connection: connection.is_enabled ? "connected" : "disconnected",
      ownerChatId: ownerChatId,
      lastAction: connection.is_enabled ? "حساب تلگرام متصل شد" : "اتصال حساب تلگرام قطع شد",
      lastActionAt: new Date().toISOString(),
    });
    return new Response("OK");
  }

  if (update.message && update.message.chat && update.message.chat.type === "private"
      && String(update.message.text || "").startsWith("/start")) {
    const senderId = String((update.message.from && update.message.from.id) || "");
    const token = await decryptSecret(bot.tokenCipher, encryptionSecret(env));
    const isOwner = activeConnections(bot).some(function (connection) {
      return senderId === connection.ownerChatId;
    }) || (Boolean(bot.ownerChatId) && senderId === bot.ownerChatId);
    ctx.waitUntil(telegramApi(token, "sendMessage", {
      chat_id: String(update.message.chat.id),
      text: isOwner
        ? "✅ بات اعلان آماده است."
        : "برای فعال‌شدن اعلان، مالک حساب باید این بات را از Settings → Chat Automation متصل کند.",
    }));
    return new Response("OK");
  }

  const message = update.business_message;
  if (!message) return new Response("OK");
  const senderId = String((message.from && message.from.id) || "");
  const incomingText = String(message.text || message.caption || "");
  const normalizedIncoming = normalizeText(incomingText);
  const configuredSender = state.senders.find(function (sender) {
    return sender.enabled && sender.telegramId === senderId;
  });
  const connection = await resolveMessageConnection(bot, message, env, state);
  const direction = connection.ownerChatId && senderId === connection.ownerChatId ? "outgoing" : "incoming";
  const messageRecord = buildMessageRecord(bot, message, update.update_id, configuredSender, direction, connection);
  const logEnabled = await upsertChatSource(env, messageRecord);
  await Promise.all([
    logEnabled ? saveMessage(env, messageRecord) : Promise.resolve(),
    saveStatus(env, bot.id, {
      lastSenderId: senderId,
      lastSenderLabel: configuredSender ? configuredSender.label : "",
      lastObservedAt: messageRecord.timestamp,
      lastObservedLogging: logEnabled,
    }),
  ]);

  if (!bot.enabled || direction === "outgoing") return new Response("OK");
  const matchedRules = bot.rules.filter(function (rule) {
    if (!rule.enabled) return false;
    if (rule.senderRef !== "*") {
      const selectedSender = state.senders.find(function (sender) {
        return sender.id === rule.senderRef && sender.enabled;
      });
      if (!selectedSender || selectedSender.telegramId !== senderId) return false;
    }
    if (rule.matchType === "any") return true;
    return Boolean(rule.keyword) && normalizedIncoming.includes(normalizeText(rule.keyword));
  });

  if (!matchedRules.length) {
    await saveStatus(env, bot.id, {
      lastSenderId: senderId,
      lastSenderLabel: configuredSender ? configuredSender.label : "",
      lastAction: "پیام دریافت شد؛ هیچ تریگری منطبق نبود",
      lastActionAt: new Date().toISOString(),
    });
    return new Response("OK");
  }

  const alertOwnerChatId = connection.ownerChatId || bot.ownerChatId;
  if (!alertOwnerChatId) {
    await saveStatus(env, bot.id, {
      lastSenderId: senderId,
      lastSenderLabel: configuredSender ? configuredSender.label : "",
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
      lastSenderLabel: configuredSender ? configuredSender.label : "",
      lastAction: "تریگر منطبق شد، اما در فاصله جلوگیری از تکرار بود",
      lastActionAt: new Date().toISOString(),
    });
    return new Response("OK");
  }

  const token = await decryptSecret(bot.tokenCipher, encryptionSecret(env));
  const alertPromise = Promise.allSettled(readyRules.map(async function (rule) {
    try {
      await telegramApiWithRetry(token, "sendMessage", {
        chat_id: alertOwnerChatId,
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
      lastSenderLabel: configuredSender ? configuredSender.label : "",
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

async function ensureMessageDatabase(env) {
  if (readyDatabases.has(env.MESSAGE_DB)) return;
  await env.MESSAGE_DB.exec(
    "CREATE TABLE IF NOT EXISTS messages ("
      + "id INTEGER PRIMARY KEY AUTOINCREMENT,"
      + "event_key TEXT NOT NULL UNIQUE,"
      + "source_key TEXT NOT NULL,"
      + "bot_id TEXT NOT NULL,"
      + "direction TEXT NOT NULL,"
      + "sent_at INTEGER NOT NULL,"
      + "payload_cipher TEXT NOT NULL,"
      + "created_at INTEGER NOT NULL"
      + ");"
      + "CREATE INDEX IF NOT EXISTS idx_messages_time ON messages(sent_at DESC, id DESC);"
      + "CREATE INDEX IF NOT EXISTS idx_messages_bot_time ON messages(bot_id, sent_at DESC, id DESC);"
      + "CREATE INDEX IF NOT EXISTS idx_messages_source ON messages(source_key);"
      + "CREATE TABLE IF NOT EXISTS chat_sources ("
      + "source_key TEXT PRIMARY KEY,"
      + "bot_id TEXT NOT NULL,"
      + "business_connection_id TEXT NOT NULL,"
      + "chat_id TEXT NOT NULL,"
      + "conversation_key TEXT NOT NULL,"
      + "owner_id TEXT NOT NULL,"
      + "log_enabled INTEGER NOT NULL DEFAULT 1,"
      + "label_cipher TEXT NOT NULL,"
      + "updated_at INTEGER NOT NULL"
      + ");"
      + "CREATE INDEX IF NOT EXISTS idx_chat_sources_updated ON chat_sources(updated_at DESC);"
      + "CREATE INDEX IF NOT EXISTS idx_chat_sources_conversation ON chat_sources(conversation_key);",
  );
  readyDatabases.add(env.MESSAGE_DB);
}

async function migrateKvHistoryToD1(env) {
  if (await env.CONFIG_STORE.get(KV_HISTORY_MIGRATION_KEY)) return;
  let cursor = "";
  do {
    const options = { prefix: MESSAGE_PREFIX, limit: 100 };
    if (cursor) options.cursor = cursor;
    const page = await env.CONFIG_STORE.list(options);
    const statements = [];
    for (const key of page.keys) {
      const cipher = await env.CONFIG_STORE.get(key.name);
      const message = await decryptMessagePayload(env, cipher);
      if (!message) continue;
      statements.push(env.MESSAGE_DB.prepare(
        "INSERT OR IGNORE INTO messages (event_key, source_key, bot_id, direction, sent_at, payload_cipher, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ).bind(
        "kv|" + key.name,
        "legacy|" + String(message.botId || "unknown"),
        String(message.botId || "unknown"),
        message.direction === "outgoing" ? "outgoing" : "incoming",
        Number(message.timestamp) || Math.floor(Date.now() / 1000),
        cipher,
        Math.floor(Date.now() / 1000),
      ));
    }
    if (statements.length) await env.MESSAGE_DB.batch(statements);
    cursor = page.list_complete ? "" : String(page.cursor || "");
  } while (cursor);
  await env.CONFIG_STORE.put(KV_HISTORY_MIGRATION_KEY, new Date().toISOString());
}

async function loadState(env) {
  const stored = await env.CONFIG_STORE.get(STATE_KEY, "json");
  if (stored && Array.isArray(stored.bots)) return normalizeState(stored);

  const v3 = await env.CONFIG_STORE.get(V3_STATE_KEY, "json");
  if (v3 && Array.isArray(v3.bots)) {
    const migrated = normalizeState(v3);
    await saveState(env, migrated);
    return migrated;
  }

  const v2 = await env.CONFIG_STORE.get(V2_STATE_KEY, "json");
  if (v2 && Array.isArray(v2.bots)) {
    const migrated = normalizeState(v2);
    await saveState(env, migrated);
    return migrated;
  }

  const old = await env.CONFIG_STORE.get(LEGACY_CONFIG_KEY, "json");
  const state = { version: 4, senders: [], bots: [], updatedAt: new Date().toISOString() };
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
      connections: old.businessConnectionId && old.ownerChatId ? [{
        id: String(old.businessConnectionId),
        ownerChatId: String(old.ownerChatId),
        ownerName: "حساب متصل قبلی",
        enabled: old.connectionEnabled !== false,
        updatedAt: old.updatedAt || "",
      }] : [],
      senders: [],
      rules: [],
      updatedAt: new Date().toISOString(),
    });
  }
  await saveState(env, state);
  return state;
}

function normalizeState(state) {
  const globalSenders = [];
  const senderByTelegramId = new Map();
  const senderIdOwner = new Map();
  const addGlobalSender = function (sender) {
    const normalized = {
      id: String(sender.id || ("sender_" + randomToken(9))),
      telegramId: String(sender.telegramId || ""),
      label: String(sender.label || sender.telegramId || "فرستنده"),
      enabled: sender.enabled !== false,
      updatedAt: sender.updatedAt || "",
    };
    if (!normalized.telegramId) return null;
    const byTelegram = senderByTelegramId.get(normalized.telegramId);
    if (byTelegram) return byTelegram;
    if (senderIdOwner.has(normalized.id) && senderIdOwner.get(normalized.id) !== normalized.telegramId) {
      normalized.id = "sender_" + randomToken(9);
    }
    globalSenders.push(normalized);
    senderByTelegramId.set(normalized.telegramId, normalized);
    senderIdOwner.set(normalized.id, normalized.telegramId);
    return normalized;
  };
  (Array.isArray(state.senders) ? state.senders : []).forEach(addGlobalSender);

  const bots = state.bots.map(function (bot) {
    const senderRefMap = new Map();
    (Array.isArray(bot.senders) ? bot.senders : []).forEach(function (sender) {
      const globalSender = addGlobalSender(sender);
      if (globalSender) senderRefMap.set(String(sender.id), globalSender.id);
    });
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
        connections: Array.isArray(bot.connections) && bot.connections.length
          ? bot.connections.map(function (connection) {
            return {
              id: String(connection.id || ""),
              ownerChatId: String(connection.ownerChatId || ""),
              ownerName: String(connection.ownerName || "حساب متصل"),
              enabled: connection.enabled !== false,
              updatedAt: connection.updatedAt || "",
            };
          }).filter(function (connection) { return connection.id; })
          : (bot.businessConnectionId && bot.ownerChatId ? [{
            id: String(bot.businessConnectionId),
            ownerChatId: String(bot.ownerChatId),
            ownerName: "حساب متصل قبلی",
            enabled: bot.connectionEnabled !== false,
            updatedAt: bot.updatedAt || "",
          }] : []),
        rules: Array.isArray(bot.rules) ? bot.rules.map(function (rule) {
          return {
            id: String(rule.id),
            senderRef: senderRefMap.get(String(rule.senderRef || "*")) || String(rule.senderRef || "*"),
            matchType: rule.matchType === "any" ? "any" : "contains",
            keyword: String(rule.keyword || ""),
            alertMessage: String(rule.alertMessage || ""),
            cooldownSeconds: clampInteger(rule.cooldownSeconds, 0, 86400, 300),
            enabled: rule.enabled !== false,
            updatedAt: rule.updatedAt || "",
          };
        }) : [],
        updatedAt: bot.updatedAt || "",
      };
  });
  return {
    version: 4,
    updatedAt: state.updatedAt || "",
    senders: globalSenders,
    bots: bots,
  };
}

async function saveState(env, state) {
  state.version = 4;
  state.updatedAt = new Date().toISOString();
  await env.CONFIG_STORE.put(STATE_KEY, JSON.stringify(state));
}

async function saveStatus(env, botId, patch) {
  const key = statusKey(botId);
  const current = (await env.CONFIG_STORE.get(key, "json")) || {};
  await env.CONFIG_STORE.put(key, JSON.stringify(Object.assign({}, current, patch)));
}

function buildMessageRecord(bot, message, updateId, configuredSender, direction, connection) {
  const timestamp = Number(message.date) > 0 ? Number(message.date) : Math.floor(Date.now() / 1000);
  const senderName = configuredSender
    ? configuredSender.label
    : telegramDisplayName(message.from, direction === "outgoing" ? "مالک حساب" : "فرستنده ناشناس");
  const chatName = telegramDisplayName(message.chat, senderName);
  const uniqueId = String(updateId == null ? (message.message_id || randomToken(6)) : updateId)
    .replace(/[^A-Za-z0-9_-]/g, "_");
  const chatId = String((message.chat && message.chat.id) || "unknown");
  const connectionId = String(connection.id || "legacy");
  const participants = [String(connection.ownerChatId || "unknown"), chatId].sort();
  return {
    eventKey: bot.id + "|" + connectionId + "|" + uniqueId,
    sourceKey: bot.id + "|" + connectionId + "|" + chatId,
    conversationKey: bot.id + "|" + participants.join("|"),
    botId: bot.id,
    botLabel: bot.label,
    connectionId: connectionId,
    ownerId: String(connection.ownerChatId || ""),
    ownerName: String(connection.ownerName || "حساب متصل"),
    chatId: chatId,
    senderRef: configuredSender ? configuredSender.id : "",
    senderTelegramId: String((message.from && message.from.id) || ""),
    senderName: senderName,
    chatName: chatName,
    direction: direction,
    text: telegramMessageText(message),
    timestamp: timestamp,
    messageId: String(message.message_id || ""),
  };
}

async function saveMessage(env, record) {
  const cipher = await encryptSecret(JSON.stringify(record), encryptionSecret(env));
  await env.MESSAGE_DB.prepare(
    "INSERT OR IGNORE INTO messages (event_key, source_key, bot_id, direction, sent_at, payload_cipher, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
  ).bind(
    record.eventKey,
    record.sourceKey,
    record.botId,
    record.direction,
    record.timestamp,
    cipher,
    Math.floor(Date.now() / 1000),
  ).run();
}

async function loadMessagePage(env, state, filters) {
  const offset = (filters.page - 1) * filters.pageSize;
  const wanted = offset + filters.pageSize + 1;
  const matches = [];
  const batchSize = 250;
  const scanLimit = 20000;
  let scanned = 0;
  let cursor = null;
  let exhausted = false;
  while (matches.length < wanted && scanned < scanLimit && !exhausted) {
    const clauses = [];
    const values = [];
    if (filters.fromTimestamp) {
      clauses.push("sent_at >= ?");
      values.push(filters.fromTimestamp);
    }
    if (filters.toTimestamp) {
      clauses.push("sent_at < ?");
      values.push(filters.toTimestamp);
    }
    if (filters.botId) {
      clauses.push("bot_id = ?");
      values.push(filters.botId);
    }
    if (cursor) {
      clauses.push("(sent_at < ? OR (sent_at = ? AND id < ?))");
      values.push(cursor.sentAt, cursor.sentAt, cursor.id);
    }
    const sql = "SELECT id, sent_at, payload_cipher FROM messages"
      + (clauses.length ? " WHERE " + clauses.join(" AND ") : "")
      + " ORDER BY sent_at DESC, id DESC LIMIT ?";
    values.push(batchSize);
    const result = await env.MESSAGE_DB.prepare(sql).bind(...values).all();
    const rows = result.results || [];
    scanned += rows.length;
    exhausted = rows.length < batchSize;
    if (rows.length) {
      const last = rows[rows.length - 1];
      cursor = { sentAt: Number(last.sent_at), id: Number(last.id) };
    }
    const decoded = await Promise.all(rows.map(async function (row) {
      const message = await decryptMessagePayload(env, row.payload_cipher);
      return message ? Object.assign({}, message, { databaseId: Number(row.id) }) : null;
    }));
    decoded.filter(Boolean).forEach(function (message) {
      if (messageMatchesFilters(message, filters, state.senders)) matches.push(message);
    });
  }
  return {
    items: matches.slice(offset, offset + filters.pageSize),
    hasNext: matches.length > offset + filters.pageSize,
    scanLimited: scanned >= scanLimit && !exhausted,
    sources: await loadChatSources(env),
  };
}

async function loadLastMessageFromD1(env, botId) {
  const row = await env.MESSAGE_DB.prepare(
    "SELECT payload_cipher FROM messages WHERE bot_id = ? ORDER BY sent_at DESC, id DESC LIMIT 1",
  ).bind(botId).first();
  if (!row) return null;
  const message = await decryptMessagePayload(env, row.payload_cipher);
  return message ? {
    lastMessageText: message.text,
    lastMessageSenderName: message.senderName,
    lastMessageAt: message.timestamp,
    lastMessageDirection: message.direction,
  } : null;
}

async function decryptMessagePayload(env, cipher) {
  if (!cipher) return null;
  try {
    return JSON.parse(await decryptSecret(cipher, encryptionSecret(env)));
  } catch (error) {
    console.warn("Could not decrypt D1 message", error);
    return null;
  }
}

async function upsertChatSource(env, record) {
  const labelCipher = await encryptSecret(JSON.stringify({
    ownerName: record.ownerName,
    chatName: record.chatName,
    botLabel: record.botLabel,
  }), encryptionSecret(env));
  const row = await env.MESSAGE_DB.prepare(
    "INSERT INTO chat_sources (source_key, bot_id, business_connection_id, chat_id, conversation_key, owner_id, log_enabled, label_cipher, updated_at) "
      + "VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?) ON CONFLICT(source_key) DO UPDATE SET "
      + "conversation_key = excluded.conversation_key, owner_id = excluded.owner_id, label_cipher = excluded.label_cipher, updated_at = excluded.updated_at "
      + "RETURNING log_enabled",
  ).bind(
    record.sourceKey,
    record.botId,
    record.connectionId,
    record.chatId,
    record.conversationKey,
    record.ownerId,
    labelCipher,
    Math.floor(Date.now() / 1000),
  ).first();
  return !row || Number(row.log_enabled) !== 0;
}

async function loadChatSources(env) {
  const result = await env.MESSAGE_DB.prepare(
    "SELECT source_key, bot_id, business_connection_id, chat_id, conversation_key, owner_id, log_enabled, label_cipher, updated_at "
      + "FROM chat_sources ORDER BY updated_at DESC LIMIT 200",
  ).all();
  return (await Promise.all((result.results || []).map(async function (row) {
    try {
      const labels = JSON.parse(await decryptSecret(row.label_cipher, encryptionSecret(env)));
      return Object.assign({}, row, labels, { logEnabled: Number(row.log_enabled) !== 0 });
    } catch (error) {
      console.warn("Could not decrypt chat source", row.source_key, error);
      return null;
    }
  }))).filter(Boolean);
}

async function resolveMessageConnection(bot, message, env, state) {
  const connectionId = String(message.business_connection_id || bot.businessConnectionId || "legacy");
  const stored = bot.connections.find(function (connection) { return connection.id === connectionId; });
  if (stored) return stored;
  if (message.business_connection_id) {
    try {
      const token = await decryptSecret(bot.tokenCipher, encryptionSecret(env));
      const remote = await telegramApi(token, "getBusinessConnection", {
        business_connection_id: connectionId,
      });
      if (remote && remote.id) {
        const recovered = {
          id: String(remote.id),
          ownerChatId: String(remote.user_chat_id || (remote.user && remote.user.id) || ""),
          ownerName: telegramDisplayName(remote.user, "حساب متصل"),
          enabled: Boolean(remote.is_enabled),
          updatedAt: new Date().toISOString(),
        };
        bot.connections.push(recovered);
        bot.updatedAt = new Date().toISOString();
        await saveState(env, state);
        return recovered;
      }
    } catch (error) {
      console.warn("Could not recover business connection", connectionId, error);
    }
  }
  return {
    id: connectionId,
    ownerChatId: String(bot.ownerChatId || ""),
    ownerName: "حساب متصل",
    enabled: bot.connectionEnabled !== false,
  };
}

function activeConnections(bot) {
  return (Array.isArray(bot.connections) ? bot.connections : []).filter(function (connection) {
    return connection.enabled !== false && connection.ownerChatId;
  });
}

function telegramDisplayName(entity, fallback) {
  if (!entity) return fallback || "ناشناس";
  const fullName = [entity.first_name, entity.last_name].filter(Boolean).join(" ").trim();
  if (fullName) return fullName;
  if (entity.title) return String(entity.title);
  if (entity.username) return "@" + String(entity.username);
  return fallback || "ناشناس";
}

function telegramMessageText(message) {
  const text = String(message.text || message.caption || "").trim();
  if (text) return text;
  if (message.photo) return "📷 تصویر";
  if (message.video) return "🎬 ویدئو";
  if (message.animation) return "🎞 تصویر متحرک";
  if (message.voice) return "🎙 پیام صوتی";
  if (message.audio) return "🎵 فایل صوتی";
  if (message.document) return "📎 " + String(message.document.file_name || "فایل");
  if (message.sticker) return (message.sticker.emoji ? message.sticker.emoji + " " : "") + "استیکر";
  if (message.contact) return "👤 مخاطب";
  if (message.location) return "📍 موقعیت مکانی";
  if (message.poll) return "📊 نظرسنجی: " + String(message.poll.question || "");
  return "پیام غیرمتنی";
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

function normalizeTelegramId(value) {
  const id = String(value || "").trim();
  if (!/^-?\d{1,20}$/.test(id)) {
    throw badRequest("شناسه فرستنده باید عددی باشد، نه username.");
  }
  return id;
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

function parseMessageFilters(searchParams) {
  const pageSizeValue = clampInteger(searchParams.get("page_size"), 20, 100, 50);
  const pageSize = MESSAGE_PAGE_SIZES.includes(pageSizeValue) ? pageSizeValue : 50;
  const from = validDateInput(searchParams.get("from"));
  const to = validDateInput(searchParams.get("to"));
  return {
    page: clampInteger(searchParams.get("page"), 1, 100000, 1),
    pageSize: pageSize,
    senderRef: String(searchParams.get("sender") || "").slice(0, 80),
    botId: String(searchParams.get("message_bot") || "").slice(0, 80),
    query: String(searchParams.get("q") || "").trim().slice(0, 200),
    from: from,
    to: to,
    fromTimestamp: from ? Math.floor(Date.parse(from + "T00:00:00+03:30") / 1000) : 0,
    toTimestamp: to ? Math.floor(Date.parse(to + "T00:00:00+03:30") / 1000) + 86400 : 0,
  };
}

function validDateInput(value) {
  const text = String(value || "");
  return /^\d{4}-\d{2}-\d{2}$/.test(text) && !Number.isNaN(Date.parse(text + "T00:00:00Z")) ? text : "";
}

function messageMatchesFilters(message, filters, senders) {
  if (filters.senderRef) {
    const sender = senders.find(function (item) { return item.id === filters.senderRef; });
    if (!sender) return false;
    const matchesSender = message.senderRef === sender.id
      || String(message.senderTelegramId || "") === sender.telegramId
      || (!message.senderRef && String(message.senderName || "") === sender.label);
    if (!matchesSender) return false;
  }
  if (filters.query) {
    const haystack = normalizeText([
      message.text,
      message.senderName,
      message.chatName,
      message.botLabel,
    ].join(" "));
    if (!haystack.includes(normalizeText(filters.query))) return false;
  }
  return true;
}

function safeAdminReturnPath(value) {
  if (!value.startsWith("/admin?tab=messages")) return "/admin?tab=messages";
  return value.replace(/[\r\n]/g, "").slice(0, 1800);
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
  if (!env.MESSAGE_DB) missing.push("MESSAGE_DB (D1 binding)");
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
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; font-src 'self' https://cdn.jsdelivr.net; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
    },
  });
}

function layout(title, content) {
  const css = [
    "@font-face{font-family:'Vazirmatn';font-style:normal;font-display:swap;font-weight:100 900;src:local('Vazirmatn'),url('https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@33.003/fonts/webfonts/Vazirmatn%5Bwght%5D.woff2') format('woff2-variations')}",
    ":root{color-scheme:dark;--bg:#050b14;--card:#0d1828;--card2:#101f33;--line:#20344d;--text:#f2f7ff;--muted:#8fa5c0;--accent:#4f8cff;--accent2:#20c7a5;--good:#24c89e;--bad:#ff6680}",
    "*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0,#142c50 0,transparent 38%),radial-gradient(circle at 10% 30%,#0c2730 0,transparent 34%),var(--bg);font-family:'Vazirmatn',Tahoma,Arial,sans-serif;color:var(--text);min-height:100vh}",
    ".wrap{width:min(1180px,calc(100% - 20px));margin:16px auto}.brand{display:flex;align-items:center;gap:10px;margin-bottom:13px}.logo{display:grid;place-items:center;width:44px;height:44px;border-radius:14px;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:0 10px 28px #238cff35;font-size:21px}",
    "h1{font-size:21px;margin:0;font-weight:750}h2{font-size:18px;margin:0 0 12px;font-weight:700}h3{font-size:15px;margin:0}.brand p{margin:3px 0 0;color:var(--muted);font-size:12px}",
    ".card{background:linear-gradient(145deg,#101e31ed,#0b1625f2);border:1px solid #203752;border-radius:17px;padding:15px;box-shadow:0 14px 38px #0003;margin-bottom:11px;backdrop-filter:blur(10px)}.bot{border-color:#2a4d73}",
    ".shell{display:grid;grid-template-columns:220px minmax(0,1fr);gap:12px;align-items:start}.sidebar{position:sticky;top:12px;background:linear-gradient(160deg,#0d1c30f2,#091422f2);border:1px solid var(--line);border-radius:17px;padding:10px}.side-title{font-size:11px;color:var(--muted);margin:7px 8px}.nav{display:flex;flex-direction:column;gap:4px}.nav a,.botlink{display:block;color:#cfe3f8;text-decoration:none;padding:8px 10px;border-radius:10px}.nav a:hover,.nav a.active,.botlink:hover{background:linear-gradient(90deg,#244f80,#173a55);color:white}.botlinks{border-top:1px solid var(--line);margin-top:9px;padding-top:8px}.main{min-width:0}.tabs{display:flex;gap:6px;overflow-x:auto;margin-bottom:10px;padding-bottom:2px;scrollbar-width:none}.tab{white-space:nowrap;color:#b9cce2;text-decoration:none;background:#0e1d30;border:1px solid var(--line);border-radius:999px;padding:7px 11px;font-size:12px}.tab.active{background:linear-gradient(135deg,var(--accent),#3474db);color:white;border-color:#639aff;box-shadow:0 6px 18px #357eed35}",
    ".pagehead{display:flex;justify-content:space-between;gap:10px;align-items:center;margin-bottom:10px}.btn{display:inline-flex;align-items:center;justify-content:center;text-decoration:none;border-radius:11px;padding:9px 13px;background:linear-gradient(135deg,var(--accent),#3778df);color:white;font-weight:650;box-shadow:0 7px 18px #347ee52b}.btn.secondary{background:#1b304a;box-shadow:none}.bothead{display:flex;justify-content:space-between;gap:10px;align-items:flex-start;margin-bottom:11px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}.full{grid-column:1/-1}",
    "label{display:block;color:#c8d8eb;font-size:12px;margin:0 0 5px}input,textarea,select{width:100%;border:1px solid #223a57;background:#071321;color:var(--text);border-radius:10px;padding:9px 11px;font:inherit;outline:none}input:focus,textarea:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px #4f8cff20}textarea{min-height:76px;resize:vertical}",
    ".hint{color:var(--muted);font-size:11px;line-height:1.75;margin:4px 0 0}.check{display:flex;gap:7px;align-items:center}.check input{width:auto;accent-color:var(--accent)}button{border:0;border-radius:11px;padding:9px 13px;background:linear-gradient(135deg,var(--accent),#3778df);color:white;font:inherit;font-weight:650;cursor:pointer;box-shadow:0 7px 18px #347ee52b}.secondary{background:#1b304a;box-shadow:none}.danger{background:linear-gradient(135deg,#7a2b3c,#5e2230);box-shadow:none}",
    ".actions{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}.actions form{margin:0}.status{display:grid;grid-template-columns:repeat(4,1fr);gap:7px}.stat{background:#071422;border:1px solid var(--line);padding:9px;border-radius:11px}.stat b{display:block;margin-top:3px;font-size:12px;word-break:break-word}.muted{color:var(--muted)}",
    ".notice{padding:13px 15px;border-radius:12px;margin-bottom:16px;background:#123b33;border:1px solid #1b6a58}.warning{padding:13px 15px;border-radius:12px;margin-bottom:16px;background:#453714;border:1px solid #745f25;color:#ffe29a}.pill{display:inline-flex;padding:4px 9px;border-radius:999px;background:#174438;color:#8ef0d2;font-size:12px}.pill.off{background:#46232e;color:#ffb1bf}.divider{height:1px;background:var(--line);margin:18px 0}.rule{background:#0a1728;border:1px solid var(--line);border-radius:15px;padding:14px;margin-top:12px}",
    ".filters .filter-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}.filters .wide{grid-column:span 2}.chat-card{padding:7px}.chat-stream{display:flex;flex-direction:column;gap:5px;background:linear-gradient(180deg,#06111e,#081726);border:1px solid #152b43;border-radius:13px;padding:10px 34px;min-height:180px}.bubble{position:relative;width:fit-content;max-width:min(76%,680px);border:1px solid var(--line);border-radius:14px;padding:8px 10px;box-shadow:0 7px 18px #0002}.bubble.incoming{margin-right:auto;background:linear-gradient(145deg,#132741,#102138);border-bottom-left-radius:4px}.bubble.outgoing{margin-left:auto;background:linear-gradient(145deg,#14513f,#123d33);border-color:#26705b;border-bottom-right-radius:4px}.message-select{position:absolute;top:50%;right:-27px;transform:translateY(-50%);display:grid;place-items:center;margin:0}.bubble.outgoing .message-select{right:auto;left:-27px}.message-select input{width:17px;height:17px;margin:0;accent-color:var(--accent);cursor:pointer}.bubble-head{display:flex;gap:7px;align-items:center;justify-content:space-between;color:#83c4ff;font-size:11px;margin-bottom:3px}.bubble.outgoing .bubble-head{color:#86edcf}.bubble-text{white-space:normal;overflow-wrap:anywhere;line-height:1.65;font-size:13px}.bubble-meta{display:flex;gap:7px;justify-content:flex-end;color:var(--muted);font-size:9px;margin-top:3px}.day{align-self:center;background:#182e48cc;border:1px solid #294761;color:#d2e7ff;border-radius:999px;padding:3px 9px;font-size:10px;margin:4px 0}.last-message{display:block;line-height:1.6}.last-message small{display:block;color:var(--muted);font-weight:normal}.pager{display:flex;gap:8px;align-items:center;justify-content:center;margin:10px 0}.page-number{color:var(--muted);font-size:11px}.bulk-bar{display:flex;justify-content:space-between;gap:10px;align-items:center;padding:8px 3px 1px}.bulk-bar .check{font-size:11px;color:#ffb1bf}.privacy-note{margin-bottom:9px;padding:8px 10px;border-radius:10px;background:#14304a;color:#b9d9f4;font-size:11px}.source-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;margin-bottom:10px}.source{background:#081624;border:1px solid var(--line);border-radius:13px;padding:10px}.source h3{margin-bottom:4px}.source .actions{margin-top:7px}.source .actions button{width:100%}.log-warning{width:100%;color:#ffcf8a;font-size:10px;align-items:flex-start}",
    ".login{width:min(430px,calc(100% - 28px));margin:14vh auto}.login button{width:100%;margin-top:14px}.foot{color:var(--muted);text-align:center;font-size:11px;margin-top:16px}.empty{padding:15px;border:1px dashed var(--line);border-radius:12px;color:var(--muted)}",
    "@media(max-width:760px){.shell{display:block}.sidebar{display:none}.grid,.status,.source-grid,.filters .filter-grid{grid-template-columns:1fr}.filters .wide{grid-column:auto}.full{grid-column:auto}.wrap{width:calc(100% - 10px);margin:7px auto}.brand{margin:5px 3px 9px}.brand p{display:none}.logo{width:38px;height:38px;border-radius:12px}.card{padding:11px;border-radius:14px;margin-bottom:8px}.pagehead{display:flex;align-items:center;margin:0 2px 8px}.pagehead h2{margin-bottom:2px}.bothead{margin-bottom:8px}.bothead .pill,.pagehead .btn{margin-top:0}.tabs{margin-bottom:8px}.tab{padding:6px 10px}.actions button,.actions .btn{width:100%}.actions form{flex:1 1 100%}.chat-card{padding:5px}.chat-stream{gap:4px;padding:8px 30px;min-height:150px}.bubble{max-width:84%;padding:7px 9px;border-radius:13px}.bubble-text{font-size:12px;line-height:1.55}.bubble-head{font-size:10px}.message-select{right:-24px}.bubble.outgoing .message-select{left:-24px}.message-select input{width:16px;height:16px}.day{margin:2px 0;padding:2px 8px}.privacy-note{margin-bottom:7px;padding:7px 9px}.bulk-bar{display:block;padding-top:7px}.bulk-bar button{width:100%;margin-top:7px}.filters .filter-grid{gap:7px}.source{padding:9px}}",
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

function adminPage(state, statuses, notice, csrfToken, activeTab, selectedBotId, messagePage, messageFilters) {
  const csrf = csrfInput(csrfToken);
  const selectedBot = state.bots.find(function (bot) { return bot.id === selectedBotId; })
    || state.bots[0] || null;
  const section = ["bot-new", "bot-edit"].includes(activeTab) ? "bots"
    : ["sender-new"].includes(activeTab) ? "senders"
    : ["rule-new"].includes(activeTab) ? "rules"
    : activeTab;
  const tabs = [
    ["overview", "نمای کلی"],
    ["messages", "پیام‌ها"],
    ["bots", "بات‌ها"],
    ["senders", "فرستنده‌ها"],
    ["rules", "هشدارها"],
    ["guide", "راهنما"],
  ].map(function (item) {
    const botPart = selectedBot && item[0] === "rules" ? "&bot=" + encodeURIComponent(selectedBot.id) : "";
    return "<a class='tab" + (section === item[0] ? " active" : "") + "' href='/admin?tab="
      + item[0] + botPart + "'>" + item[1] + "</a>";
  }).join("");
  const sidebarBots = state.bots.map(function (bot) {
    return "<a class='botlink' href='/admin?tab=rules&bot=" + encodeURIComponent(bot.id) + "'>🤖 "
      + escapeHtml(bot.label) + "</a>";
  }).join("");
  const sidebar = "<aside class='sidebar'><div class='side-title'>دسترسی سریع</div><nav class='nav'>"
    + sideLink("overview", "⌂ نمای کلی", section)
    + sideLink("messages", "💬 پیام‌ها", section)
    + sideLink("bots", "🤖 مدیریت بات‌ها", section)
    + sideLink("senders", "👤 فرستنده‌ها", section)
    + sideLink("rules", "🔔 هشدارها", section, selectedBot)
    + sideLink("guide", "؟ راهنما", section)
    + "</nav><div class='botlinks'><div class='side-title'>بات‌ها</div>"
    + (sidebarBots || "<div class='hint'>هنوز باتی نیست</div>") + "</div>"
    + "<form method='post' action='/logout' class='actions'>" + csrf
    + "<button class='secondary' type='submit'>خروج</button></form></aside>";
  const content = renderTab(activeTab, state, selectedBot, statuses, csrf, messagePage, messageFilters);
  const page = "<main class='wrap'><div class='brand'><div class='logo'>🔔</div><div>"
    + "<h1>پنل هشدار تلگرام</h1><p>چند بات، چند فرستنده و چند فیلتر مستقل</p></div></div>"
    + "<div class='tabs'>" + tabs + "</div>"
    + (notice ? "<div class='notice'>" + escapeHtml(notice) + "</div>" : "")
    + "<div class='shell'>" + sidebar + "<section class='main'>" + content + "</section></div></main>";
  return layout("پنل هشدار تلگرام", page);
}

function sideLink(tab, label, activeSection, bot) {
  const botPart = bot ? "&bot=" + encodeURIComponent(bot.id) : "";
  return "<a class='" + (activeSection === tab ? "active" : "") + "' href='/admin?tab=" + tab + botPart + "'>"
    + label + "</a>";
}

function renderTab(activeTab, state, bot, statuses, csrf, messagePage, messageFilters) {
  if (activeTab === "bot-new") {
    return pageHeader("افزودن بات جدید", "", "/admin?tab=bots", "بازگشت")
      + "<section class='card'>" + botForm(null, csrf) + "</section>";
  }
  if (activeTab === "bot-edit") {
    if (!bot) return emptyBots();
    return pageHeader("ویرایش " + bot.label, "", "/admin?tab=bots", "بازگشت")
      + "<section class='card'>" + botForm(bot, csrf)
      + "<div class='divider'></div><div class='actions'>"
      + actionForm("/admin/bot/test", bot.id, csrf, "پیام آزمایشی", "secondary")
      + actionForm("/admin/bot/disable", bot.id, csrf, "غیرفعال‌کردن وب‌هوک", "danger")
      + actionForm("/admin/bot/delete", bot.id, csrf, "حذف کامل بات", "danger")
      + "</div></section>";
  }
  if (activeTab === "sender-new") {
    return pageHeader("افزودن فرستنده مشترک", "این فرستنده در هشدارهای همه بات‌ها قابل انتخاب است", "/admin?tab=senders", "بازگشت")
      + "<section class='card'>" + senderForm(null, csrf) + "</section>";
  }
  if (activeTab === "rule-new") {
    if (!bot) return emptyBots();
    return pageHeader("افزودن هشدار به " + bot.label, "", "/admin?tab=rules&bot=" + encodeURIComponent(bot.id), "بازگشت")
      + "<section class='card'>" + ruleEditor(bot, state.senders, null, csrf) + "</section>";
  }
  if (activeTab === "bots") return botsTab(state, statuses, csrf);
  if (activeTab === "messages") return messagesTab(state, messagePage, messageFilters, csrf);
  if (activeTab === "senders") return sendersTab(state, csrf);
  if (activeTab === "rules") return rulesTab(state, bot, csrf);
  if (activeTab === "guide") return guideTab(csrf);
  return overviewTab(state, statuses, csrf);
}

function overviewTab(state, statuses, csrf) {
  const senderCount = state.senders.length;
  const ruleCount = state.bots.reduce(function (sum, bot) { return sum + bot.rules.length; }, 0);
  const connectedCount = state.bots.filter(function (bot) {
    return activeConnections(bot).length > 0 || (bot.ownerChatId && bot.connectionEnabled !== false);
  }).length;
  const cards = state.bots.map(function (bot) {
    return botSummary(bot, statuses[bot.id] || {}, csrf);
  }).join("");
  return pageHeader("نمای کلی", "وضعیت همه بات‌ها و هشدارها", "/admin?tab=bot-new", "＋ افزودن بات")
    + "<div class='status'>" + stat("بات‌ها", String(state.bots.length))
    + stat("متصل", String(connectedCount)) + stat("فرستنده‌ها", String(senderCount))
    + stat("هشدارها", String(ruleCount)) + "</div><div style='height:14px'></div>"
    + (cards || emptyBots());
}

function botsTab(state, statuses, csrf) {
  const cards = state.bots.map(function (bot) {
    return botSummary(bot, statuses[bot.id] || {}, csrf);
  }).join("");
  return pageHeader("بات‌ها", "توکن و وب‌هوک هر بات مستقل است", "/admin?tab=bot-new", "＋ افزودن بات جدید")
    + (cards || emptyBots());
}

function botSummary(bot, status, csrf) {
  const connectionCount = activeConnections(bot).length || (bot.ownerChatId && bot.connectionEnabled !== false ? 1 : 0);
  const connected = connectionCount > 0;
  const lastMessage = status.lastMessageAt
    ? "<span class='last-message'>" + escapeHtml(status.lastMessageSenderName || "ناشناس")
      + "<small>" + escapeHtml(shortText(status.lastMessageText || "پیام غیرمتنی", 80))
      + " · " + escapeHtml(formatMessageTime(status.lastMessageAt)) + "</small></span>"
    : "هنوز پیامی نرسیده";
  return "<section class='card bot'><div class='bothead'><div><h2>" + escapeHtml(bot.label) + "</h2>"
    + "<div class='hint'>@" + escapeHtml(bot.botUsername || "نامشخص") + "</div></div>"
    + "<span class='pill" + (bot.enabled ? "" : " off") + "'>" + (bot.enabled ? "فعال" : "غیرفعال") + "</span></div>"
    + "<div class='status'>"
    + stat("Chat Automation", connected ? "<span class='pill'>" + connectionCount + " اتصال</span>" : "<span class='pill off'>منتظر اتصال</span>", true)
    + stat("فرستنده‌های مشترک", "در تب فرستنده‌ها")
    + stat("هشدارها", String(bot.rules.length))
    + stat("آخرین پیام", lastMessage, true)
    + "</div><div class='actions'>"
    + "<a class='btn secondary' href='/admin?tab=bot-edit&bot=" + encodeURIComponent(bot.id) + "'>تنظیمات بات</a>"
    + "<a class='btn secondary' href='/admin?tab=sender-new'>＋ افزودن فرستنده</a>"
    + "<a class='btn' href='/admin?tab=rule-new&bot=" + encodeURIComponent(bot.id) + "'>＋ افزودن هشدار</a>"
    + "</div></section>";
}

function messagesTab(state, messagePage, filters, csrf) {
  const chronological = (messagePage.items || []).slice().reverse();
  let previousDay = "";
  const messages = chronological.map(function (message) {
    const dayKey = formatMessageDay(message.timestamp);
    const separator = dayKey !== previousDay ? "<div class='day'>" + escapeHtml(dayKey) + "</div>" : "";
    previousDay = dayKey;
    const direction = message.direction === "outgoing" ? "outgoing" : "incoming";
    const directionLabel = direction === "outgoing" ? "خروجی" : "ورودی";
    const safeText = escapeHtml(message.text || "پیام غیرمتنی").replace(/\r?\n/g, "<br>");
    return separator + "<article class='bubble " + direction + "'><label class='message-select' title='انتخاب برای حذف'><input type='checkbox' name='message_ids' aria-label='انتخاب پیام برای حذف' value='"
      + escapeHtml(String(message.databaseId)) + "'></label><div class='bubble-head'><strong>"
      + escapeHtml(message.senderName || "ناشناس") + "</strong><span>" + escapeHtml(message.botLabel || "بات")
      + "</span></div><div class='bubble-text'>" + safeText + "</div><div class='bubble-meta'><span>"
      + directionLabel + "</span><time>" + escapeHtml(formatMessageTime(message.timestamp)) + "</time></div></article>";
  }).join("");
  const previous = filters.page > 1
    ? "<a class='btn secondary' href='" + escapeHtml(messageFilterUrl(filters, filters.page - 1)) + "'>صفحه قبل</a>"
    : "";
  const next = messagePage.hasNext
    ? "<a class='btn secondary' href='" + escapeHtml(messageFilterUrl(filters, filters.page + 1)) + "'>صفحه بعد</a>"
    : "";
  const pagination = previous || next
    ? "<div class='pager'>" + previous + "<span class='page-number'>صفحه " + filters.page + "</span>" + next + "</div>"
    : "";
  const returnTo = messageFilterUrl(filters, filters.page);
  return pageHeader("پیام‌ها", "پیام‌های خوانده‌شده توسط همه بات‌ها، از قدیمی به جدید در هر صفحه", "", "")
    + "<div class='privacy-note'>تاریخچه رمزنگاری‌شده در D1 نگهداری می‌شود. اگر یک گفتگو از دو حساب به همین بات وصل است، لاگ یکی از دو سمت را خاموش کن؛ هشدار آن سمت همچنان کار می‌کند.</div>"
    + messageFiltersForm(state, filters)
    + chatSourcesPanel(messagePage.sources || [], csrf)
    + (messagePage.scanLimited ? "<div class='warning'>دامنه جستجو بسیار بزرگ بود؛ برای نتیجه دقیق‌تر بازه زمانی را محدود کن.</div>" : "")
    + (messages
      ? "<form method='post' action='/admin/message/delete' class='message-delete-form'>" + csrf
        + hidden("return_to", returnTo)
        + "<section class='card chat-card'><div class='chat-stream'>" + messages + "</div>"
        + "<div class='bulk-bar'><label class='check'><input type='checkbox' name='confirm_delete' required>حذف پیام‌ها دائمی است و قابل بازگشت نیست.</label>"
        + "<button class='danger' type='submit'>حذف یک یا چند پیام انتخاب‌شده</button></div></section></form>"
      : "<section class='card empty'>پیامی مطابق این صفحه و فیلترها پیدا نشد.</section>")
    + pagination;
}

function messageFiltersForm(state, filters) {
  const senderOptions = "<option value=''>همه فرستنده‌ها</option>" + state.senders.map(function (sender) {
    return "<option value='" + escapeHtml(sender.id) + "'" + (filters.senderRef === sender.id ? " selected" : "") + ">"
      + escapeHtml(sender.label) + "</option>";
  }).join("");
  const botOptions = "<option value=''>همه بات‌ها</option>" + state.bots.map(function (bot) {
    return "<option value='" + escapeHtml(bot.id) + "'" + (filters.botId === bot.id ? " selected" : "") + ">"
      + escapeHtml(bot.label) + "</option>";
  }).join("");
  const sizeOptions = MESSAGE_PAGE_SIZES.map(function (size) {
    return "<option value='" + size + "'" + (filters.pageSize === size ? " selected" : "") + ">" + size + " پیام</option>";
  }).join("");
  return "<section class='card filters'><h2>فیلتر و جستجو</h2><form method='get' action='/admin'>"
    + hidden("tab", "messages")
    + "<div class='filter-grid'><div class='wide'><label>جستجو در متن، نام و بات</label><input type='search' name='q' maxlength='200' value='"
    + escapeHtml(filters.query) + "' placeholder='عبارت موردنظر'></div>"
    + "<div><label>فرستنده</label><select name='sender'>" + senderOptions + "</select></div>"
    + "<div><label>بات</label><select name='message_bot'>" + botOptions + "</select></div>"
    + "<div><label>از تاریخ</label><input type='date' name='from' value='" + escapeHtml(filters.from) + "'></div>"
    + "<div><label>تا تاریخ</label><input type='date' name='to' value='" + escapeHtml(filters.to) + "'></div>"
    + "<div><label>تعداد در صفحه</label><select name='page_size'>" + sizeOptions + "</select></div></div>"
    + "<div class='actions'><button type='submit'>اعمال فیلتر</button><a class='btn secondary' href='/admin?tab=messages'>پاک‌کردن فیلترها</a></div></form></section>";
}

function messageFilterUrl(filters, page) {
  const params = new URLSearchParams({ tab: "messages", page: String(page), page_size: String(filters.pageSize) });
  if (filters.query) params.set("q", filters.query);
  if (filters.senderRef) params.set("sender", filters.senderRef);
  if (filters.botId) params.set("message_bot", filters.botId);
  if (filters.from) params.set("from", filters.from);
  if (filters.to) params.set("to", filters.to);
  return "/admin?" + params.toString();
}

function chatSourcesPanel(sources, csrf) {
  if (!sources.length) return "<section class='card empty'>پس از رسیدن اولین پیام، کلید روشن/خاموش لاگ هر سمت چت اینجا ظاهر می‌شود.</section>";
  const counts = {};
  sources.forEach(function (source) {
    counts[source.conversation_key] = (counts[source.conversation_key] || 0) + 1;
  });
  const cards = sources.map(function (source) {
    const mirrored = counts[source.conversation_key] > 1;
    return "<div class='source'><div class='bothead'><div><h3>" + escapeHtml(source.ownerName || "حساب متصل")
      + " ↔ " + escapeHtml(source.chatName || "گفتگو") + "</h3><div class='hint'>بات: "
      + escapeHtml(source.botLabel || "بات") + " · لاگ این سمت</div></div><span class='pill"
      + (source.logEnabled ? "" : " off") + "'>" + (source.logEnabled ? "فعال" : "غیرفعال") + "</span></div>"
      + (mirrored ? "<div class='hint'>دو سمت این گفتگو شناسایی شده؛ فقط یکی را فعال نگه دار.</div>" : "")
      + "<form method='post' action='/admin/chat-log/toggle' class='actions'>" + csrf
      + hidden("source_key", source.source_key)
      + (source.logEnabled ? "" : hidden("log_enabled", "on"))
      + "<label class='check log-warning'><input type='checkbox' name='confirm' required>"
      + (source.logEnabled ? "با غیرفعال‌سازی، پیام‌های جدید این سمت ذخیره نمی‌شوند؛ هشدارها فعال می‌مانند."
        : "با فعال‌سازی، پیام‌های جدید این سمت در تاریخچه ذخیره می‌شوند.") + "</label>"
      + "<button class='" + (source.logEnabled ? "danger" : "secondary") + "' type='submit'>"
      + (source.logEnabled ? "غیرفعال‌کردن لاگ این سمت" : "فعال‌کردن لاگ این سمت")
      + "</button></form></div>";
  }).join("");
  return "<section class='card'><h2>کنترل لاگ چت‌ها</h2><div class='source-grid'>" + cards + "</div></section>";
}

function sendersTab(state, csrf) {
  const senders = state.senders.map(function (sender) {
    return "<section class='card'>" + senderForm(sender, csrf)
      + "<form method='post' action='/admin/sender/delete' class='actions'>" + csrf
      + hidden("sender_id", sender.id)
      + "<button class='danger' type='submit'>حذف فرستنده و قوانین مرتبط در همه بات‌ها</button></form></section>";
  }).join("");
  return pageHeader("فرستنده‌های مشترک", "هر فرستنده در هشدارهای همه بات‌ها قابل انتخاب است",
    "/admin?tab=sender-new", "＋ افزودن فرستنده")
    + (senders || "<section class='card empty'>هنوز فرستنده‌ای ثبت نشده است.</section>");
}

function rulesTab(state, bot, csrf) {
  if (!bot) return emptyBots();
  const botPicker = botPickerTabs(state, bot, "rules");
  const rules = bot.rules.map(function (rule) {
    return "<section class='card'>" + ruleEditor(bot, state.senders, rule, csrf)
      + "<form method='post' action='/admin/rule/delete' class='actions'>" + csrf
      + hidden("bot_id", bot.id) + hidden("rule_id", rule.id)
      + "<button class='danger' type='submit'>حذف هشدار</button></form></section>";
  }).join("");
  return pageHeader("هشدارهای " + bot.label, "هر پیام می‌تواند چند هشدار منطبق را هم‌زمان اجرا کند",
    "/admin?tab=rule-new&bot=" + encodeURIComponent(bot.id), "＋ افزودن هشدار")
    + botPicker + (rules || "<section class='card empty'>هنوز هشداری تعریف نشده است.</section>");
}

function botPickerTabs(state, selectedBot, tab) {
  return "<div class='tabs'>" + state.bots.map(function (bot) {
    return "<a class='tab" + (bot.id === selectedBot.id ? " active" : "") + "' href='/admin?tab=" + tab
      + "&bot=" + encodeURIComponent(bot.id) + "'>" + escapeHtml(bot.label) + "</a>";
  }).join("") + "</div>";
}

function guideTab(csrf) {
  return pageHeader("راهنمای کامل", "از ساخت بات تا مدیریت هشدار و تاریخچه", "", "")
    + "<section class='card'><h2>۱. ساخت بات در تلگرام</h2><ol class='hint'>"
    + "<li>در تلگرام وارد @BotFather شو و دستور /newbot را بفرست.</li>"
    + "<li>یک نام و سپس username منتهی به bot انتخاب کن.</li>"
    + "<li>توکن دریافتی را محرمانه نگه دار؛ هرکس آن را داشته باشد کنترل بات را دارد.</li>"
    + "<li>در BotFather وارد Bot Settings همان بات شو و Secretary Mode را فعال کن.</li></ol></section>"
    + "<section class='card'><h2>۲. افزودن بات به پنل</h2><ol class='hint'>"
    + "<li>در تب «بات‌ها»، «افزودن بات جدید» را بزن و نام نمایشی و توکن را وارد کن.</li>"
    + "<li>پنل اعتبار توکن را بررسی و webhook اختصاصی بات را ثبت می‌کند.</li>"
    + "<li>برای ویرایش نام لازم نیست توکن را دوباره وارد کنی. فقط تغییر توکن باعث جایگزینی اتصال webhook می‌شود.</li></ol></section>"
    + "<section class='card'><h2>۳. تعریف Chat Automation</h2><ol class='hint'>"
    + "<li>در تلگرام حسابی که باید پیام‌هایش کنترل شود، Settings → Telegram Business → Chatbots یا Chat Automation را باز کن.</li>"
    + "<li>username بات را وارد و چت‌های مجاز را انتخاب کن. برای حریم خصوصی بهتر، فقط چت‌های لازم را مجاز کن.</li>"
    + "<li>پس از اتصال، وضعیت بات در نمای کلی از «منتظر اتصال» به «متصل» تغییر می‌کند.</li>"
    + "<li>اگر دو طرف یک گفتگو همین بات را متصل کنند، هر پیام از دو مسیر دیده می‌شود؛ در بخش کنترل لاگ، ثبت یکی از دو سمت را خاموش کن.</li></ol></section>"
    + "<section class='card'><h2>۴. فرستنده‌ها و هشدارها</h2><ol class='hint'>"
    + "<li>فرستنده‌ها مشترک‌اند: هر شناسه عددی را یک‌بار ثبت کن و در قوانین تمام بات‌ها انتخاب کن.</li>"
    + "<li>برای یافتن شناسه، یک پیام از آن حساب دریافت کن و نام را در صفحه پیام‌ها ببین؛ در صورت نیاز از بات‌های معتبر نمایش شناسه استفاده کن.</li>"
    + "<li>در تب «هشدارها» ابتدا بات را انتخاب کن، سپس فرستنده، نوع فیلتر و متن هشدار را تعیین کن.</li>"
    + "<li>«هر پیام» برای تمام پیام‌های فرستنده و «شامل عبارت» فقط برای متن یا کپشن دارای عبارت اجرا می‌شود.</li>"
    + "<li>فاصله تکرار جلوی ارسال پشت‌سرهم یک قانون را می‌گیرد. اگر چند قانون منطبق باشند، همه اجرا می‌شوند.</li>"
    + "<li>هشدار در چت خصوصی مالک همان اتصال و توسط همان بات ارسال می‌شود.</li></ol></section>"
    + "<section class='card'><h2>۵. پیام‌ها و کنترل لاگ</h2><ol class='hint'>"
    + "<li>پیام‌ها در D1 و محتوای آن‌ها به‌صورت رمزنگاری‌شده ذخیره می‌شود.</li>"
    + "<li>می‌توانی بر اساس تاریخ، فرستنده و بات فیلتر کنی، متن را جستجو کنی و اندازه صفحه را تغییر دهی.</li>"
    + "<li>خاموش‌کردن لاگ یک سمت فقط ذخیره تاریخچه را متوقف می‌کند و قوانین هشدار را خاموش نمی‌کند.</li>"
    + "<li>حذف موردی یا گروهی پیام‌ها دائمی است؛ قبل از حذف باید هشدار را تأیید کنی.</li></ol></section>"
    + "<section class='card'><h2>۶. عیب‌یابی سریع</h2><ul class='hint'>"
    + "<li>«منتظر اتصال»: Secretary Mode یا Chat Automation هنوز وصل نیست.</li>"
    + "<li>پیام ثبت می‌شود ولی هشدار نمی‌آید: فعال‌بودن بات، فرستنده، قانون، عبارت و فاصله تکرار را بررسی کن.</li>"
    + "<li>پیام تکراری است: همان گفتگو از دو حساب متصل شده؛ لاگ یکی از دو منبع آینه‌ای را غیرفعال کن.</li>"
    + "<li>توکن را هرگز در پیام، تصویر یا مخزن عمومی منتشر نکن؛ در صورت افشا آن را از BotFather تعویض کن.</li></ul>"
    + "<form method='post' action='/logout' class='actions'>" + csrf
    + "<button class='secondary' type='submit'>خروج از پنل</button></form></section>";
}

function pageHeader(title, subtitle, actionUrl, actionLabel) {
  return "<div class='pagehead'><div><h2>" + escapeHtml(title) + "</h2>"
    + (subtitle ? "<p class='hint'>" + escapeHtml(subtitle) + "</p>" : "") + "</div>"
    + (actionUrl ? "<a class='btn' href='" + actionUrl + "'>" + escapeHtml(actionLabel) + "</a>" : "") + "</div>";
}

function emptyBots() {
  return "<section class='card empty'>هنوز باتی وجود ندارد. از دکمه «افزودن بات» شروع کن.</section>";
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
    + "<div class='actions'><button type='submit'>" + (existing ? "ذخیره و فعال‌سازی وب‌هوک" : "افزودن بات") + "</button></div></form>";
}

function senderForm(sender, csrf) {
  const existing = Boolean(sender);
  const idSuffix = existing ? sender.id : "new_global";
  return "<form method='post' action='/admin/sender/save'>" + csrf
    + (existing ? hidden("sender_id", sender.id) : "")
    + "<div class='grid'><div><label>نام فرستنده</label><input name='label' maxlength='80' required value='"
    + escapeHtml(existing ? sender.label : "") + "' placeholder='مثلاً سرور مانیتورینگ'></div>"
    + "<div><label>شناسه عددی تلگرام</label><input name='telegram_id' inputmode='numeric' required value='"
    + escapeHtml(existing ? sender.telegramId : "") + "' placeholder='123456789'></div>"
    + "<div class='full check'><input id='sender_enabled_" + escapeHtml(idSuffix)
    + "' name='enabled' type='checkbox' " + (!existing || sender.enabled ? "checked" : "") + ">"
    + "<label for='sender_enabled_" + escapeHtml(idSuffix) + "'>این فرستنده فعال باشد</label></div></div>"
    + "<div class='actions'><button type='submit'>" + (existing ? "ذخیره فرستنده" : "افزودن فرستنده") + "</button></div></form>";
}

function ruleEditor(bot, senders, rule, csrf) {
  const existing = Boolean(rule);
  const idSuffix = existing ? rule.id : "new_" + bot.id;
  const senderRef = existing ? rule.senderRef : "*";
  const matchType = existing ? rule.matchType : "any";
  const senderOptions = "<option value='*'" + (senderRef === "*" ? " selected" : "") + ">همه فرستنده‌ها</option>"
    + senders.map(function (sender) {
      return "<option value='" + escapeHtml(sender.id) + "'" + (senderRef === sender.id ? " selected" : "") + ">"
        + escapeHtml(sender.label + " — " + sender.telegramId) + "</option>";
    }).join("");
  return "<form method='post' action='/admin/rule/save'>" + csrf + hidden("bot_id", bot.id)
    + (existing ? hidden("rule_id", rule.id) : "")
    + "<div class='grid'><div><label>فرستنده</label><select name='sender_ref'>" + senderOptions + "</select></div>"
    + "<div><label>نوع فیلتر پیام</label><select name='match_type'>"
    + "<option value='any'" + (matchType === "any" ? " selected" : "") + ">هر پیام</option>"
    + "<option value='contains'" + (matchType === "contains" ? " selected" : "") + ">شامل عبارت</option></select></div>"
    + "<div><label>عبارت موردنظر</label><input name='keyword' maxlength='200' value='"
    + escapeHtml(existing ? rule.keyword : "") + "' placeholder='فقط برای حالت شامل عبارت'>"
    + "<p class='hint'>در حالت «هر پیام» این فیلد نادیده گرفته می‌شود.</p></div>"
    + "<div><label>فاصله تکرار (ثانیه)</label><input name='cooldown_seconds' type='number' min='0' max='86400' value='"
    + escapeHtml(String(existing ? rule.cooldownSeconds : 300)) + "'></div>"
    + "<div class='full'><label>متن هشدار ارسالی</label><textarea name='alert_message' maxlength='4096' required>"
    + escapeHtml(existing ? rule.alertMessage : "سایت قطع شد") + "</textarea></div>"
    + "<div class='full check'><input id='rule_enabled_" + escapeHtml(idSuffix) + "' name='enabled' type='checkbox' "
    + (!existing || rule.enabled ? "checked" : "") + "><label for='rule_enabled_" + escapeHtml(idSuffix)
    + "'>این هشدار فعال باشد</label></div></div><div class='actions'><button type='submit'>"
    + (existing ? "ذخیره هشدار" : "افزودن هشدار") + "</button></div></form>";
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

function shortText(value, limit) {
  const clean = String(value || "").replace(/\s+/g, " ").trim();
  return clean.length > limit ? clean.slice(0, limit - 1) + "…" : clean;
}

function formatMessageTime(timestamp) {
  return new Intl.DateTimeFormat("fa-IR", {
    timeZone: DISPLAY_TIME_ZONE,
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).format(new Date(Number(timestamp) * 1000));
}

function formatMessageDay(timestamp) {
  return new Intl.DateTimeFormat("fa-IR", {
    timeZone: DISPLAY_TIME_ZONE,
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  }).format(new Date(Number(timestamp) * 1000));
}

function escapeHtml(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, function (char) {
    return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char];
  });
}
