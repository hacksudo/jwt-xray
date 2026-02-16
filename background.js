/* Hacksudo JWT X-Ray - background.js
 * Author: Vishal Waghmare (hacksudo.com)
 * For authorized testing only.
 */

const STATE_KEY = "hx_state_v1";

const defaultState = {
  enabled: true,
  history: [], // { token, source, url, ts }
  rulesEnabled: false,
  rules: []
};

async function loadState() {
  const got = await browser.storage.local.get(STATE_KEY);
  return got?.[STATE_KEY] ? { ...defaultState, ...got[STATE_KEY] } : structuredClone(defaultState);
}

async function saveState(state) {
  await browser.storage.local.set({ [STATE_KEY]: state });
}

function now() {
  return Date.now();
}

function uniqHistoryPush(history, entry, max = 50) {
  const key = `${entry.source}|${entry.url}|${entry.token}`;
  const exists = history.some(h => `${h.source}|${h.url}|${h.token}` === key);
  if (!exists) history.unshift(entry);
  if (history.length > max) history.length = max;
  return history;
}

function looksLikeJwt(s) {
  if (!s || typeof s !== "string") return false;
  const parts = s.split(".");
  if (parts.length !== 3) return false;
  return parts.every(p => /^[A-Za-z0-9_-]+$/.test(p) && p.length > 5);
}

function extractBearerToken(headers) {
  const h = headers.find(x => x.name && x.value && x.name.toLowerCase() === "authorization");
  if (!h) return null;
  const v = h.value.trim();
  const m = v.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const token = m[1].trim();
  return looksLikeJwt(token) ? token : null;
}

function urlMatches(match, url) {
  if (!match || !match.value) return false;
  const v = match.value;
  if (match.type === "contains") return url.includes(v);
  if (match.type === "startsWith") return url.startsWith(v);
  if (match.type === "regex") {
    try {
      const re = new RegExp(v);
      return re.test(url);
    } catch {
      return false;
    }
  }
  return false;
}

function findRule(state, url) {
  if (!state.rulesEnabled) return null;
  for (const r of state.rules || []) {
    if (!r.enabled) continue;
    if (urlMatches(r.match, url)) return r;
  }
  return null;
}

browser.webRequest.onBeforeSendHeaders.addListener(
  async (details) => {
    try {
      const state = await loadState();
      if (!state.enabled) return {};

      // 1) capture token
      const token = extractBearerToken(details.requestHeaders || []);
      if (token) {
        state.history = uniqHistoryPush(state.history, {
          token,
          source: "Authorization header",
          url: details.url,
          ts: now()
        });
        await saveState(state);
        browser.runtime.sendMessage({ type: "HX_TOKEN_SEEN", entry: state.history[0] }).catch(() => {});
      }

      // 2) apply safe rule-based modifications
      const rule = findRule(state, details.url);
      if (!rule) return {};

      const headers = details.requestHeaders || [];
      const action = rule.action || {};

      // Option A: set Authorization bearer literal
      if (action.setAuthBearerLiteral && action.setAuthBearerLiteral.trim()) {
        setHeader(headers, "Authorization", `Bearer ${action.setAuthBearerLiteral.trim()}`);
      }

      // Option B: set Authorization bearer from history entry timestamp
      if (action.setAuthBearerFromTokenId) {
        const entry = (state.history || []).find(h => h.ts === action.setAuthBearerFromTokenId);
        if (entry?.token) setHeader(headers, "Authorization", `Bearer ${entry.token}`);
      }

      // Option C: upsert Cookie key=value
      if (action.setCookieKV && action.setCookieKV.includes("=")) {
        const [k, ...rest] = action.setCookieKV.split("=");
        const v = rest.join("=");
        if (k && v) {
          const cookieHeader = headers.find(h => h.name.toLowerCase() === "cookie");
          if (!cookieHeader) {
            headers.push({ name: "Cookie", value: `${k.trim()}=${v.trim()}` });
          } else {
            cookieHeader.value = upsertCookieKV(cookieHeader.value, k.trim(), v.trim());
          }
        }
      }

      return { requestHeaders: headers };
    } catch {
      return {};
    }
  },
  { urls: ["<all_urls>"] },
  ["blocking", "requestHeaders"]
);

function setHeader(headers, name, value) {
  const idx = headers.findIndex(h => h.name.toLowerCase() === name.toLowerCase());
  if (idx >= 0) headers[idx].value = value;
  else headers.push({ name, value });
}

function upsertCookieKV(cookieStr, key, val) {
  const parts = cookieStr.split(";").map(s => s.trim()).filter(Boolean);
  const out = [];
  let replaced = false;
  for (const p of parts) {
    const eq = p.indexOf("=");
    if (eq <= 0) { out.push(p); continue; }
    const k = p.slice(0, eq).trim();
    if (k === key) {
      out.push(`${key}=${val}`);
      replaced = true;
    } else out.push(p);
  }
  if (!replaced) out.push(`${key}=${val}`);
  return out.join("; ");
}

browser.runtime.onMessage.addListener(async (msg) => {
  const state = await loadState();

  if (msg?.type === "HX_GET_STATE") return state;

  if (msg?.type === "HX_SET_STATE") {
    const next = { ...state, ...msg.patch };
    await saveState(next);
    return { ok: true };
  }

  if (msg?.type === "HX_ADD_HISTORY") {
    const entry = msg.entry;
    if (entry?.token && looksLikeJwt(entry.token)) {
      state.history = uniqHistoryPush(state.history, {
        token: entry.token,
        source: entry.source || "Manual",
        url: entry.url || "",
        ts: now()
      });
      await saveState(state);
      return { ok: true, entry: state.history[0] };
    }
    return { ok: false };
  }

  if (msg?.type === "HX_CLEAR_HISTORY") {
    state.history = [];
    await saveState(state);
    return { ok: true };
  }

  if (msg?.type === "HX_UPSERT_RULE") {
    const r = msg.rule;
    if (!r?.id) return { ok: false };
    const rules = Array.isArray(state.rules) ? state.rules : [];
    const i = rules.findIndex(x => x.id === r.id);
    if (i >= 0) rules[i] = r;
    else rules.unshift(r);
    state.rules = rules.slice(0, 25);
    await saveState(state);
    return { ok: true };
  }

  if (msg?.type === "HX_DELETE_RULE") {
    const id = msg.id;
    state.rules = (state.rules || []).filter(r => r.id !== id);
    await saveState(state);
    return { ok: true };
  }

  return null;
});
