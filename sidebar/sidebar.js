/* Hacksudo JWT X-Ray - sidebar.js */

const $ = (id) => document.getElementById(id);

let state = null;
let latestEntry = null;

function b64urlDecode(str) {
  const pad = "=".repeat((4 - (str.length % 4)) % 4);
  const s = (str + pad).replace(/-/g, "+").replace(/_/g, "/");
  try {
    return decodeURIComponent(Array.prototype.map.call(atob(s), c =>
      "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2)
    ).join(""));
  } catch {
    try { return atob(s); } catch { return null; }
  }
}

function b64urlEncodeBytes(bytes) {
  let bin = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  return b64;
}

function b64urlEncodeString(str) {
  const enc = new TextEncoder().encode(str);
  return b64urlEncodeBytes(enc);
}

async function hmacSign(alg, secret, data) {
  const hash = alg === "HS256" ? "SHA-256" : alg === "HS384" ? "SHA-384" : "SHA-512";
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: { name: hash } },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return b64urlEncodeBytes(sig);
}

function setBuilderStatus(msg) {
  const el = $("bStatus");
  if (el) el.textContent = msg || "";
}

function readJsonFromTextarea(id) {
  const raw = $(id).value.trim();
  if (!raw) throw new Error(`${id} is empty`);
  return JSON.parse(raw);
}

function prettyInto(id, obj) {
  $(id).value = JSON.stringify(obj, null, 2);
}

function safeJson(obj) {
  return JSON.stringify(obj, null, 2);
}

function parseJwt(token) {
  if (!token || typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts;

  const hd = b64urlDecode(h);
  const pd = b64urlDecode(p);
  if (!hd || !pd) return null;

  let header, payload;
  try { header = JSON.parse(hd); } catch { return null; }
  try { payload = JSON.parse(pd); } catch { return null; }

  return { header, payload, sig: s };
}

function looksLikeJwt(token) {
  if (!token) return false;
  const parts = token.split(".");
  return parts.length === 3 && parts.every(p => /^[A-Za-z0-9_-]*$/.test(p));
}

function tsToLocal(tsSec) {
  if (!tsSec) return "—";
  const d = new Date(tsSec * 1000);
  return d.toLocaleString();
}

function remaining(expSec) {
  if (!expSec) return "—";
  const ms = (expSec * 1000) - Date.now();
  if (ms <= 0) return "expired";
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  const mm = m % 60;
  const ss = s % 60;
  if (h > 0) return `${h}h ${mm}m ${ss}s`;
  return `${m}m ${ss}s`;
}

function analyze(jwt) {
  const issues = [];
  let level = "ok";

  const h = jwt?.header || {};
  const p = jwt?.payload || {};

  const alg = (h.alg || "").toString();
  if (!alg) issues.push({ sev: "bad", msg: "Missing header.alg" });
  if (alg.toLowerCase() === "none") issues.push({ sev: "bad", msg: "alg=none (no signature protection)" });

  if (p.exp == null) issues.push({ sev: "warn", msg: "No exp claim (token may never expire)" });
  if (p.iat == null) issues.push({ sev: "warn", msg: "No iat claim" });
  if (p.iss == null) issues.push({ sev: "warn", msg: "No iss claim" });
  if (p.aud == null) issues.push({ sev: "warn", msg: "No aud claim" });

  const sensitiveKeys = ["is_admin", "admin", "role", "roles", "scope", "permissions"];
  for (const k of sensitiveKeys) {
    if (Object.prototype.hasOwnProperty.call(p, k)) {
      issues.push({ sev: "warn", msg: `Sensitive claim present: ${k}=${String(p[k])}` });
    }
  }

  if (typeof p.exp === "number") {
    const expMs = p.exp * 1000;
    if (expMs < Date.now()) issues.push({ sev: "warn", msg: "Token is expired (exp is in the past)" });

    const farFutureDays = 30;
    const farMs = Date.now() + farFutureDays * 24 * 3600 * 1000;
    if (expMs > farMs) issues.push({ sev: "warn", msg: `exp is > ${farFutureDays} days in future (long-lived token)` });
  }

  if (issues.some(x => x.sev === "bad")) level = "bad";
  else if (issues.some(x => x.sev === "warn")) level = "warn";

  return { level, issues };
}

function setBadge(level) {
  const el = $("riskBadge");
  el.className = "badge " + (level === "bad" ? "bad" : level === "warn" ? "warn" : "ok");
  el.textContent = level === "bad" ? "CRITICAL RISK" : level === "warn" ? "MEDIUM RISK" : "LOW RISK";
}

function renderRisks(a) {
  const ul = $("riskList");
  ul.innerHTML = "";
  for (const it of a.issues) {
    const li = document.createElement("li");
    li.textContent = it.msg;
    ul.appendChild(li);
  }
  if (!a.issues.length) {
    const li = document.createElement("li");
    li.textContent = "No obvious issues detected (still verify server-side validation).";
    ul.appendChild(li);
  }
}

function renderDecode(jwt) {
  $("outHeader").textContent = jwt ? safeJson(jwt.header) : "";
  $("outPayload").textContent = jwt ? safeJson(jwt.payload) : "";
  $("outSig").textContent = jwt ? jwt.sig : "—";
}

function renderTimeline(jwt) {
  const p = jwt?.payload || {};
  $("tIat").textContent = (typeof p.iat === "number") ? `${p.iat} (${tsToLocal(p.iat)})` : "—";
  $("tExp").textContent = (typeof p.exp === "number") ? `${p.exp} (${tsToLocal(p.exp)})` : "—";
  $("tRemain").textContent = (typeof p.exp === "number") ? remaining(p.exp) : "—";
}

function renderHistory() {
  const box = $("historyList");
  box.innerHTML = "";
  const list = state?.history || [];
  if (!list.length) {
    const d = document.createElement("div");
    d.className = "hint";
    d.textContent = "No tokens yet. Open a site that uses JWT and refresh, or paste manually in Decode.";
    box.appendChild(d);
    return;
  }

  for (const h of list) {
    const el = document.createElement("div");
    el.className = "item";
    el.innerHTML = `
      <div class="itemTop">
        <div class="itemTitle">${escapeHtml(h.source || "Unknown")}</div>
        <div class="itemMeta mono">${new Date(h.ts).toLocaleTimeString()}</div>
      </div>
      <div class="itemMeta">${escapeHtml((h.url || "").slice(0, 120))}</div>
      <div class="itemToken mono">${escapeHtml(h.token)}</div>
      <div class="itemMeta mono">ts=${h.ts}</div>
    `;
    el.addEventListener("click", () => {
      $("tokenInput").value = h.token;
      latestEntry = h;
      doDecodeAndAnalyze();
      activateTab("decode");
    });
    box.appendChild(el);
  }
}

function renderRulesList() {
  const box = $("rulesList");
  box.innerHTML = "";
  const rules = state?.rules || [];
  if (!rules.length) {
    const d = document.createElement("div");
    d.className = "hint";
    d.textContent = "No rules yet. Create one above.";
    box.appendChild(d);
    return;
  }
  for (const r of rules) {
    const el = document.createElement("div");
    el.className = "item";
    el.innerHTML = `
      <div class="itemTop">
        <div class="itemTitle">${escapeHtml(r.id)}</div>
        <div class="itemMeta mono">${r.enabled ? "enabled" : "disabled"}</div>
      </div>
      <div class="itemMeta">match: ${escapeHtml(r.match?.type || "?")} → <span class="mono">${escapeHtml(r.match?.value || "")}</span></div>
      <div class="itemMeta">authLiteral: <span class="mono">${escapeHtml((r.action?.setAuthBearerLiteral || "").slice(0, 40))}</span></div>
      <div class="itemMeta">cookieKV: <span class="mono">${escapeHtml((r.action?.setCookieKV || "").slice(0, 40))}</span></div>
    `;
    el.addEventListener("click", () => fillRuleForm(r));
    box.appendChild(el);
  }
}

function fillRuleForm(r) {
  $("ruleId").value = r.id || "";
  $("ruleEnabled").value = String(!!r.enabled);
  $("ruleMatchType").value = r.match?.type || "contains";
  $("ruleMatchValue").value = r.match?.value || "";
  $("ruleAuthLiteral").value = r.action?.setAuthBearerLiteral || "";
  $("ruleAuthFromTs").value = r.action?.setAuthBearerFromTokenId ? String(r.action.setAuthBearerFromTokenId) : "";
  $("ruleCookieKV").value = r.action?.setCookieKV || "";
}

function escapeHtml(s) {
  return (s ?? "").toString()
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

// Tabs
function activateTab(name) {
  document.querySelectorAll(".tab").forEach(b => {
    b.classList.toggle("active", b.dataset.tab === name);
  });
  document.querySelectorAll(".pane").forEach(p => p.classList.remove("show"));
  $(`pane-${name}`).classList.add("show");
}
document.querySelectorAll(".tab").forEach(b => b.addEventListener("click", () => activateTab(b.dataset.tab)));

async function refreshState() {
  state = await browser.runtime.sendMessage({ type: "HX_GET_STATE" });
  $("enabled").checked = !!state.enabled;
  $("rulesEnabled").checked = !!state.rulesEnabled;
  renderHistory();
  renderRulesList();
}

async function setState(patch) {
  await browser.runtime.sendMessage({ type: "HX_SET_STATE", patch });
  await refreshState();
}

async function loadCurrentTabUrl() {
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  const t = tabs?.[0];
  $("currentUrl").textContent = t?.url || "—";
}

function doDecodeAndAnalyze() {
  const token = $("tokenInput").value.trim();
  if (!looksLikeJwt(token)) {
    renderDecode(null);
    $("riskList").innerHTML = "";
    $("riskBadge").className = "badge ok";
    $("riskBadge").textContent = "—";
    renderTimeline(null);
    return;
  }
  const jwt = parseJwt(token);
  if (!jwt) return;

  renderDecode(jwt);
  const a = analyze(jwt);
  setBadge(a.level);
  renderRisks(a);
  renderTimeline(jwt);
}

$("btnDecode").addEventListener("click", doDecodeAndAnalyze);

$("btnSaveToHistory").addEventListener("click", async () => {
  const token = $("tokenInput").value.trim();
  if (!looksLikeJwt(token)) return;
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  const url = tabs?.[0]?.url || "";
  const res = await browser.runtime.sendMessage({
    type: "HX_ADD_HISTORY",
    entry: { token, source: "Manual", url }
  });
  if (res?.ok) {
    latestEntry = res.entry;
    await refreshState();
  }
});

$("btnUseLatest").addEventListener("click", () => {
  const h = state?.history?.[0];
  if (h?.token) {
    $("tokenInput").value = h.token;
    latestEntry = h;
    doDecodeAndAnalyze();
  }
});

$("enabled").addEventListener("change", async () => {
  await setState({ enabled: $("enabled").checked });
});

$("rulesEnabled").addEventListener("change", async () => {
  await setState({ rulesEnabled: $("rulesEnabled").checked });
});

$("btnClearHistory").addEventListener("click", async () => {
  await browser.runtime.sendMessage({ type: "HX_CLEAR_HISTORY" });
  await refreshState();
});

$("btnUseLatestA").addEventListener("click", () => {
  const h = state?.history?.[0];
  if (h?.token) $("cmpA").value = h.token;
});
$("btnUseLatestB").addEventListener("click", () => {
  const h = state?.history?.[0];
  if (h?.token) $("cmpB").value = h.token;
});

function diffObjects(a, b) {
  const out = [];
  const keys = new Set([...Object.keys(a||{}), ...Object.keys(b||{})]);
  for (const k of Array.from(keys).sort()) {
    const va = a?.[k];
    const vb = b?.[k];
    const same = JSON.stringify(va) === JSON.stringify(vb);
    if (!same) out.push({ k, a: va, b: vb });
  }
  return out;
}

$("cmpA").addEventListener("input", () => compareNow());
$("cmpB").addEventListener("input", () => compareNow());

function compareNow() {
  const A = parseJwt($("cmpA").value.trim());
  const B = parseJwt($("cmpB").value.trim());
  if (!A || !B) { $("cmpOut").textContent = ""; return; }
  const diffs = diffObjects(A.payload, B.payload);
  $("cmpOut").textContent = diffs.length ? safeJson(diffs) : "No payload differences.";
}

// Rules actions
$("btnSaveRule").addEventListener("click", async () => {
  const id = $("ruleId").value.trim();
  if (!id) return;

  const rule = {
    id,
    enabled: $("ruleEnabled").value === "true",
    match: {
      type: $("ruleMatchType").value,
      value: $("ruleMatchValue").value.trim()
    },
    action: {
      setAuthBearerLiteral: $("ruleAuthLiteral").value.trim(),
      setAuthBearerFromTokenId: $("ruleAuthFromTs").value.trim() ? Number($("ruleAuthFromTs").value.trim()) : null,
      setCookieKV: $("ruleCookieKV").value.trim()
    }
  };

  await browser.runtime.sendMessage({ type: "HX_UPSERT_RULE", rule });
  await refreshState();
});

$("btnDeleteRule").addEventListener("click", async () => {
  const id = $("ruleId").value.trim();
  if (!id) return;
  await browser.runtime.sendMessage({ type: "HX_DELETE_RULE", id });
  await refreshState();
});

// --- Builder handlers ---
$("btnLoadFromDecode").addEventListener("click", () => {
  try {
    const token = $("tokenInput").value.trim();
    const jwt = parseJwt(token);
    if (!jwt) return setBuilderStatus("Decode a valid JWT first.");
    prettyInto("bHeader", jwt.header);
    prettyInto("bPayload", jwt.payload);
    const alg = (jwt.header?.alg || "none").toString();
    $("bAlg").value = ["HS256","HS384","HS512","none"].includes(alg) ? alg : "none";
    setBuilderStatus("Loaded header/payload from Decode.");
  } catch {
    setBuilderStatus("Failed to load from Decode.");
  }
});

$("btnBuildUnsigned").addEventListener("click", async () => {
  try {
    setBuilderStatus("");
    const header = readJsonFromTextarea("bHeader");
    const payload = readJsonFromTextarea("bPayload");
    header.alg = $("bAlg").value;

    const h = b64urlEncodeString(JSON.stringify(header));
    const p = b64urlEncodeString(JSON.stringify(payload));

    const token = `${h}.${p}.`;
    $("bOut").value = token;
    setBuilderStatus("Encoded (unsigned).");
  } catch (e) {
    setBuilderStatus(`Encode error: ${e.message}`);
  }
});

$("btnBuildSigned").addEventListener("click", async () => {
  try {
    setBuilderStatus("");
    const header = readJsonFromTextarea("bHeader");
    const payload = readJsonFromTextarea("bPayload");
    const alg = $("bAlg").value;

    if (alg === "none") {
      setBuilderStatus("Select HS256/HS384/HS512 to sign. For none, use Encode.");
      return;
    }

    const secret = $("bSecret").value;
    if (!secret) {
      setBuilderStatus("Secret is required for HS* signing.");
      return;
    }

    header.alg = alg;

    const h = b64urlEncodeString(JSON.stringify(header));
    const p = b64urlEncodeString(JSON.stringify(payload));
    const signingInput = `${h}.${p}`;

    const sig = await hmacSign(alg, secret, signingInput);
    const token = `${signingInput}.${sig}`;
    $("bOut").value = token;

    setBuilderStatus(`Signed & encoded (${alg}).`);
  } catch (e) {
    setBuilderStatus(`Sign error: ${e.message}`);
  }
});

$("btnUseBuiltInDecode").addEventListener("click", () => {
  const t = $("bOut").value.trim();
  if (!t) return setBuilderStatus("No output token to use.");
  $("tokenInput").value = t;
  doDecodeAndAnalyze();
  activateTab("decode");
  setBuilderStatus("Loaded output token into Decode.");
});

$("btnCopyBuilt").addEventListener("click", async () => {
  try {
    const t = $("bOut").value;
    await navigator.clipboard.writeText(t);
    setBuilderStatus("Copied to clipboard.");
  } catch {
    setBuilderStatus("Copy failed (clipboard permission).");
  }
});

$("btnSaveBuiltToHistory").addEventListener("click", async () => {
  const token = $("bOut").value.trim();
  if (!looksLikeJwt(token)) return setBuilderStatus("Output is not a valid JWT format.");
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  const url = tabs?.[0]?.url || "";
  const res = await browser.runtime.sendMessage({
    type: "HX_ADD_HISTORY",
    entry: { token, source: "Builder", url }
  });
  if (res?.ok) {
    latestEntry = res.entry;
    await refreshState();
    setBuilderStatus("Saved to history.");
  } else setBuilderStatus("Save failed.");
});

// Live updates when background sees a token
browser.runtime.onMessage.addListener(async (msg) => {
  if (msg?.type === "HX_TOKEN_SEEN") {
    latestEntry = msg.entry;
    await refreshState();
  }
});

(async function init() {
  await refreshState();
  await loadCurrentTabUrl();
  setInterval(loadCurrentTabUrl, 1200);
})();
