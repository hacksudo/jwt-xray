/* Hacksudo JWT X-Ray - content_script.js */

function looksLikeJwt(s) {
  if (!s || typeof s !== "string") return false;
  const parts = s.split(".");
  if (parts.length !== 3) return false;
  return parts.every(p => /^[A-Za-z0-9_-]+$/.test(p) && p.length > 5);
}

function scanStorage() {
  const found = [];
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      const v = localStorage.getItem(k);
      if (looksLikeJwt(v)) found.push({ where: "localStorage", key: k, token: v });
    }
  } catch {}

  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const k = sessionStorage.key(i);
      const v = sessionStorage.getItem(k);
      if (looksLikeJwt(v)) found.push({ where: "sessionStorage", key: k, token: v });
    }
  } catch {}

  try {
    const cookies = document.cookie.split(";").map(x => x.trim()).filter(Boolean);
    for (const c of cookies) {
      const eq = c.indexOf("=");
      if (eq <= 0) continue;
      const k = c.slice(0, eq).trim();
      const v = c.slice(eq + 1).trim();
      if (looksLikeJwt(v)) found.push({ where: "document.cookie", key: k, token: v });
    }
  } catch {}

  return found;
}

async function report(found) {
  if (!found.length) return;
  const url = location.href;
  for (const f of found.slice(0, 5)) {
    await browser.runtime.sendMessage({
      type: "HX_ADD_HISTORY",
      entry: { token: f.token, source: `${f.where}:${f.key}`, url }
    }).catch(() => {});
  }
}

(async function boot() {
  report(scanStorage());

  let lastHref = location.href;
  setInterval(() => {
    if (location.href !== lastHref) {
      lastHref = location.href;
      report(scanStorage());
    }
  }, 2000);
})();
