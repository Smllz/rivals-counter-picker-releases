// Basic Auth für die Website (Cloudflare Pages Function, gilt für alle Seiten).
// Zugangsdaten im Pages-Projekt als Secrets setzen: SITE_USER und SITE_PASS.
// Ohne gesetzte Zugangsdaten bleibt die Seite gesperrt.
export async function onRequest({ request, env, next }) {
  const user = env.SITE_USER, pass = env.SITE_PASS;
  if (!user || !pass) return text("Die Website ist noch nicht freigeschaltet.", 503);
  const h = request.headers.get("Authorization") || "";
  if (h.startsWith("Basic ")) {
    let dec = "";
    try { dec = new TextDecoder().decode(Uint8Array.from(atob(h.slice(6)), c => c.charCodeAt(0))); } catch {}
    const i = dec.indexOf(":");
    if (i > 0 && (await same(dec.slice(0, i), user)) & (await same(dec.slice(i + 1), pass))) {
      const res = await next();
      const r = new Response(res.body, res);
      r.headers.set("Cache-Control", "private, no-store");
      r.headers.set("X-Robots-Tag", "noindex, nofollow");
      return r;
    }
  }
  return text("Anmeldung erforderlich.", 401, { "WWW-Authenticate": 'Basic realm="Rivals Counter-Picker", charset="UTF-8"' });
}
function text(t, status, extra = {}) {
  return new Response(t, { status, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", ...extra } });
}
// Vergleich in konstanter Zeit (über Hashes)
async function same(a, b) {
  const enc = new TextEncoder();
  const [x, y] = await Promise.all([crypto.subtle.digest("SHA-256", enc.encode(a)), crypto.subtle.digest("SHA-256", enc.encode(b))]);
  const u = new Uint8Array(x), v = new Uint8Array(y); let d = 0;
  for (let i = 0; i < u.length; i++) d |= u[i] ^ v[i];
  return d === 0;
}
