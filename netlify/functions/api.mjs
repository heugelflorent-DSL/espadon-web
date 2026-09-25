// Espadon Web — API comptes + historique des analyses
// Stockage : Netlify Blobs (store "espadon"). Aucune vidéo n'est stockée.
// Variables d'environnement requises : ADMIN_EMAIL (super admin), SESSION_SECRET (clé de signature des sessions)
import { getStore } from "@netlify/blobs";
import { scryptSync, randomBytes, timingSafeEqual, createHmac, randomUUID } from "node:crypto";

export const config = { path: "/api/*" };

const COOKIE = "esp_session";
const SESSION_DAYS = 30;
const MAX_BODY = 300_000;          // 300 Ko max par requête
const MAX_FAILS = 5, LOCK_MIN = 10; // anti-force brute

// ---------- stockage ----------
// Production : store "espadon". Prévisualisations / branches de test : store "espadon-test" (données séparées).
const storeName = () => ((globalThis.Netlify?.context?.deploy?.context || process.env.CONTEXT || "production") === "production" ? "espadon" : "espadon-test");
const store = () => globalThis.__ESPADON_TEST_STORE__ || getStore({ name: storeName(), consistency: "strong" });
const getJSON = async k => (await store().get(k, { type: "json" })) ?? null;
const setJSON = (k, v) => store().setJSON(k, v);
const del = k => store().delete(k);

// ---------- utilitaires ----------
const env = k => (globalThis.Netlify?.env?.get?.(k)) ?? process.env[k];
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers } });
const err = (status, message) => json({ error: message }, status);
const normEmail = e => String(e || "").trim().toLowerCase();
const validEmail = e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e) && e.length <= 200;
const cleanStr = (s, n = 200) => String(s ?? "").trim().slice(0, n);

function hashPassword(pw) {
  const salt = randomBytes(16);
  const h = scryptSync(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString("hex")}$${h.toString("hex")}`;
}
function checkPassword(pw, stored) {
  const [, s, h] = String(stored || "").split("$");
  if (!s || !h) return false;
  const a = scryptSync(pw, Buffer.from(s, "hex"), 64, { N: 16384, r: 8, p: 1 });
  const b = Buffer.from(h, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
function secret() {
  const s = env("SESSION_SECRET");
  if (!s || s.length < 32) throw new Error("SESSION_SECRET manquant ou trop court");
  return s;
}
function signSession(uid, ver) {
  const exp = Date.now() + SESSION_DAYS * 864e5;
  const payload = Buffer.from(JSON.stringify({ uid, ver, exp })).toString("base64url");
  const sig = createHmac("sha256", secret()).update(payload).digest("base64url");
  return `${payload}.${sig}`;
}
function readSession(token) {
  if (!token || !token.includes(".")) return null;
  const [payload, sig] = token.split(".");
  const good = createHmac("sha256", secret()).update(payload).digest("base64url");
  if (sig.length !== good.length || !timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try { const d = JSON.parse(Buffer.from(payload, "base64url").toString()); return d.exp > Date.now() ? d : null; } catch { return null; }
}
const cookieOf = req => Object.fromEntries((req.headers.get("cookie") || "").split(";").map(c => c.trim().split("=")).filter(p => p[0]).map(([k, ...v]) => [k, v.join("=")]));
const setCookie = (token, maxAge) => `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;

const publicUser = u => ({ id: u.id, name: u.name, email: u.email, role: u.role, status: u.status, createdAt: u.createdAt, lastLogin: u.lastLogin || null });
const isAdminEmail = e => normEmail(env("ADMIN_EMAIL")) && normEmail(env("ADMIN_EMAIL")) === e;

async function currentUser(req) {
  const s = readSession(cookieOf(req)[COOKIE]);
  if (!s) return null;
  const u = await getJSON(`users/${s.uid}`);
  if (!u || u.status !== "active" || (u.sessionVer || 0) !== s.ver) return null;
  return u;
}
async function allUsers() {
  const { blobs } = await store().list({ prefix: "users/" });
  return (await Promise.all(blobs.map(b => getJSON(b.key)))).filter(Boolean);
}

// ---------- analyses ----------
// analyses/<ownerId>/<id>  : { id, ownerId, meta, marks, summary, createdAt, updatedAt }
// index/<ownerId>          : [ { id, meta résumé, summary, updatedAt } ]  (liste rapide)
const indexEntry = a => ({ id: a.id, ownerId: a.ownerId, meta: pickMeta(a.meta), summary: a.summary || {}, createdAt: a.createdAt, updatedAt: a.updatedAt });
function pickMeta(m = {}) {
  const o = {};
  for (const k of ["nageur", "competition", "date", "bassin", "distance", "nage", "tour", "rang", "couloir", "officiel", "reactOff"]) if (m[k] != null) o[k] = typeof m[k] === "string" ? cleanStr(m[k]) : m[k];
  return o;
}
function validAnalysis(b) {
  if (!b || typeof b !== "object" || typeof b.meta !== "object" || !Array.isArray(b.marks)) return "Format d'analyse invalide";
  if (b.marks.length > 20000) return "Trop de pointages";
  for (const m of b.marks) if (!m || typeof m.type !== "string" || typeof m.t !== "number" || !isFinite(m.t)) return "Pointage invalide";
  return null;
}
async function readIndex(ownerId) { return (await getJSON(`index/${ownerId}`)) || []; }
async function writeIndex(ownerId, list) { await setJSON(`index/${ownerId}`, list); }

// ---------- routeur ----------
export default async (req) => {
  try {
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/api/, "").replace(/\/+$/, "") || "/";
    const method = req.method;

    // Protection CSRF : les requêtes qui modifient doivent venir de l'appli (en-tête + JSON)
    let body = null;
    if (method !== "GET") {
      if (req.headers.get("x-espadon") !== "1") return err(403, "Requête refusée");
      const txt = await req.text();
      if (txt.length > MAX_BODY) return err(413, "Données trop volumineuses");
      if (txt) { try { body = JSON.parse(txt); } catch { return err(400, "JSON invalide"); } }
    }

    // --- inscription ---
    if (path === "/signup" && method === "POST") {
      const email = normEmail(body?.email), name = cleanStr(body?.name, 80), pw = String(body?.password || "");
      if (!validEmail(email)) return err(400, "Adresse e-mail invalide");
      if (name.length < 2) return err(400, "Indique ton nom");
      if (pw.length < 8) return err(400, "Mot de passe : 8 caractères minimum");
      if (await getJSON(`emails/${email}`)) return err(409, "Un compte existe déjà avec cette adresse");
      const admin = isAdminEmail(email);
      const u = { id: randomUUID(), email, name, pw: hashPassword(pw), role: admin ? "superadmin" : "coach", status: admin ? "active" : "pending", createdAt: new Date().toISOString(), fails: 0, lockUntil: 0, sessionVer: 0 };
      await setJSON(`users/${u.id}`, u);
      await setJSON(`emails/${email}`, { id: u.id });
      return json({ ok: true, status: u.status, message: admin ? "Compte super admin créé, tu peux te connecter." : "Demande envoyée. Ton compte sera actif après validation." }, 201);
    }

    // --- connexion ---
    if (path === "/login" && method === "POST") {
      const email = normEmail(body?.email), pw = String(body?.password || "");
      const ref = await getJSON(`emails/${email}`);
      const u = ref && await getJSON(`users/${ref.id}`);
      const generic = err(401, "E-mail ou mot de passe incorrect");
      if (!u) { hashPassword(pw); return generic; } // temps constant approximatif
      if (u.lockUntil > Date.now()) return err(429, "Trop d'essais. Réessaie dans quelques minutes.");
      if (!checkPassword(pw, u.pw)) {
        u.fails = (u.fails || 0) + 1;
        if (u.fails >= MAX_FAILS) { u.fails = 0; u.lockUntil = Date.now() + LOCK_MIN * 6e4; }
        await setJSON(`users/${u.id}`, u);
        return generic;
      }
      if (isAdminEmail(u.email) && u.status === "pending") { u.status = "active"; u.role = "superadmin"; }
      if (u.status === "pending") return err(403, "Ton compte attend la validation de l'administrateur.");
      if (u.status !== "active") return err(403, "Ce compte est désactivé.");
      if (isAdminEmail(u.email) && u.role !== "superadmin") u.role = "superadmin";
      u.fails = 0; u.lockUntil = 0; u.lastLogin = new Date().toISOString();
      await setJSON(`users/${u.id}`, u);
      return json({ user: publicUser(u) }, 200, { "set-cookie": setCookie(signSession(u.id, u.sessionVer || 0), SESSION_DAYS * 86400) });
    }

    if (path === "/logout" && method === "POST") return json({ ok: true }, 200, { "set-cookie": setCookie("", 0) });

    // --- routes connectées ---
    const me = await currentUser(req);
    if (!me) return err(401, "Connexion requise");
    const isAdmin = me.role === "superadmin";

    if (path === "/me" && method === "GET") return json({ user: publicUser(me) });

    if (path === "/password" && method === "POST") {
      if (!checkPassword(String(body?.current || ""), me.pw)) return err(400, "Mot de passe actuel incorrect");
      const pw = String(body?.password || "");
      if (pw.length < 8) return err(400, "Mot de passe : 8 caractères minimum");
      me.pw = hashPassword(pw); me.sessionVer = (me.sessionVer || 0) + 1;
      await setJSON(`users/${me.id}`, me);
      return json({ ok: true }, 200, { "set-cookie": setCookie(signSession(me.id, me.sessionVer), SESSION_DAYS * 86400) });
    }

    // liste des analyses (résumés) : les siennes ; super admin : toutes, ou celles d'un entraîneur (?owner=)
    if (path === "/analyses" && method === "GET") {
      if (!isAdmin) return json({ analyses: await readIndex(me.id) });
      const owner = url.searchParams.get("owner");
      const users = await allUsers();
      const names = Object.fromEntries(users.map(u => [u.id, u.name]));
      const owners = owner ? [owner] : users.map(u => u.id);
      const lists = await Promise.all(owners.map(readIndex));
      return json({ analyses: lists.flat().map(a => ({ ...a, ownerName: names[a.ownerId] || "?" })) });
    }

    const m = path.match(/^\/analyses(?:\/([0-9a-f-]{36}))?$/);
    if (m) {
      const id = m[1];
      // retrouver l'analyse (le propriétaire est obligatoire, sauf super admin qui cherche partout)
      const find = async () => {
        let a = await getJSON(`analyses/${me.id}/${id}`);
        if (!a && isAdmin) { for (const u of await allUsers()) { a = await getJSON(`analyses/${u.id}/${id}`); if (a) break; } }
        return a;
      };
      if (id && method === "GET") { const a = await find(); return a ? json({ analysis: a }) : err(404, "Analyse introuvable"); }
      if (id && method === "DELETE") {
        const a = await find(); if (!a) return err(404, "Analyse introuvable");
        await del(`analyses/${a.ownerId}/${a.id}`);
        await writeIndex(a.ownerId, (await readIndex(a.ownerId)).filter(x => x.id !== a.id));
        return json({ ok: true });
      }
      if (method === "POST") { // création (sans id) ou mise à jour (avec id)
        const bad = validAnalysis(body); if (bad) return err(400, bad);
        const now = new Date().toISOString();
        let a;
        if (id) { a = await find(); if (!a) return err(404, "Analyse introuvable"); }
        else a = { id: randomUUID(), ownerId: me.id, createdAt: now };
        a.meta = body.meta; a.marks = body.marks; a.summary = typeof body.summary === "object" && body.summary ? body.summary : {}; a.updatedAt = now;
        await setJSON(`analyses/${a.ownerId}/${a.id}`, a);
        const idx = (await readIndex(a.ownerId)).filter(x => x.id !== a.id); idx.unshift(indexEntry(a));
        await writeIndex(a.ownerId, idx);
        return json({ analysis: indexEntry(a) }, id ? 200 : 201);
      }
    }

    // --- administration (super admin uniquement) ---
    if (path.startsWith("/admin")) {
      if (!isAdmin) return err(403, "Réservé à l'administrateur");
      if (path === "/admin/users" && method === "GET") {
        const users = await allUsers();
        const counts = Object.fromEntries(await Promise.all(users.map(async u => [u.id, (await readIndex(u.id)).length])));
        return json({ users: users.map(u => ({ ...publicUser(u), analyses: counts[u.id] })).sort((a, b) => (a.status === "pending" ? -1 : 0) - (b.status === "pending" ? -1 : 0) || a.name.localeCompare(b.name)) });
      }
      const um = path.match(/^\/admin\/users\/([0-9a-f-]{36})$/);
      if (um && method === "POST") {
        const u = await getJSON(`users/${um[1]}`); if (!u) return err(404, "Compte introuvable");
        if (u.id === me.id && body?.status && body.status !== "active") return err(400, "Tu ne peux pas désactiver ton propre compte");
        let temp = null;
        if (body?.status && ["active", "disabled", "pending"].includes(body.status)) { u.status = body.status; if (u.status !== "active") u.sessionVer = (u.sessionVer || 0) + 1; }
        if (body?.role && ["coach", "superadmin"].includes(body.role) && u.id !== me.id) u.role = body.role;
        if (body?.resetPassword) { temp = randomBytes(6).toString("base64url"); u.pw = hashPassword(temp); u.sessionVer = (u.sessionVer || 0) + 1; u.fails = 0; u.lockUntil = 0; }
        await setJSON(`users/${u.id}`, u);
        return json({ user: publicUser(u), tempPassword: temp });
      }
    }

    return err(404, "Route inconnue");
  } catch (e) {
    console.error(e);
    return err(500, "Erreur serveur");
  }
};
