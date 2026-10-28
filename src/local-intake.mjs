import { randomBytes, timingSafeEqual } from "node:crypto";
import { createHttpServer } from "@red-cup-engineering/http-services-section/node-server";
import { readJsonBody, BodyReadError } from "@red-cup-engineering/http-services-section/body";

// This is temporary custody intake. Saving a key does not authenticate its provider or activate a service.
export async function startLocalCredentialIntake({ store, id, metadata, title = "Service access setup",
  instructions = "", providerUrl, pattern, ttlMs = 900000 }) {
  if (!store || typeof store.record !== "function" || typeof store.requests !== "function" || typeof store.put !== "function"
      || store.record(id) || store.requests().findLast(r => r.id === id)?.state !== "requested"
      || !metadata?.holders?.length || metadata.holders.some(h => !Object.hasOwn(store.recipients().hosts, h))
      || !(pattern instanceof RegExp) || /[gy]/u.test(pattern.flags)
      || !Number.isSafeInteger(ttlMs) || ttlMs < 1 || ttlMs > 900000)
    throw new TypeError("A missing requested credential, registered holders and bounded intake policy are required");
  if (providerUrl !== undefined) {
    const u = new URL(providerUrl);
    if (u.protocol !== "https:" || u.username || u.password) throw new TypeError("Provider link must use HTTPS");
  }
  const fields = structuredClone(metadata), details = Object.freeze({ id, title, instructions, providerUrl });
  const token = randomBytes(32).toString("base64url"), tokenBytes = Buffer.from("Bearer " + token);
  let busy = false, settled = false, expired = false, cancelled = false, timer, origin, authority, resolveCompleted;
  const completed = new Promise(resolve => { resolveCompleted = resolve; });
  const finish = async result => {
    if (settled) return completed;
    settled = true; clearTimeout(timer);
    try { await server.closeGracefully(1000); resolveCompleted(result); }
    catch { resolveCompleted({ ...result, shutdown: "failed" }); }
    return completed;
  };
  const authorized = req => {
    const candidate = Buffer.from(req.headers.authorization ?? "");
    return candidate.length === tokenBytes.length && timingSafeEqual(candidate, tokenBytes);
  };
  const server = createHttpServer({ handle: (req, res) => {
    const nonce = randomBytes(16).toString("base64");
    const headers = { "cache-control": "no-store", "referrer-policy": "no-referrer",
      "x-content-type-options": "nosniff", "cross-origin-resource-policy": "same-origin",
      "content-security-policy": "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" };
    const send = (status, value) => res.writeHead(status, { ...headers, "content-type": "application/json" }).end(JSON.stringify(value));
    void (async () => {
      if (req.headers.host !== authority) return send(403, { error: "host-refused" });
      if (expired || cancelled || settled) return send(410, { error: "setup-closed" });
      if (req.url === "/" && req.method === "GET") {
        const html = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Service access setup</title>
<style>body{font:17px/1.6 system-ui;max-width:42rem;margin:4rem auto;padding:1rem;background:#f5f3ee;color:#202824}label,input,button{display:block}input{width:95%;padding:.7rem;margin:.5rem 0}button{padding:.7rem 1.2rem}pre{white-space:pre-wrap;font:inherit}#status{min-height:2em}</style>
<h1 id="title">Service access setup</h1><pre id="instructions"></pre><p><a id="provider" target="_blank" rel="noreferrer noopener" hidden>Open provider settings</a></p>
<form id="setup"><label for="value">Restricted service API key</label><input id="value" type="password" autocomplete="off" required maxlength="2048"><button id="save" disabled>Save securely</button></form><p id="status" role="status" aria-live="polite">Checking setup link…</p>
<script nonce="${nonce}">(()=>{let token=location.hash.slice(1);history.replaceState(null,"",location.pathname);const status=document.getElementById("status"),form=document.getElementById("setup"),input=document.getElementById("value"),button=document.getElementById("save");const headers={Authorization:"Bearer "+token};fetch("/details",{headers,cache:"no-store"}).then(async r=>{if(!r.ok)throw Error();const d=await r.json();document.getElementById("title").textContent=d.title;document.getElementById("instructions").textContent=d.instructions;if(d.providerUrl){const a=document.getElementById("provider");a.href=d.providerUrl;a.hidden=false}button.disabled=false;status.textContent="The key goes directly into encrypted custody on this machine. Do not enter your account password."}).catch(()=>{status.textContent="This setup link is invalid or expired."});form.addEventListener("submit",async e=>{e.preventDefault();button.disabled=true;status.textContent="Saving…";try{const r=await fetch("/credential",{method:"POST",headers:{...headers,"Content-Type":"application/json"},body:JSON.stringify({value:input.value})});input.value="";if(!r.ok)throw Error();token="";headers.Authorization="";status.textContent="Saved securely. Service verification is pending.";form.hidden=true}catch{input.value="";status.textContent="The key was not confirmed saved. Return to the agent before retrying.";}});})();</script></html>`;
        return res.writeHead(200, { ...headers, "content-type": "text/html; charset=utf-8" }).end(html);
      }
      if (!authorized(req)) return send(403, { error: "authorization-refused" });
      if (req.url === "/details") return req.method === "GET" ? send(200, details) : send(405, { error: "method-refused" });
      if (req.url !== "/credential") return send(404, { error: "not-found" });
      if (req.method !== "POST") return send(405, { error: "method-refused" });
      if (req.headers.origin !== origin) return send(403, { error: "origin-refused" });
      if ((req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase() !== "application/json"
          || req.headers["content-encoding"] && req.headers["content-encoding"] !== "identity") return send(415, { error: "media-refused" });
      if (busy || store.record(id)) return send(409, { error: "already-being-fulfilled" });
      busy = true;
      let stored = false;
      try {
        const body = await readJsonBody(req, { maxBytes: 4096, maxEncodedBytes: 4096 });
        if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).length !== 1
            || typeof body.value !== "string" || body.value.length < 1 || body.value.length > 2048 || !pattern.test(body.value))
          return send(400, { error: "invalid-credential-input" });
        if (expired || cancelled) return send(410, { error: "setup-closed" });
        if (store.record(id)) return send(409, { error: "already-fulfilled" });
        await store.put(id, body.value, fields);
        body.value = ""; stored = true;
        res.once("finish", () => { void finish({ state: "stored-unverified", id }); });
        send(201, { state: "stored-unverified", id });
      } catch (error) {
        send(error instanceof BodyReadError ? error.status : 500, { error: "credential-not-confirmed" });
      } finally {
        busy = false;
        if (!stored && (expired || cancelled)) void finish({ state: cancelled ? "cancelled" : "expired", id });
      }
    })().catch(() => { if (!res.headersSent) send(500, { error: "setup-failed" }); else res.destroy(); });
  } });
  server.requestTimeout = 15000; server.headersTimeout = 5000; server.keepAliveTimeout = 1000;
  await new Promise((resolve, reject) => { server.once("error", reject); server.listen({ host: "127.0.0.1", port: 0 }, resolve); });
  authority = "127.0.0.1:" + server.address().port; origin = "http://" + authority;
  timer = setTimeout(() => { expired = true; if (!busy) void finish({ state: "expired", id }); }, ttlMs);
  const close = () => { cancelled = true; if (!busy) void finish({ state: "cancelled", id }); return completed; };
  return Object.freeze({ origin, url: origin + "/#" + token, completed, close });
}
