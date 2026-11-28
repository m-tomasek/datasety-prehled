// Přihlášení: heslem odemkne šifrovaný balík (a.enc) a sestaví stránku. Bez hesla tu nic není.
(() => {
  const ZAKLAD = document.documentElement.dataset.z || "./", APP = document.documentElement.dataset.a || "p";
  const $ = (s) => document.querySelector(s);
  const b64 = (s) => { const t = atob(s), u = new Uint8Array(t.length); for (let i = 0; i < t.length; i++) u[i] = t.charCodeAt(i); return u; };
  const db = () => new Promise((ok, chyba) => {
    const r = indexedDB.open("z", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("klice");
    r.onsuccess = () => ok(r.result); r.onerror = () => chyba(r.error);
  });
  const cti = async (k) => { try { const d = await db(); return await new Promise((ok) => { const q = d.transaction("klice").objectStore("klice").get(k); q.onsuccess = () => ok(q.result); q.onerror = () => ok(null); }); } catch (e) { return null; } };
  const pis = async (k, v) => { try { const d = await db(); d.transaction("klice", "readwrite").objectStore("klice").put(v, k); } catch (e) { /* nic */ } };
  async function obalka() {
    let v = String(Date.now());
    try { const r = await fetch(ZAKLAD + "info.json?t=" + v, { cache: "no-store" }); if (r.ok) v = (await r.json()).vytvoreno || v; } catch (e) { /* nic */ }
    const r = await fetch(ZAKLAD + "a.enc?v=" + encodeURIComponent(v));
    if (!r.ok) throw new Error("Nedostupné (" + r.status + ").");
    return r.json();
  }
  async function otevri(o, klic) {
    const zip = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(o.iv) }, klic, b64(o.data));
    return JSON.parse(await new Response(new Blob([zip]).stream().pipeThrough(new DecompressionStream("gzip"))).text());
  }
  async function spust(balik, ul) {
    const a = balik[APP]; if (!a) throw new Error("Nedostupné.");
    window.ZAMEK = ul;
    document.title = a.t;
    for (const href of a.l) { const l = document.createElement("link"); l.rel = "stylesheet"; l.href = href; document.head.appendChild(l); }
    const st = document.createElement("style"); st.textContent = a.c; document.head.appendChild(st);
    document.body.className = ""; document.body.innerHTML = a.h;
    for (const s of a.s) {
      await new Promise((ok, chyba) => {
        const el = document.createElement("script");
        el.src = s.u || URL.createObjectURL(new Blob([s.k], { type: "text/javascript" }));
        el.onload = ok; el.onerror = chyba; document.body.appendChild(el);
      });
    }
  }
  let O = null;
  $("#f").addEventListener("submit", async (e) => {
    e.preventDefault();
    const tl = $("#f button"), ch = $("#ch"); ch.hidden = true; tl.disabled = true;
    try {
      O = O || await obalka();
      const zaklad = await crypto.subtle.importKey("raw", new TextEncoder().encode($("#h").value), "PBKDF2", false, ["deriveKey"]);
      const klic = await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: b64(O.sul), iterations: O.iter }, zaklad,
        { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
      let balik;
      try { balik = await otevri(O, klic); } catch (x) { throw new Error("Špatné heslo."); }
      const ul = { sul: O.sul, iter: O.iter, klic };
      if ($("#zap").checked) await pis("klic-v2", ul);
      await spust(balik, ul);
    } catch (x) { ch.textContent = x.message; ch.hidden = false; tl.disabled = false; }
  });
  (async () => {                                   // zapamatované zařízení: bez hesla
    try {
      const ul = await cti("klic-v2"); if (!ul) return;
      O = await obalka();
      if (ul.sul !== O.sul || ul.iter !== O.iter) return;
      await spust(await otevri(O, ul.klic), ul);
    } catch (e) { /* zůstane formulář */ }
  })();
})();
