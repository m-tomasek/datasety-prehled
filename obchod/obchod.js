"use strict";
/* Analytik příležitostí – stejná šifrovaná data jako přehled datasetů (../data.enc), jiný pohled.
   Zásada: jen to, co je v datech naměřené (počty, částky, data, zdroje). Žádné předpovědi ani váhy „od oka“;
   kde je k dispozici historie, ukáže se jako historie („v datech dosud: …“) i s velikostí vzorku.
   Nastavení a sledované položky se ukládají jen v tomto prohlížeči. */

const SOUBOR = "../data.enc";
const INFO = "../info.json";
const KONTROLA_MS = 5 * 60 * 1000;
const NA_STRANKU = 100;
const $ = (s) => document.querySelector(s);
let D = null, KLIC = null, VERZE = null, CASOVAC = null;

/* ------------------------------------------------------------------ úložiště */
const uloz = {
  cti(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  pis(k, v) { try { localStorage.setItem(k, v); return true; } catch (e) { return false; } },
  smaz(k) { try { localStorage.removeItem(k); } catch (e) { /* nic */ } },
};
// zapamatovaný klíč: neexportovatelný CryptoKey v IndexedDB (sdílený s přehledem datasetů)
const IDB = {
  db() {
    return new Promise((ok, chyba) => {
      try {
        const r = indexedDB.open("datasety-prehled", 1);
        r.onupgradeneeded = () => r.result.createObjectStore("klice");
        r.onsuccess = () => ok(r.result);
        r.onerror = () => chyba(r.error);
      } catch (e) { chyba(e); }
    });
  },
  async cti(k) {
    try { const db = await this.db(); return await new Promise((ok) => { const t = db.transaction("klice").objectStore("klice").get(k); t.onsuccess = () => ok(t.result || null); t.onerror = () => ok(null); }); }
    catch (e) { return null; }
  },
  async pis(k, v) {
    try { const db = await this.db(); await new Promise((ok, ch) => { const t = db.transaction("klice", "readwrite"); t.objectStore("klice").put(v, k); t.oncomplete = ok; t.onerror = () => ch(t.error); }); return true; }
    catch (e) { return false; }
  },
  async smaz(k) {
    try { const db = await this.db(); await new Promise((ok) => { const t = db.transaction("klice", "readwrite"); t.objectStore("klice").delete(k); t.oncomplete = ok; t.onerror = ok; }); }
    catch (e) { /* nic */ }
  },
};

/* ------------------------------------------------------------------ kryptografie */
const b64naBajty = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function stahniObalku() {
  const r = await fetch(SOUBOR + "?t=" + Date.now(), { cache: "no-store" });
  if (!r.ok) throw new Error("Data se nepodařilo stáhnout (" + r.status + ").");
  return r.json();
}
async function klicZHesla(heslo, obalka) {
  const zaklad = await crypto.subtle.importKey("raw", new TextEncoder().encode(heslo), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: b64naBajty(obalka.sul), iterations: obalka.iter },
    zaklad, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}
async function desifruj(obalka, klic) {
  const zip = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64naBajty(obalka.iv) }, klic, b64naBajty(obalka.data));
  const proud = new Blob([zip]).stream().pipeThrough(new DecompressionStream("gzip"));
  return JSON.parse(await new Response(proud).text());
}
async function otevri(data, klic) {
  if (D) return;                                 // přihlášení a automatické odemčení se mohou potkat
  D = data; KLIC = klic; VERZE = data.vytvoreno;
  $("#zamek").hidden = true; $("#aplikace").hidden = false;
  try { priprav(); vykresliVse(); }
  catch (x) { console.error(x); $("main").insertAdjacentHTML("afterbegin", `<p class="chyba">Část dat se nepodařilo zpracovat (${esc(x.message)}). Zkuste stránku obnovit.</p>`); }
  if (!CASOVAC) CASOVAC = setInterval(zkontrolujNovaData, KONTROLA_MS);
}
$("#prihlaseni").addEventListener("submit", async (e) => {
  e.preventDefault();
  const chyba = $("#chyba"), tl = e.target.querySelector("button");
  chyba.hidden = true; tl.disabled = true; tl.textContent = "Odemykám…";
  try {
    const obalka = await stahniObalku();
    const klic = await klicZHesla($("#heslo").value, obalka);
    let data;
    try { data = await desifruj(obalka, klic); } catch (x) { throw new Error("Špatné heslo."); }
    if ($("#pamatovat").checked) await IDB.pis("klic-v2", { sul: obalka.sul, iter: obalka.iter, klic });
    $("#heslo").value = "";
    await otevri(data, klic);
  } catch (x) { chyba.textContent = x.message; chyba.hidden = false; }
  finally { tl.disabled = false; tl.textContent = "Otevřít"; }
});
$("#odhlasit").addEventListener("click", async () => { await IDB.smaz("klic-v2"); uloz.smaz("prehled-klic-v1"); location.reload(); });
(async function automatickePrihlaseni() {
  try {
    const obalka = await stahniObalku();
    let ul = await IDB.cti("klic-v2");
    if (!ul) {                                   // starší způsob (přehled datasetů): surový klíč v localStorage
      const stary = uloz.cti("prehled-klic-v1");
      if (stary) {
        const { sul, k } = JSON.parse(stary);
        const klic = await crypto.subtle.importKey("raw", b64naBajty(k), "AES-GCM", false, ["decrypt"]);
        ul = { sul, iter: obalka.iter, klic };
      }
    }
    if (!ul || ul.sul !== obalka.sul || ul.iter !== obalka.iter) return;
    await otevri(await desifruj(obalka, ul.klic), ul.klic);
  } catch (x) { /* zůstane přihlašovací formulář */ }
})();
async function zkontrolujNovaData() {
  try {
    const r = await fetch(INFO + "?t=" + Date.now(), { cache: "no-store" });
    if (!r.ok) return;
    const info = await r.json();
    if (!info.vytvoreno || info.vytvoreno === VERZE) return;
    const data = await desifruj(await stahniObalku(), KLIC);
    D = data; VERZE = data.vytvoreno; priprav(); vykresliVse(true);
  } catch (x) { /* příště */ }
}

/* ------------------------------------------------------------------ pomocné */
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cislo = (n) => (n == null || n === "" || isNaN(n) ? "" : Number(n).toLocaleString("cs-CZ"));
const kc = (n) => (n == null || n === "" || isNaN(n) ? "" : Math.round(Number(n)).toLocaleString("cs-CZ") + " Kč");
const kcK = (n) => n == null || n === "" || isNaN(n) ? "" : n >= 1e6 ? (n / 1e6).toLocaleString("cs-CZ", { maximumFractionDigits: 1 }) + " mil. Kč" : Math.round(n / 1e3).toLocaleString("cs-CZ") + " tis. Kč";
const datum = (s) => { if (!s) return ""; const [r, m, d] = String(s).slice(0, 10).split("-"); return d ? `${+d}. ${+m}. ${r}` : esc(s); };
const praha = (d = new Date()) => d.toLocaleString("sv-SE", { timeZone: "Europe/Prague" });   // lhůty jsou místní čas
const iso = (d) => praha(d).slice(0, 10);
const dnes = () => iso(new Date());
const posun = (dni) => iso(new Date(Date.now() + dni * 864e5));
const zaDni = (d) => (d == null ? "" : d < 0 ? `před ${-d} dny` : d === 0 ? "dnes" : d === 1 ? "zítra" : d < 5 ? `za ${d} dny` : `za ${d} dní`);
const dniDo = (s) => (s ? Math.round((new Date(String(s).slice(0, 10)) - new Date(dnes())) / 864e5) : null);
const bezpecnaUrl = (u) => (u && /^https?:\/\//i.test(u) ? u : "");
const odkaz = (u, t) => (bezpecnaUrl(u) ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t)}</a>` : esc(t));
const median = (a) => { const b = a.filter((x) => x != null && x !== "" && !isNaN(x)).map(Number).sort((x, y) => x - y); if (!b.length) return null; const i = b.length / 2; return b.length % 2 ? b[i | 0] : (b[i - 1] + b[i]) / 2; };
const kvantil = (a, q) => { const b = a.filter((x) => x != null && x !== "" && !isNaN(x)).map(Number).sort((x, y) => x - y); return b.length ? b[Math.min(b.length - 1, Math.floor(q * (b.length - 1)))] : null; };
const seznam = (s) => String(s || "").split("; ").filter(Boolean);
const hledej = (t, ...pole) => { t = (t || "").trim().toLowerCase(); return !t || pole.some((p) => String(p || "").toLowerCase().includes(t)); };
const debounce = (fn, ms = 200) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
function napoj(ids, fn) {
  ids.forEach((id) => {
    const el = $(id); if (!el) return;
    if (el.type === "search" || el.tagName === "INPUT" && el.type !== "checkbox") el.oninput = debounce(() => fn(true));
    else el.onchange = () => fn(true);
  });
}
function stahniCsv(nazev, sloupce, radky) {
  const q = (v) => { let s = String(v ?? ""); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return /[;"\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  const text = "﻿" + sloupce.map((s) => q(s[0])).join(";") + "\r\n" + radky.map((r) => sloupce.map((s) => q(s[1](r))).join(";")).join("\r\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/csv;charset=utf-8" }));
  a.download = `${nazev}-${dnes()}.csv`; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
function stahniSoubor(nazev, obsah, typ) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([obsah], { type: typ }));
  a.download = nazev; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}
function tabulka(el, sloupce, radky, stav) {
  stav.n = stav.n || NA_STRANKU;
  if (stav.razeni) {
    const s = sloupce.find((x) => x.k === stav.razeni) || sloupce[0], hod = s.h || ((r) => r[s.k]), sm = stav.smer || 1;
    radky = [...radky].sort((a, b) => {
      const x = hod(a), y = hod(b);
      if (x == null || x === "") return 1; if (y == null || y === "") return -1;
      return (s.c ? x - y : String(x).localeCompare(String(y), "cs")) * sm;
    });
  }
  const zobraz = radky.slice(0, stav.n);
  el.innerHTML = `<thead><tr>${sloupce.map((s) => `<th data-k="${s.k}" class="${s.c ? "cis" : ""}">${esc(s.t)}${stav.razeni === s.k ? (stav.smer > 0 ? " ▲" : " ▼") : ""}</th>`).join("")}</tr></thead>
    <tbody>${zobraz.map((r) => `<tr>${sloupce.map((s) => `<td class="${s.c ? "cis" : ""}${s.sir ? " nazev-bunka" : ""}">${s.f(r)}</td>`).join("")}</tr>`).join("") || `<tr><td colspan="${sloupce.length}" class="tlumene">Nic neodpovídá filtru.</td></tr>`}</tbody>
    ${radky.length > stav.n ? `<tfoot><tr><td colspan="${sloupce.length}" class="vice"><button class="maly" data-vice>Zobrazit dalších ${NA_STRANKU} (zbývá ${cislo(radky.length - stav.n)})</button></td></tr></tfoot>` : ""}`;
  el.querySelectorAll("th").forEach((th) => th.onclick = () => {
    const s = sloupce.find((x) => x.k === th.dataset.k);
    stav.smer = stav.razeni === th.dataset.k ? -(stav.smer || 1) : (s.c ? -1 : 1);
    stav.razeni = th.dataset.k; stav.prekresli();
  });
  const v = el.querySelector("[data-vice]"); if (v) v.onclick = () => { stav.n += NA_STRANKU; stav.prekresli(); };
}
const naplnVyber = (sel, hodnoty, prvni) => {
  const el = $(sel), puv = el.value;
  el.innerHTML = `<option value="">${esc(prvni)}</option>` + hodnoty.map((h) => `<option value="${esc(h)}">${esc(h)}</option>`).join("");
  el.value = hodnoty.includes(puv) ? puv : "";
};

/* ------------------------------------------------------------------ nastavení */
const OBORY = ["projektová dokumentace", "studie", "územní plánování", "technický dozor a BOZP", "statika a průzkumy",
  "geodézie", "energetika", "TZB a instalace", "ekologie a posudky", "stavební práce", "investice do nemovitostí"];
const OBOR_RX = {
  "projektová dokumentace": /projekc|projektov|\bPD\b|\bDPS\b|\bDPZ\b|\bDUR\b|\bDSP\b|dokumentac/i,
  "studie": /studi/i,
  "územní plánování": /územní\w* plán|územní\w* studi|urbanis|parcelac|regulační plán/i,
  "technický dozor a BOZP": /\bTDI\b|\bTDS\b|technick\w* dozor|BOZP|koordinátor/i,
  "statika a průzkumy": /statik|průzkum|pasport|diagnostik/i,
  "geodézie": /geodet|geodéz|vytyč|zaměřen|geometrick/i,
  "energetika": /PENB|energetick|\bFVE\b|fotovolt|úspor/i,
  "TZB a instalace": /\bTZB\b|vytápě|\bVZT\b|elektroinst|instalac|kotel|tepeln/i,
  "ekologie a posudky": /biolog|naturov|dendrolog|hlukov|rozptylov|kompenzac|přírod|\bEIA\b|krajinn|\bÚSES\b/i,
  "stavební práce": /realizace|výběr zhotovitele|zhotovitel|stavební práce/i,
};
const VYCHOZI = { obory: [], kraje: [], ico: "" };          // prázdné = všechno (nic se nepředpokládá)
let S = (() => { try { return { ...VYCHOZI, ...JSON.parse(uloz.cti("obchod-nastaveni-v2") || "{}") }; } catch (e) { return { ...VYCHOZI }; } })();
const ulozS = () => uloz.pis("obchod-nastaveni-v2", JSON.stringify(S));
const mojeKraje = () => S.kraje.length ? S.kraje : null;
const vUzemi = (kr, filtr) => filtr ? kr === filtr : (!mojeKraje() || !kr || S.kraje.includes(kr));
const oboryZTextu = (t) => Object.entries(OBOR_RX).filter(([, rx]) => rx.test(t || "")).map(([o]) => o);
const shoda = (kat) => !S.obory.length || kat.some((k) => S.obory.includes(k));

/* ------------------------------------------------------------------ můj obchod (pipeline) */
const STAVY = [["novy", "sleduji"], ["oslovit", "oslovit"], ["osloveno", "osloveno"], ["nabidka", "nabídka podána"],
  ["vyhrano", "vyhráno"], ["prohrano", "prohráno"], ["odlozeno", "odloženo"]];
const STAV_POPIS = Object.fromEntries(STAVY.map(([k, p]) => [k, p]));
let P = (() => { try { return JSON.parse(uloz.cti("obchod-pipeline-v1") || "{}"); } catch (e) { return {}; } })();
const ulozP = () => { if (!uloz.pis("obchod-pipeline-v1", JSON.stringify(P))) alert("Uložení se nepodařilo (prohlížeč nepovoluje úložiště)."); };
function doObchodu(lead, stav) {
  const t = new Date().toISOString().slice(0, 16).replace("T", " ");
  const st = P[lead.id];
  P[lead.id] = { ...(st || { pridano: t, pozn: "", fu: "" }), stav, zmeneno: t, n: lead.n, kdo: lead.kdo, ico: lead.ico || "",
    u: lead.u || "", druh: lead.druh, kr: lead.kr || "", h: st && st.hRucne ? st.h : lead.h, hRucne: st ? st.hRucne : false, termin: lead.termin || "" };
  if (!P[lead.id].fu && (stav === "oslovit" || stav === "novy")) P[lead.id].fu = posun(2);
  ulozP();
}

/* ------------------------------------------------------------------ příprava dat */
let HIST = {}, OBJEVY = [], OBJEV = new Map();
let LEADY = [], LEAD = new Map(), UCTY = new Map(), ZAK = new Map(), CENY = {}, NABIDEK = {}, KRAJE = [], OPAK = [], SML_OD = "";
function priprav() {
  for (const k of ["zakazky", "nabidky_zak", "smlouvy", "zamery", "signaly", "tipy", "projekty", "eia"]) D[k] = D[k] || [];
  D.souvislosti = D.souvislosti || {}; for (const k of ["konkurence", "trh"]) D.souvislosti[k] = D.souvislosti[k] || [];
  D.body = D.body || { k: {}, o: {} }; D.obce_up = D.obce_up || {};
  ZAK = new Map(D.zakazky.map((z) => [z.k, z]));
  // od kdy registr smluv sbíráme souvisle: první měsíc s aspoň čtvrtinou počtu nejsilnějšího měsíce
  // (pár starších smluv zveřejněných se zpožděním pokrytí neznamená)
  const mesice = {}; for (const x of D.smlouvy) if (x.d && x.d <= dnes()) mesice[x.d.slice(0, 7)] = (mesice[x.d.slice(0, 7)] || 0) + 1;
  const maxM = Math.max(0, ...Object.values(mesice));
  const prvni = Object.keys(mesice).sort().find((m) => mesice[m] >= maxM / 4);
  SML_OD = prvni ? prvni + "-01" : "";
  KRAJE = [...new Set([...D.zakazky, ...D.smlouvy].map((x) => x.kr).filter(Boolean))].sort((a, b) => a.localeCompare(b, "cs"));
  // vítězné ceny a počty nabídek podle oboru × kraje (z vysoutěžených zakázek)
  const ceny = {}, nab = {};
  for (const z of D.zakazky) {
    for (const k of seznam(z.kat)) for (const kr of [z.kr || "?", "*"]) {
      const key = k + "|" + kr;
      if (z.cb > 0) (ceny[key] = ceny[key] || []).push(z.cb);
      if (z.pn > 0) (nab[key] = nab[key] || []).push(z.pn);
    }
  }
  CENY = Object.fromEntries(Object.entries(ceny).map(([k, v]) => [k, { med: median(v), n: v.length }]));
  NABIDEK = Object.fromEntries(Object.entries(nab).map(([k, v]) => [k, { med: median(v), jedna: v.filter((x) => x === 1).length / v.length, n: v.length }]));
  OPAK = opakovanePoptavky();
  HIST = historie();
  sestavLeady();
  sestavUcty();
  sestavObjevy();
  const st = $("#stari"); st.textContent = "data: " + datum(D.vytvoreno) + " " + String(D.vytvoreno || "").slice(11, 16);
  for (const s of ["#l-kraj", "#u-kraj", "#k-kraj", "#o-kraj"]) naplnVyber(s, KRAJE, "všechny kraje");
  naplnVyber("#o-kat", KATEGORIE_OBJEVU.filter((k) => OBJEVY.some((o) => o.kat === k)), "všechny oblasti");
  naplnTypy();
  naplnVyber("#c-kraj", KRAJE, "celá ČR");
  naplnVyber("#c-kat", OBORY.filter((o) => o !== "investice do nemovitostí"), "všechny obory");
  naplnVyber("#m-kat", OBORY.filter((o) => o !== "investice do nemovitostí"), "všechny obory");
  naplnVyber("#l-typ", [...new Set(LEADY.map((l) => l.druh))], "všechny druhy");
  naplnVyber("#p-stav", STAVY.map(([k]) => k), "všechny stavy");
  [...$("#p-stav").options].forEach((o) => { if (o.value) o.textContent = STAV_POPIS[o.value]; });
}
function zIndexu(idx, k, kr) {                 // kraj, má-li aspoň 5 případů, jinak celá ČR
  const v = idx[k + "|" + (kr || "?")];
  return v && v.n >= 5 ? { ...v, kraj: true } : idx[k + "|*"] ? { ...idx[k + "|*"], kraj: false } : null;
}
function odhadCeny(kat, kr) {
  let best = null;
  for (const k of kat) { const c = zIndexu(CENY, k, kr); if (c && c.med && (!best || c.med > best.med)) best = c; }
  return best;
}
function konkurenceOdhad(kat, kr) {
  let v = null;
  for (const k of kat) { const c = zIndexu(NABIDEK, k, kr); if (c && (v == null || c.med < v.med)) v = c; }
  return v;
}
const obecZM = (m) => !m ? "" : m[0] === "o" ? m[1] : ((D.body.k[m[1]] || [])[3] || "");
const nazevObce = (kod) => !kod ? "" : (D.obce_up[kod] && D.obce_up[kod].on) || (D.body.o[kod] || [])[2] || "";
const TYP_SIG = {
  drazba_v_obci_se_zmenou_up: "dražba v obci se změnou ÚP", drazba_parcela_v_zmene_up: "parcela ve změně ÚP", mve_na_prodej: "MVE na prodej",
  projekt_v_obci_se_zmenou_up: "inzerát v obci se změnou ÚP", pd_hotova_stavba_nevypsana: "PD hotová, stavba nevypsaná",
  stavba_bez_tdi: "stavba bez technického dozoru", zastupitelstvo_pd_bez_zakazky: "PD projednaná zastupitelstvem",
  zakazka_zrusena_zatim_nevypsana: "zrušená, zatím nevypsaná", investor_vice_staveb: "investor s více stavbami",
  kolaudace_bytoveho_domu: "kolaudace bytového domu",
};
// popisy signálů: jen co v datech je (bez odhadu, co bude)
const SIG_LEAD = {
  zakazka_zrusena_zatim_nevypsana: { druh: "zrušená zakázka", kat: null, proc: "Zakázka byla zrušena; nové vypsání stejného zadavatele zatím v datech není." },
  pd_hotova_stavba_nevypsana: { druh: "navazující poptávka", kat: ["technický dozor a BOZP", "stavební práce", "projektová dokumentace"], proc: "Zadavatel má smlouvu na projektovou dokumentaci; zakázka na stavbu od něj zatím v datech není." },
  stavba_bez_tdi: { druh: "navazující poptávka", kat: ["technický dozor a BOZP"], proc: "Stavba je vypsaná; zakázka na technický dozor od stejného zadavatele v datech není." },
  zastupitelstvo_pd_bez_zakazky: { druh: "projednáno", kat: ["projektová dokumentace", "studie"], proc: "Zastupitelstvo projednalo projektovou dokumentaci; zakázka ani smlouva na ni v datech není." },
  uzemni_studie_schvalena: { druh: "projednáno", kat: ["projektová dokumentace", "geodézie", "územní plánování", "investice do nemovitostí"], proc: "Obec schválila možnost využití územní studie." },
  uzemni_studie_zadana: { druh: "projednáno", kat: ["územní plánování", "studie"], proc: "Obec zadala územní studii." },
  eia_zamer: { druh: "záměr v řízení", kat: ["ekologie a posudky", "projektová dokumentace"], proc: "Záměr je v posuzování vlivů na životní prostředí (IS EIA)." },
  stavba_a_priroda: { druh: "záměr v řízení", kat: ["ekologie a posudky"], proc: "Stavba v katastru, kde je Natura 2000 nebo zvláště chráněné území." },
  kompenzacni_opatreni: { druh: "záměr v řízení", kat: ["ekologie a posudky"], proc: "Dokument zmiňuje kompenzační / náhradní opatření (citace v popisu)." },
  projekt_financovani: { druh: "investor", kat: ["projektová dokumentace", "technický dozor a BOZP"], proc: "Developerský projekt ve financování přes crowdfunding." },
  kolaudace_bytoveho_domu: { druh: "investor", kat: ["energetika", "TZB a instalace"], proc: "Kolaudace bytového domu." },
  investor_vice_staveb: { druh: "investor", kat: ["projektová dokumentace", "technický dozor a BOZP", "stavební práce"], proc: "Stejný investor má v datech víc staveb." },
  drazba_v_obci_se_zmenou_up: { druh: "nemovitost", kat: ["investice do nemovitostí"], proc: "Dražba / nabídka v obci, kde probíhá změna územního plánu." },
  drazba_parcela_v_zmene_up: { druh: "nemovitost", kat: ["investice do nemovitostí"], proc: "Dražená parcela je uvedená ve změně územního plánu." },
  nabidka_pod_cenou_okresu: { druh: "nemovitost", kat: ["investice do nemovitostí"], proc: "Cena za m² pod 70 % mediánu okresu." },
  mve_na_prodej: { druh: "nemovitost", kat: ["investice do nemovitostí"], proc: "Vodní elektrárna na prodej (spárovaná s licencí ERÚ)." },
  projekt_v_obci_se_zmenou_up: { druh: "nemovitost", kat: ["investice do nemovitostí"], proc: "Projekt / pozemek z inzerce v obci se změnou ÚP." },
};
function sestavLeady() {
  const L = [], ted = dnes(), d180 = posun(-180), d60 = posun(-60);
  // 1) otevřené zakázky
  for (const z of D.zakazky) {
    const lh = (z.lh || "").slice(0, 10);
    if (!lh || lh < ted || z.s === "zrušen") continue;
    const kat = seznam(z.kat), mojeKat = kat.filter((k) => S.obory.includes(k)), odh = odhadCeny(mojeKat.length ? mojeKat : kat, z.kr), konk = konkurenceOdhad(kat, z.kr);
    L.push({ id: "z:" + z.k, druh: "veřejná zakázka", n: z.c ? `${z.n} – ${z.c}` : z.n, kdo: z.zd, ico: z.zi, kr: z.kr, obec: obecZM(z.m), kat,
      h: odh ? odh.med : null, hz: odh ? `medián vítězných cen (${odh.n} vysoutěžených zakázek, ${odh.kraj ? "stejný kraj" : "celá ČR"})` : "",
      termin: lh, terminPopis: "lhůta pro nabídky " + datum(lh) + (z.lh.length > 10 ? " " + z.lh.slice(11, 16) : ""),
      konk: konk ? konk.med : null, proc: `${z.dr || "zakázka"}${z.rez ? " · " + z.rez : ""}. Lhůta ${datum(lh)}.`, u: z.u, pz: z.pz || z.dz, zdroj: z });
  }
  // 2) stavby v přípravě (investor známý)
  for (const x of D.zamery) {
    if ((x.pd || "") < d180 || !["zamer", "eia", "stanovisko", "rizeni", "povoleni"].includes(x.f)) continue;
    const kat = oboryZTextu(x.nc + " " + x.ds);
    if (!kat.length) continue;
    const proc = { zamer: "Záměr stavby", eia: "Stavba v EIA", stanovisko: "Environmentální stanovisko", rizeni: "Zahájeno řízení o povolení", povoleni: "Stavba povolena" }[x.f];
    L.push({ id: "s:" + x.k, druh: "stavba v přípravě", n: x.n, kdo: x.st === "fyzicka_osoba" ? "soukromá osoba" : x.sn, ico: x.si, kr: x.kr, obec: obecZM(x.m), kat,
      h: null, hz: "", termin: null, terminPopis: `${proc} ${datum(x.df)}`, konk: null,
      proc: `${proc} (${datum(x.df)}).` + [x.op ? ` Obestavěný prostor ${cislo(x.op)} m³.` : "", x.zp ? ` Zastavěná plocha ${cislo(x.zp)} m².` : "",
        x.pb ? ` Bytů ${x.pb}.` : "", x.nd > 1 ? ` Dokumentů k záměru: ${x.nd}.` : ""].join(""), u: "", pz: x.pd, zdroj: x });
  }
  // 3) signály z kombinací
  for (const s of D.signaly) {
    const def = SIG_LEAD[s.t];
    if (!def || (s.d || "") < d180) continue;
    const z = ZAK.get(s.k);
    let kat = def.kat || (z ? seznam(z.kat) : oboryZTextu(s.p));
    if (s.t === "zakazka_zrusena_zatim_nevypsana" && z) kat = seznam(z.kat);
    const odh = kat.length ? odhadCeny(kat.filter((k) => k !== "investice do nemovitostí"), s.kr) : null;
    const termin = null, tp = HIST[s.t] ? HIST[s.t].text : "";
    L.push({ id: "g:" + s.id, druh: def.druh, n: s.p.slice(0, 220), kdo: z ? z.zd : (s.on || ""), ico: z ? z.zi : (/^\d{8}$/.test(s.k) ? s.k : ""),
      kr: s.kr, obec: s.o, kat, h: odh && def.druh !== "nemovitost" ? odh.med : null, hz: odh ? `medián vítězných cen oboru (${odh.n} zakázek)` : "",
      termin, terminPopis: tp, konk: null, proc: def.proc, u: s.u, pz: s.pz || s.d, zdroj: s });
  }
  // 4) firmy se signály (soukromí klienti)
  for (const t of D.tipy) {
    if ((t.ps || 0) < 1) continue;
    const kat = oboryZTextu(t.po + " " + t.si);
    L.push({ id: "f:" + t.i, druh: "soukromý klient", n: t.n, kdo: t.n, ico: t.i, kr: t.kr, obec: obecZM(t.m), kat,
      h: null, hz: "", termin: null, terminPopis: "", konk: null, proc: `${t.sg} · ${t.zam || "?"} zaměstnanců. Signály: ${String(t.si || "").slice(0, 300)}`,
      u: "", pz: (String(t.si).match(/(20\d\d-\d\d-\d\d)/) || [])[1] || "", zdroj: t });
  }
  // 5) projekty z inzerce (ČR)
  for (const p of D.projekty) {
    if (p.ze !== "CZ" || !p.a || (p.pz || "") < d60) continue;
    const kat = p.sm === "nabidka" ? ["investice do nemovitostí"] : oboryZTextu(p.nc + " " + p.n);
    L.push({ id: "p:" + p.k, druh: p.sm === "financovani" ? "investor" : p.sm === "poptavka" ? "poptávka z inzerce" : "nemovitost",
      n: p.n, kdo: p.mi || "", ico: "", kr: "", obec: obecZM(p.m), kat, h: p.c && p.me !== "EUR" && p.me !== "PLN" ? p.c : null,
      hz: p.c ? "cena v inzerátu" : "", termin: null, terminPopis: "", konk: null,
      proc: `${p.sm === "nabidka" ? "Nabízí se" : p.sm === "poptavka" ? "Shání se" : "Financuje se"}: ${String(p.t || "").replace(/_/g, " ")}${p.nf ? ", fáze " + p.nf.replace(/_/g, " ") : ""}.`,
      u: p.u, pz: p.pz, zdroj: p });
  }
  for (const l of L) { if (!l.kr && l.obec) l.kr = krajObce(l.obec); }
  LEADY = L; LEAD = new Map(L.map((l) => [l.id, l]));
}
const KRAJ_OBCE = new Map();
function krajObce(kod) {
  if (!KRAJ_OBCE.size) {
    for (const x of [...D.zamery, ...D.zakazky]) { const o = obecZM(x.m); if (o && x.kr && !KRAJ_OBCE.has(o)) KRAJ_OBCE.set(o, x.kr); }
    for (const [o, v] of Object.entries(D.obce_up)) if (v.kr && !KRAJ_OBCE.has(o)) KRAJ_OBCE.set(o, v.kr);
  }
  return KRAJ_OBCE.get(kod) || "";
}
function opakovanePoptavky() {
  const slova = (t) => new Set((String(t).toLowerCase().match(/[a-zá-ž0-9]{3,}/g) || []).filter((x) => !STOP.has(x)));
  const podob = (a, b) => { let n = 0; for (const x of a) if (b.has(x)) n++; return n / Math.max(a.size, b.size, 1); };
  const podle = new Map();
  for (const z of D.zakazky) { if (!z.zi || !z.dz) continue; if (!podle.has(z.zi)) podle.set(z.zi, []); podle.get(z.zi).push(z); }
  const skup = [];
  for (const v of podle.values()) {
    v.sort((a, b) => (a.dz > b.dz ? 1 : -1));
    const gr = [];
    for (const z of v) {
      const sz = slova(z.n + " " + z.c);
      let best = null, bs = 0;
      for (const g of gr) {
        const last = g.z[g.z.length - 1];
        if ((new Date(z.dz) - new Date(last.dz)) / 864e5 > 365) continue;
        if (z.dz === last.dz && last.s !== "zrušen") continue;
        const p = podob(g.s, sz);
        if (p >= 0.7 && p > bs) { best = g; bs = p; }
      }
      if (best) best.z.push(z); else gr.push({ s: sz, z: [z] });
    }
    for (const g of gr) if (g.z.length >= 2) skup.push(g.z);
  }
  return skup.map((z) => {
    const zad = z.filter((x) => x.s === "dokončen" || x.s === "ukončeno plnění"), posl = zad[zad.length - 1];
    return { z, zd: z[0].zd, zi: z[0].zi, kr: z[0].kr, kat: seznam(z[0].kat), n: z[z.length - 1].n, pocet: z.length,
      zrus: z.filter((x) => x.s === "zrušen").length, zad: zad.length, od: z[0].dz, do: z[z.length - 1].dz,
      cena: posl ? posl.cb : null, vitez: posl ? posl.v : "", u: z[z.length - 1].u };
  }).sort((a, b) => b.pocet - a.pocet || b.zrus - a.zrus);
}
const STOP = new Set("pro na v ve s se z ze do od o u a obce města městyse obec město akce stavba stavby projektová dokumentace pd zpracování zhotovení rekonstrukce oprava opravy úpravy stavební úpravy".split(" "));

/* ------------------------------------------------------------------ historie (co se v datech už stalo) */
// Ne předpověď: kolikrát a za jak dlouho k něčemu v datech dosud došlo, s velikostí vzorku.
function historie() {
  const H = {}, hranice = posun(-30);
  // zrušené zakázky: vypsal je stejný zadavatel znovu (podobný název, do roka)?
  const dny = [];
  let zrusenych = 0, znovu = 0;
  for (const g of OPAK) g.z.forEach((z, i) => {
    if (z.s !== "zrušen" || !z.dz || z.dz > hranice) return;
    const dalsi = g.z.slice(i + 1).find((x) => x.dz > z.dz);
    if (dalsi) { znovu++; dny.push((new Date(dalsi.dz) - new Date(z.dz)) / 864e5); }
  });
  for (const z of D.zakazky) if (z.s === "zrušen" && z.dz && z.dz <= hranice) zrusenych++;
  if (zrusenych >= 10) H.zakazka_zrusena_zatim_nevypsana = {
    n: zrusenych, k: znovu, med: median(dny),
    text: `v datech dosud: ${znovu} z ${zrusenych} zrušených zakázek (starších 30 dní) stejný zadavatel znovu vypsal` + (dny.length ? `, medián ${Math.round(median(dny))} dní` : ""),
  };
  // projektová dokumentace -> vypsání stavby
  const nav = (D.souvislosti.navaznosti || []).map((x) => +x.zpozdeni_dni).filter((x) => x >= 0);
  if (nav.length >= 10) H.pd_hotova_stavba_nevypsana = {
    n: nav.length, med: median(nav),
    text: `v datech dosud: u ${nav.length} dvojic PD → stavba uplynulo od smlouvy na PD do vypsání stavby medián ${Math.round(median(nav))} dní (polovina mezi ${Math.round(kvantil(nav, 0.25))} a ${Math.round(kvantil(nav, 0.75))})`,
  };
  return H;
}

/* ------------------------------------------------------------------ objevy */
// Každý objev = kombinace naměřených faktů. Síla dokladu podle velikosti vzorku / počtu nezávislých zdrojů.
const DRUH_NAB = { aukce_stat: "aukce státu", nabidka_statni_organizace: "nabídka státní organizace", drazba_dobrovolna: "dražba dobrovolná",
  drazba_nedobrovolna: "dražba nedobrovolná", drazba_exekucni: "dražba exekuční", drazba_insolvence: "dražba v insolvenci", nabidka_stat_prodej: "prodej státu" };
const DOKLAD = (n, zdroju) => zdroju ? (zdroju >= 3 ? "silný" : zdroju === 2 ? "střední" : "malý") : (n >= 20 ? "silný" : n >= 8 ? "střední" : "malý");
const KATEGORIE_OBJEVU = ["Nemovitosti", "Trhy", "Zákazníci", "Navazující poptávka", "Území", "Inzerce"];
function sestavObjevy() {
  const O = [], ted = dnes(), r1 = posun(-365);
  const pridej = (o) => { o.kr = o.kr || (o.obec ? krajObce(o.obec) : ""); O.push(o); };
  const kdeObce = (m) => { const o = obecZM(m); return { obec: o, kde: nazevObce(o) }; };
  const obdobi = SML_OD ? `od ${datum(SML_OD)}` : "";

  // 1) nemovitosti pod cenou okresu (aktivní nabídky × ceny pozemků z historie prodejů)
  const ceny = new Map((D.souvislosti.ceny_pozemku || []).map((c) => [c.okres + "|" + c.druh_pozemku, c]));
  for (const x of D.nabidky || []) {
    if (!x.a || !(x.cm > 0) || !(x.v > 0) || x.t !== "pozemek" || /pronáj|nájem|pacht/i.test(x.n)) continue;
    const c = ceny.get(x.ok + "|" + (x.dp || "neuvedeno"));
    if (!c || +c.pocet < 5 || !(x.cm <= +c.p25_kc_m2)) continue;
    const rozdil = (+c.median_kc_m2 - x.cm) * x.v;
    pridej({ id: "o:nem:" + x.k, kat: "Nemovitosti", typ: "pod cenou okresu", n: x.n, ...kdeObce(x.m), kc: rozdil, kcPopis: "rozdíl proti mediánu okresu × výměra",
      fakta: [`${x.cm.toLocaleString("cs-CZ")} Kč/m² · ${cislo(x.v)} m² · ${kc(x.cv || x.cm * x.v)} (${esc(DRUH_NAB[x.dr] || String(x.dr || x.z).replace(/_/g, " "))})`,
        `okres ${esc(x.ok)}, ${esc(c.druh_pozemku)}: medián ${(+c.median_kc_m2).toLocaleString("cs-CZ")} Kč/m², dolní čtvrtina ${(+c.p25_kc_m2).toLocaleString("cs-CZ")} Kč/m² (${c.pocet} prodejů ${datum(c.od)} – ${datum(c.do)}, ${esc(c.zdroje)})`,
        x.du ? `ukončení ${datum(x.du)}` : "", x.pm ? "kulturní památka" : "", x.po ? `podíl ${esc(x.po)}` : ""].filter(Boolean),
      vzorek: +c.pocet, doklad: DOKLAD(+c.pocet), odkazy: [{ t: "nabídka", u: x.u }], d: x.pz });
  }
  // 2) více nezávislých zdrojů o stejné parcele / firmě
  for (const x of D.souvislosti.pruniky || []) {
    const z = +x.pocet_zdroju; if (z < 2) continue;
    pridej({ id: "o:pr:" + x.klic, kat: "Nemovitosti", typ: "shoda zdrojů", obec: x.kod_obce, kde: nazevObce(x.kod_obce),
      n: (x.klic_typ === "ico" ? "Firma IČO " + x.klic : "Parcela " + (x.klic.split(":")[1] || x.klic)) + (nazevObce(x.kod_obce) ? " – " + nazevObce(x.kod_obce) : ""),
      kc: null, fakta: [`${z} nezávislé zdroje: ${esc(x.zdroje)}`, ...String(x.detail || "").split(" | ").slice(0, 6).map(esc), `${datum(x.prvni)} – ${datum(x.posledni)}`],
      vzorek: z, doklad: DOKLAD(0, z), odkazy: [], d: x.posledni, ico: x.klic_typ === "ico" ? x.klic : "" });
  }
  // 3) nemovitostní signály
  for (const g of D.signaly) {
    if (!["drazba_v_obci_se_zmenou_up", "drazba_parcela_v_zmene_up", "mve_na_prodej", "projekt_v_obci_se_zmenou_up"].includes(g.t)) continue;
    pridej({ id: "o:sg:" + g.id, kat: "Nemovitosti", typ: TYP_SIG[g.t], n: g.p.slice(0, 160), obec: g.o, kde: g.on, kr: g.kr,
      kc: null, fakta: [esc(SIG_LEAD[g.t].proc), esc(g.p), `zdroje: ${esc(g.z)}`], vzorek: 2, doklad: "střední", odkazy: [{ t: "zdroj", u: g.u }], d: g.d });
  }
  // 4) trhy s jedinou nabídkou (vysoutěžené zakázky podle oboru × kraje)
  const bunky = new Map();
  for (const z of D.zakazky) {
    if (!z.kr || !(z.pn > 0)) continue;
    for (const k of seznam(z.kat)) {
      const key = k + "|" + z.kr; if (!bunky.has(key)) bunky.set(key, { k, kr: z.kr, z: [] });
      bunky.get(key).z.push(z);
    }
  }
  for (const b of bunky.values()) {
    const n = b.z.length, jedna = b.z.filter((z) => z.pn === 1);
    if (n < 8 || jedna.length / n < 0.35) continue;
    const vit = new Map();                         // podle IČO: „podnikající fyzická osoba“ je víc různých lidí
    for (const z of b.z) if (z.v || z.vi) { const key = z.vi || z.v, v = vit.get(key) || [z.v + (z.vi && z.v === "podnikající fyzická osoba" ? " IČO " + z.vi : ""), 0]; v[1]++; vit.set(key, v); }
    const top = [...vit.values()].sort((a, c) => c[1] - a[1]).slice(0, 3);
    const objem = b.z.reduce((s2, z) => s2 + (z.cb || 0), 0);
    pridej({ id: "o:tr1:" + b.k + "|" + b.kr, kat: "Trhy", typ: "slabá konkurence", n: `${b.k} – ${b.kr}`, kr: b.kr, kc: objem, kcPopis: "vysoutěženo celkem (bez DPH)",
      fakta: [`${jedna.length} z ${n} zakázek s počtem nabídek mělo jedinou nabídku (${Math.round(100 * jedna.length / n)} %)`,
        `medián počtu nabídek ${String(median(b.z.map((z) => z.pn))).replace(".", ",")}, medián vítězné ceny ${kcK(median(b.z.map((z) => z.cb)))}`,
        top.length ? `nejčastější vítězové: ${top.map(([v, c]) => `${esc(v)} (${c}×)`).join(", ")}` : ""].filter(Boolean),
      vzorek: n, doklad: DOKLAD(n), odkazy: [], d: b.z.reduce((m, z) => (z.dz > m ? z.dz : m), ""), trh: b.k });
  }
  // 5) koncentrované trhy (registr smluv)
  const sml = new Map();
  for (const x of D.smlouvy) {
    if (!x.kr || !x.d || x.d > ted || x.d < SML_OD) continue;
    for (const k of seznam(x.kat)) {
      const key = k + "|" + x.kr; if (!sml.has(key)) sml.set(key, { k, kr: x.kr, h: 0, n: 0, dod: new Map() });
      const b = sml.get(key); b.h += x.h || 0; b.n++;
      const dk = x.di || x.do; const d = b.dod.get(dk) || { n: x.do, ico: x.di, h: 0, c: 0 }; d.h += x.h || 0; d.c++; b.dod.set(dk, d);
    }
  }
  for (const b of sml.values()) {
    if (b.n < 10 || !b.h) continue;
    const dod = [...b.dod.values()].sort((a, c) => c.h - a.h), podil = dod[0].h / b.h;
    // dominance = opakovaně, ne jedna velká zakázka: aspoň 5 smluv a pětina všech smluv
    if (podil < 0.5 || dod[0].c < 5 || dod[0].c / b.n < 0.2) continue;
    pridej({ id: "o:tr2:" + b.k + "|" + b.kr, kat: "Trhy", typ: "jeden dominantní dodavatel", n: `${b.k} – ${b.kr}`, kr: b.kr, kc: b.h, kcPopis: `objem smluv ${obdobi}`,
      fakta: [`${b.n} smluv za ${kcK(b.h)} (${obdobi})`, `${esc(dod[0].n)} má ${Math.round(100 * podil)} % objemu (${dod[0].c} smluv)`,
        `dodavatelů celkem ${dod.length}; další: ${dod.slice(1, 4).map((d) => `${esc(d.n)} ${Math.round(100 * d.h / b.h)} %`).join(", ") || "—"}`],
      vzorek: dod[0].c, doklad: DOKLAD(dod[0].c), odkazy: [], d: "", firma: dod[0].ico, trh: b.k });
  }
  // 6) opakované poptávky
  for (const g of OPAK) {
    if (g.pocet < 3) continue;
    const ceny2 = g.z.map((z) => z.cb).filter((x) => x > 0);
    pridej({ id: "o:op:" + g.z[0].k, kat: "Zákazníci", typ: "opakovaná poptávka", n: g.n, kr: g.kr, kc: ceny2.reduce((a, b) => a + b, 0) || null, kcPopis: "součet vysoutěžených cen ve skupině",
      fakta: [`${esc(g.zd)} vypsal podobnou zakázku ${g.pocet}× (${datum(g.od)} – ${datum(g.do)}), zrušeno ${g.zrus}×, zadáno ${g.zad}×`,
        ceny2.length ? `vítězné ceny: ${ceny2.map(kcK).join(", ")}` : "",
        g.vitez ? `poslední vítěz: ${esc(g.vitez)}` : "",
        `zakázky: ${g.z.slice(-4).map((z) => `${datum(z.dz)} ${esc(z.s)}`).join("; ")}`].filter(Boolean),
      vzorek: g.pocet, doklad: g.pocet >= 5 ? "silný" : g.pocet >= 3 ? "střední" : "malý", odkazy: [{ t: "poslední vypsání", u: g.u }], d: g.do, ico: g.zi });
  }
  // 7) zákazník s jedním dodavatelem
  for (const u of UCTY.values()) {
    if (u.smluv < 5 || !u.utrata) continue;
    const d = [...u.dod.values()].sort((a, c) => c.h - a.h)[0];
    if (!d || d.h / u.utrata < 0.7 || d.c < 3 || d.c / u.smluv < 0.5) continue;   // opakovaně týž dodavatel, ne jedna velká smlouva
    pridej({ id: "o:zd:" + u.ico, kat: "Zákazníci", typ: "jeden dodavatel", n: u.n, kr: u.kr, kc: u.utrata, kcPopis: `útrata ${obdobi}`,
      fakta: [`${u.smluv} smluv za ${kcK(u.utrata)} (${obdobi})`, `${esc(d.n)}: ${Math.round(100 * d.h / u.utrata)} % objemu (${d.c} smluv)`,
        `za co: ${Object.entries(u.kat).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k, v]) => `${esc(k)} ${kcK(v)}`).join(", ")}`,
        u.otevrene ? `teď otevřených zakázek: ${u.otevrene}` : ""].filter(Boolean),
      vzorek: d.c, doklad: DOKLAD(d.c), odkazy: [], d: u.posledni, ico: u.ico });
  }
  // 8) navazující poptávka (fakt + historie)
  for (const g of D.signaly) {
    if (!["pd_hotova_stavba_nevypsana", "stavba_bez_tdi", "zastupitelstvo_pd_bez_zakazky", "zakazka_zrusena_zatim_nevypsana"].includes(g.t)) continue;
    if ((g.d || "") < posun(-365)) continue;
    const z = ZAK.get(g.k), h = HIST[g.t], zdroju = String(g.z || "").split(" + ").filter(Boolean).length;
    const cena = z && g.t === "stavba_bez_tdi" ? z.cb : null;    // u ostatních by cena patřila jiné zakázce, než o kterou jde
    pridej({ id: "o:nv:" + g.id, kat: "Navazující poptávka", typ: TYP_SIG[g.t], n: z ? (z.c ? z.n + " – " + z.c : z.n) : g.p.slice(0, 140), obec: g.o, kde: g.on, kr: g.kr,
      kc: cena || null, kcPopis: cena ? "cena vysoutěžené stavby" : "",
      fakta: [esc(SIG_LEAD[g.t].proc), esc(g.p), h ? esc(h.text) + ` (vzorek ${cislo(h.n)})` : ""].filter(Boolean),
      vzorek: zdroju, doklad: DOKLAD(0, zdroju), odkazy: [{ t: "zdroj", u: g.u }], d: g.d,
      ico: z ? z.zi : (/^\d{8}$/.test(g.k) ? g.k : ""), lead: "g:" + g.id });
  }
  for (const g of D.signaly) {
    if (g.t !== "investor_vice_staveb" && g.t !== "kolaudace_bytoveho_domu") continue;
    pridej({ id: "o:iv:" + g.id, kat: "Zákazníci", typ: TYP_SIG[g.t], n: g.p.slice(0, 160), obec: g.o, kde: g.on, kr: g.kr,
      kc: null, fakta: [esc(g.p), `zdroje: ${esc(g.z)}`], vzorek: 2, doklad: "střední", odkazy: [{ t: "zdroj", u: g.u }], d: g.d, ico: /^\d{8}$/.test(g.k) ? g.k : "" });
  }
  // 9) území: kde se v okrese staví a mění plány (počty z desek, ÚP, dražeb)
  for (const x of D.souvislosti.pipeline || []) {
    const stavby = +x.stavby_zamer + +x.stavby_rizeni + +x.stavby_povoleni + +x.stavby_kolaudace;
    if (stavby + +x.up_probiha < 10) continue;
    pridej({ id: "o:uz:" + x.okres, kat: "Území", typ: "aktivita v okrese", n: `Okres ${x.okres}`, kr: x.kraj, kc: null,
      fakta: [`stavby z úředních desek: záměr ${x.stavby_zamer}, řízení ${x.stavby_rizeni}, povolení ${x.stavby_povoleni}, kolaudace ${x.stavby_kolaudace}`,
        `územní plány: rozpracované změny ${x.up_probiha}, vydané za rok ${x.up_vydano_rok}`,
        `prodeje obcí za rok ${x.prodeje_obci_rok}, aktivní nabídky majetku ${x.nabidky_aktivni}, otevřené zakázky ${x.zakazky_otevrene}`],
      vzorek: stavby, doklad: DOKLAD(stavby), odkazy: [], d: "", razeni: stavby });
  }
  // 10) inzerce: co se shání víc, než nabízí
  const pt = new Map();
  for (const p of D.projekty) {
    if (!p.a) continue;
    const t = String(p.t || "jiné").replace(/_/g, " "), v = pt.get(t) || { t, pop: [], nab: 0 };
    if (p.sm === "poptavka") v.pop.push(p); else if (p.sm === "nabidka") v.nab++; pt.set(t, v);
  }
  for (const v of pt.values()) {
    if (v.pop.length < 5 || v.pop.length < 2 * Math.max(1, v.nab)) continue;
    const zeme = [...new Set(v.pop.map((p) => p.ze))].join(", ");
    pridej({ id: "o:in:" + v.t, kat: "Inzerce", typ: "poptávka převyšuje nabídku", n: `${v.t}: shání se ${v.pop.length}×, nabízí ${v.nab}×`, kc: null,
      fakta: [`aktivní poptávky ${v.pop.length}, nabídky ${v.nab} (${esc(zeme)})`,
        ...v.pop.slice(0, 4).map((p) => `${datum(p.d || p.pz)} ${esc(p.n.slice(0, 90))}${p.c ? " · " + cislo(p.c) + " " + esc(p.me || "Kč") : ""}`)],
      vzorek: v.pop.length + v.nab, doklad: DOKLAD(v.pop.length + v.nab), odkazy: v.pop.slice(0, 4).map((p) => ({ t: p.n.slice(0, 40), u: p.u })), d: "" });
  }
  OBJEVY = O; OBJEV = new Map(O.map((o) => [o.id, o]));
}

/* ------------------------------------------------------------------ zákazníci (účty) */
function sestavUcty() {
  UCTY = new Map();
  const od = SML_OD > posun(-3 * 365) ? SML_OD : posun(-3 * 365), ted = dnes();
  const ucet = (ico, n, kr) => {
    if (!ico) return null;
    if (!UCTY.has(ico)) UCTY.set(ico, { ico, n: n || ico, kr: kr || "", utrata: 0, smluv: 0, kat: {}, dod: new Map(), posledni: "", zak: [], stavby: [], otevrene: 0, opak: 0 });
    const u = UCTY.get(ico); if (!u.kr && kr) u.kr = kr; return u;
  };
  for (const s of D.smlouvy) {
    if (!s.d || s.d < od || s.d > ted) continue;
    const kat = seznam(s.kat); if (!shoda(kat)) continue;
    const u = ucet(s.oi, s.ob, s.kr); if (!u) continue;
    u.utrata += s.h || 0; u.smluv++; if (s.d > u.posledni) u.posledni = s.d;
    for (const k of kat) u.kat[k] = (u.kat[k] || 0) + (s.h || 0);
    const key = s.di || s.do;
    if (key && s.di !== S.ico) { const d = u.dod.get(key) || { n: s.do, ico: s.di, h: 0, c: 0 }; d.h += s.h || 0; d.c++; u.dod.set(key, d); }
  }
  for (const z of D.zakazky) {
    if (!shoda(seznam(z.kat))) continue;
    const u = ucet(z.zi, z.zd, z.kr); if (!u) continue;
    u.zak.push(z);
    if ((z.lh || "").slice(0, 10) >= ted && z.s !== "zrušen") u.otevrene++;
    if (z.dz > u.posledni) u.posledni = z.dz;
  }
  for (const x of D.zamery) if (x.si && (x.pd || "") >= posun(-365)) { const u = ucet(x.si, x.sn, x.kr); if (u) u.stavby.push(x); }
  for (const g of OPAK) { const u = UCTY.get(g.zi); if (u) u.opak++; }
}

/* ------------------------------------------------------------------ záložky */
let ZALOZKA = "objevy";
const vykreslene = new Set();
$("#zalozky").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-z]"); if (!b) return;
  ZALOZKA = b.dataset.z;
  document.querySelectorAll("#zalozky button").forEach((x) => x.classList.toggle("aktivni", x === b));
  document.querySelectorAll(".zalozka").forEach((s) => (s.hidden = s.id !== "z-" + ZALOZKA));
  uloz.pis("obchod-zalozka", ZALOZKA);
  KRESLI[ZALOZKA]();
});
const KRESLI = { objevy: kresliObjevy, leady: kresliLeady, pipeline: kresliPipeline, ucty: kresliUcty, konkurence: kresliKonkurenci, cena: kresliCenu, trhy: kresliTrhy, nastaveni: kresliNastaveni };
function vykresliVse(obnova) {
  if (!obnova) { const z = uloz.cti("obchod-zalozka"); const b = z && document.querySelector(`#zalozky button[data-z="${z}"]`); if (b) { b.click(); return; } }
  KRESLI[ZALOZKA]();
}

/* ------------------------------------------------------------------ OBJEVY */
function filtrLeadu(volby = {}) {
  const h = volby.h ?? "", typ = volby.typ ?? "", kr = volby.kr ?? "", min = volby.min ?? 0, moje = volby.moje ?? true, skryt = volby.skryt ?? true;
  return LEADY.filter((l) => (!typ || l.druh === typ) && vUzemi(l.kr, kr) && (!min || (l.h || 0) >= min) && (!moje || shoda(l.kat))
    && (!skryt || !P[l.id]) && hledej(h, l.n, l.kdo, nazevObce(l.obec), l.proc));
}
function kartaLeadu(l) {
  return `<div class="polozka"><span class="stitek${l.termin && dniDo(l.termin) <= 7 ? " horko" : ""}">${esc(l.druh)}</span>
    <div><a href="#" data-lead="${esc(l.id)}">${esc(l.n)}</a></div>
    <div class="meta">${esc(l.kdo || "")}${l.obec ? " · " + esc(nazevObce(l.obec)) : l.kr ? " · " + esc(l.kr) : ""}${l.h ? " · srovnatelné ceny " + kcK(l.h) : ""}${l.terminPopis ? " · " + esc(l.terminPopis) : ""}</div></div>`;
}
const DOKLAD_PORADI = { "silný": 3, "střední": 2, "malý": 1 };
let OBJEVU_ZOBRAZ = 60;
function filtrObjevu() {
  const kat = $("#o-kat").value, typ = $("#o-typ").value, kr = $("#o-kraj").value, h = $("#o-hledat").value, jenDoklad = $("#o-doklad").checked;
  return OBJEVY.filter((o) => (!kat || o.kat === kat) && (!typ || o.typ === typ) && (!kr || o.kr === kr) && (!mojeKraje() || kr || !o.kr || S.kraje.includes(o.kr))
    && (!jenDoklad || o.doklad !== "malý") && hledej(h, o.n, o.kde, o.kr, o.typ, ...o.fakta));
}
function kartaObjevu(o) {
  return `<div class="objev doklad-${o.doklad === "silný" ? "s" : o.doklad === "střední" ? "m" : "x"}">
    <div class="objev-hlava"><span class="stitek">${esc(o.kat)}</span> <span class="tlumene">${esc(o.typ)}</span>
      <span class="doklad" title="Síla dokladu podle velikosti vzorku nebo počtu nezávislých zdrojů">doklad: ${esc(o.doklad)} (${cislo(o.vzorek)})</span></div>
    <div class="objev-nazev"><a href="#" data-objev="${esc(o.id)}">${esc(o.n)}</a>${o.kde || o.kr ? `<span class="tlumene"> · ${esc(o.kde || "")}${o.kde && o.kr ? ", " : ""}${esc(o.kr || "")}</span>` : ""}</div>
    ${o.kc ? `<div class="objev-cislo">${kcK(o.kc)} <span class="tlumene">${esc(o.kcPopis || "")}</span></div>` : ""}
    <ul class="fakta">${o.fakta.slice(0, 3).map((f) => `<li>${f}</li>`).join("")}</ul></div>`;
}
function kresliObjevy(zpet) {
  if (zpet === true) OBJEVU_ZOBRAZ = 60;
  const vse = filtrObjevu(), raz = $("#o-razeni").value;
  const r = [...vse].sort(raz === "doklad" ? (a, b) => DOKLAD_PORADI[b.doklad] - DOKLAD_PORADI[a.doklad] || b.vzorek - a.vzorek
    : raz === "datum" ? (a, b) => (b.d || "").localeCompare(a.d || "")
    : (a, b) => (b.kc || 0) - (a.kc || 0) || DOKLAD_PORADI[b.doklad] - DOKLAD_PORADI[a.doklad] || (b.razeni || 0) - (a.razeni || 0));
  const pocty = {}; for (const o of OBJEVY) pocty[o.kat] = (pocty[o.kat] || 0) + 1;
  $("#o-dlazdice").innerHTML = KATEGORIE_OBJEVU.filter((k) => pocty[k]).map((k) =>
    `<button class="karta dl-tl${$("#o-kat").value === k ? " vybrano" : ""}" data-okat="${esc(k)}"><div class="dl-cislo">${cislo(pocty[k])}</div><div class="dl-popis">${esc(k)}</div></button>`).join("");
  $("#o-uvod").textContent = `Data k ${datum(D.vytvoreno)} · registr smluv ${SML_OD ? "od " + datum(SML_OD) : "—"} · vysoutěžených zakázek ${cislo(D.zakazky.filter((z) => z.cb > 0).length)} · aktivních nabídek majetku ${cislo((D.nabidky || []).filter((x) => x.a).length)}.`
    + (S.obory.length || S.kraje.length ? ` Filtr z Nastavení: ${[S.obory.join(", "), S.kraje.join(", ")].filter(Boolean).join(" · ")}.` : "");
  $("#o-pocet").textContent = `${cislo(r.length)} objevů`;
  $("#o-seznam").innerHTML = r.slice(0, OBJEVU_ZOBRAZ).map(kartaObjevu).join("") || '<p class="tlumene">Nic neodpovídá filtru.</p>'
    + "";
  $("#o-vice").hidden = r.length <= OBJEVU_ZOBRAZ;
  $("#o-vice").textContent = `Zobrazit dalších 60 (zbývá ${cislo(r.length - OBJEVU_ZOBRAZ)})`;
}
$("#o-vice").onclick = () => { OBJEVU_ZOBRAZ += 60; kresliObjevy(); };
$("#o-dlazdice").addEventListener("click", (e) => {
  const b = e.target.closest("[data-okat]"); if (!b) return;
  $("#o-kat").value = $("#o-kat").value === b.dataset.okat ? "" : b.dataset.okat; naplnTypy(); kresliObjevy(true);
});
function naplnTypy() { naplnVyber("#o-typ", [...new Set(OBJEVY.filter((o) => !$("#o-kat").value || o.kat === $("#o-kat").value).map((o) => o.typ))].sort(), "všechny typy"); }
$("#o-kat").addEventListener("change", naplnTypy);
napoj(["#o-hledat", "#o-kat", "#o-typ", "#o-kraj", "#o-razeni", "#o-doklad"], kresliObjevy);
$("#o-csv").onclick = () => stahniCsv("objevy", [["kategorie", (o) => o.kat], ["typ", (o) => o.typ], ["nazev", (o) => o.n], ["kde", (o) => o.kde], ["kraj", (o) => o.kr],
  ["kc", (o) => o.kc ? Math.round(o.kc) : ""], ["co_je_kc", (o) => o.kcPopis || ""], ["doklad", (o) => o.doklad], ["vzorek", (o) => o.vzorek],
  ["fakta", (o) => o.fakta.map((f) => f.replace(/<[^>]+>/g, "").replace(/&amp;/g, "&").replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">")).join(" | ")],
  ["odkaz", (o) => bezpecnaUrl((o.odkazy[0] || {}).u)]], filtrObjevu());
function detailObjevu(id) {
  const o = OBJEV.get(id); if (!o) return;
  const p = P[id], lead = o.lead && LEAD.get(o.lead);
  otevriPanel(`<p class="tlumene">${esc(o.kat)} · ${esc(o.typ)}</p><h2>${esc(o.n)}</h2>
    <p>${o.kde || o.kr ? esc([o.kde, o.kr].filter(Boolean).join(", ")) + " · " : ""}doklad: <b>${esc(o.doklad)}</b> (${o.doklad === "malý" || o.doklad === "střední" || o.doklad === "silný" ? "vzorek / zdrojů " + cislo(o.vzorek) : ""})</p>
    ${o.kc ? `<p class="objev-cislo">${kc(o.kc)} <span class="tlumene">${esc(o.kcPopis || "")}</span></p>` : ""}
    <h3>Co data ukazují</h3><ul class="fakta">${o.fakta.map((f) => `<li>${f}</li>`).join("")}</ul>
    ${o.odkazy.filter((x) => bezpecnaUrl(x.u)).length ? `<h3>Zdroje</h3>${o.odkazy.filter((x) => bezpecnaUrl(x.u)).map((x) => `<div class="pp">${odkaz(x.u, x.t)}</div>`).join("")}` : ""}
    <h3>Dál v datech</h3><div class="pp">${[o.ico ? `<a href="#" data-ucet="${esc(o.ico)}">zákazník IČO ${esc(o.ico)}</a>` : "",
      o.firma ? `<a href="#" data-firma="${esc(o.firma)}">dominantní dodavatel</a>` : "", lead ? `<a href="#" data-lead="${esc(lead.id)}">detail položky</a>` : "",
      o.trh ? `<a href="#" data-trh="${esc(o.trh)}">nacenění v oboru ${esc(o.trh)}</a>` : ""].filter(Boolean).join(" · ") || '<span class="tlumene">—</span>'}</div>
    <h3>Sledované</h3>
    <p>${p ? `Sleduješ (${esc(STAV_POPIS[p.stav])}). <button id="ob-smazat" class="maly">Přestat sledovat</button>` : '<button id="ob-sledovat">Sledovat</button>'}</p>`);
  const b = $("#ob-sledovat"); if (b) b.onclick = () => {
    doObchodu({ id, n: o.n, kdo: o.kde || o.kr || "", ico: o.ico || "", u: (o.odkazy[0] || {}).u || "", druh: o.kat + " – " + o.typ, kr: o.kr, h: o.kc, termin: "" }, "novy");
    detailObjevu(id);
  };
  const sm = $("#ob-smazat"); if (sm) sm.onclick = () => { delete P[id]; ulozP(); detailObjevu(id); };
}

/* ------------------------------------------------------------------ PŘÍLEŽITOSTI */
const stavL = { razeni: "pz", smer: -1 };
const filtrL = () => filtrLeadu({ h: $("#l-hledat").value, typ: $("#l-typ").value, kr: $("#l-kraj").value, min: +$("#l-min").value, moje: $("#l-moje").checked, skryt: $("#l-skryt").checked });
const SL_L = [
  { k: "n", t: "Příležitost", sir: 1, f: (l) => `<a href="#" data-lead="${esc(l.id)}">${esc(l.n)}</a><div class="tlumene">${esc(l.proc.slice(0, 200))}</div>` },
  { k: "druh", t: "Druh", f: (l) => `<span class="stitek">${esc(l.druh)}</span>` },
  { k: "kdo", t: "Kdo", f: (l) => l.ico ? `<a href="#" data-ucet="${esc(l.ico)}">${esc(l.kdo || l.ico)}</a>` : esc(l.kdo) },
  { k: "kr", t: "Kde", f: (l) => `${esc(nazevObce(l.obec))}<div class="tlumene">${esc(l.kr)}</div>` },
  { k: "h", t: "Srovnatelné ceny", c: 1, f: (l) => l.h ? `${kcK(l.h)}<div class="tlumene">${esc(l.hz)}</div>` : "" },
  { k: "pz", t: "Zachyceno", f: (l) => datum(l.pz) },
  { k: "termin", t: "Termín", h: (l) => l.termin || "", f: (l) => l.termin ? `${datum(l.termin)}<div class="tlumene">${zaDni(dniDo(l.termin))}</div>` : "" },
  { k: "konk", t: "Medián nabídek", c: 1, f: (l) => l.konk == null ? "" : cislo(l.konk) },
];
function kresliLeady(zpet) {
  if (zpet === true) stavL.n = NA_STRANKU;
  stavL.prekresli = kresliLeady;
  const r = filtrL();
  $("#l-pocet").textContent = `${cislo(r.length)} příležitostí`;
  tabulka($("#t-leady"), SL_L, r, stavL);
}
napoj(["#l-hledat", "#l-typ", "#l-kraj", "#l-min", "#l-moje", "#l-skryt"], kresliLeady);
$("#l-csv").onclick = () => stahniCsv("prilezitosti", [["druh", (l) => l.druh], ["nazev", (l) => l.n], ["kdo", (l) => l.kdo], ["ico", (l) => l.ico],
  ["obec", (l) => nazevObce(l.obec)], ["kraj", (l) => l.kr], ["srovnatelne_ceny_kc", (l) => l.h ? Math.round(l.h) : ""], ["z_ceho", (l) => l.hz], ["zachyceno", (l) => l.pz], ["termin", (l) => l.termin],
  ["obory", (l) => l.kat.join(", ")], ["proc", (l) => l.proc], ["odkaz", (l) => bezpecnaUrl(l.u)]], filtrL());

/* ------------------------------------------------------------------ detail příležitosti */
function otevriPanel(html) { $("#panel-obsah").innerHTML = html; $("#panel").hidden = false; $("#panel").scrollTop = 0; }
$("#panel-zavrit").onclick = () => ($("#panel").hidden = true);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#panel").hidden = true; });
document.addEventListener("click", (e) => {
  const a = e.target.closest("[data-lead],[data-ucet],[data-firma],[data-objev],[data-trh]");
  if (!a) return;
  e.preventDefault();
  if (a.dataset.objev) detailObjevu(a.dataset.objev);
  else if (a.dataset.trh) { $("#panel").hidden = true; $('#zalozky button[data-z="cena"]').click(); $("#c-kat").value = a.dataset.trh; $("#c-hledat").value = ""; kresliCenu(true); }
  else if (a.dataset.lead) detailLeadu(a.dataset.lead);
  else if (a.dataset.ucet) detailUctu(a.dataset.ucet);
  else if (a.dataset.firma) detailKonkurenta(a.dataset.firma);
});
const radek = (k, v) => (v === "" || v == null ? "" : `<tr><th>${esc(k)}</th><td>${v}</td></tr>`);
function detailLeadu(id) {
  if (OBJEV.has(id)) return detailObjevu(id);
  const l = LEAD.get(id), p = P[id];
  if (!l && !p) return;
  const x = l || { id, n: p.n, kdo: p.kdo, ico: p.ico, u: p.u, druh: p.druh, kr: p.kr, kat: [], proc: "Příležitost už v datech není (zakázka skončila nebo signál zmizel). Záznam ve vašem obchodě zůstává.", h: p.h };
  const konk = x.kat && x.kat.length ? topKonkurenti(x.kat, x.kr, 5) : [];
  const srovnani = x.kat && x.kat.length ? srovnatelne(x.n, x.kat, x.kr).slice(0, 6) : [];
  const ucet = x.ico ? UCTY.get(x.ico) : null;
  otevriPanel(`<h2>${esc(x.n)}</h2><p class="tlumene">${esc(x.druh)}${x.kr ? " · " + esc(x.kr) : ""}${x.obec ? " · " + esc(nazevObce(x.obec)) : ""}</p>
    <table class="info">${radek("Co je v datech", esc(x.proc))}${radek("Kdo", x.ico ? `<a href="#" data-ucet="${esc(x.ico)}">${esc(x.kdo || x.ico)}</a> · IČO ${esc(x.ico)}` : esc(x.kdo))}
      ${radek("Termín / historie", esc(x.terminPopis || ""))}${radek("Srovnatelné ceny", x.h ? `${kc(x.h)}<div class="tlumene">${esc(x.hz || "")}</div>` : "")}
      ${radek("Medián nabídek v oboru", x.konk == null ? "" : cislo(x.konk))}${radek("Obory", esc((x.kat || []).join(", ")))}
      ${radek("Zdroj", odkaz(x.u, "otevřít zdroj"))}
      ${x.ico ? radek("Rejstříky", `<a href="https://ares.gov.cz/ekonomicke-subjekty?ico=${esc(x.ico)}" target="_blank" rel="noopener noreferrer">ARES</a> · <a href="https://or.justice.cz/ias/ui/rejstrik-$firma?ico=${esc(x.ico)}" target="_blank" rel="noopener noreferrer">obchodní rejstřík</a> · <a href="https://smlouvy.gov.cz/vyhledavani?searchResultList-limit=10&do=searchResultList-setLimit&subject_idnum=${esc(x.ico)}" target="_blank" rel="noopener noreferrer">registr smluv</a>`) : ""}</table>
    <h3>Sledované</h3>
    <div class="lead-akce filtry">
      <select id="pl-stav">${STAVY.map(([k, t]) => `<option value="${k}"${p && p.stav === k ? " selected" : ""}>${esc(t)}</option>`).join("")}</select>
      <label>připomenout <input id="pl-fu" type="date" value="${esc(p ? p.fu : posun(2))}"></label>
      <label>hodnota Kč <input id="pl-h" type="number" min="0" step="1000" value="${p && p.h ? Math.round(p.h) : x.h ? Math.round(x.h) : ""}" style="width:120px"></label>
    </div>
    <textarea id="pl-pozn" class="poznamka" placeholder="Poznámka (kontakt, co řekli, další krok)">${esc(p ? p.pozn : "")}</textarea>
    <p><button id="pl-ulozit">${p ? "Uložit změny" : "Sledovat"}</button> ${p ? '<button id="pl-smazat" class="maly">Odebrat</button>' : ""}</p>
    ${ucet ? `<h3>Tento zákazník v datech</h3>${souhrnUctu(ucet)}` : ""}
    ${srovnani.length ? `<h3>Srovnatelné ceny</h3>${srovnani.map((s) => `<div class="pp">${odkaz(s.u, s.n)} · <b>${kcK(s.cena)}</b><div class="tlumene">${esc(s.kdo)} · ${datum(s.d)}${s.pn ? " · " + s.pn + " nabídek" : ""}</div></div>`).join("")}` : ""}
    ${konk.length ? `<h3>Kdo tu obvykle vyhrává</h3>${konk.map((k) => `<div class="pp"><a href="#" data-firma="${esc(k.ico)}">${esc(k.n)}</a> · ${cislo(k.c)}× · ${kcK(k.h)}</div>`).join("")}` : ""}`);
  $("#pl-ulozit").onclick = () => {
    doObchodu(x, $("#pl-stav").value);
    const q = P[id]; q.fu = $("#pl-fu").value; q.pozn = $("#pl-pozn").value;
    const hv = Number($("#pl-h").value); if (hv > 0 && hv !== Math.round(x.h || 0)) { q.h = hv; q.hRucne = true; }
    ulozP(); $("#panel").hidden = true; KRESLI[ZALOZKA](true);
  };
  const sm = $("#pl-smazat"); if (sm) sm.onclick = () => { delete P[id]; ulozP(); $("#panel").hidden = true; KRESLI[ZALOZKA](true); };
}

/* ------------------------------------------------------------------ MŮJ OBCHOD */
const stavP = { razeni: "fu", smer: 1 };
const SL_P = [
  { k: "stav", t: "Stav", h: (r) => STAVY.findIndex(([k]) => k === r.stav), c: 1, f: (r) => `<span class="stitek${r.stav === "vyhrano" ? " stav-vyhra" : r.stav === "prohrano" ? " stav-prohra" : ""}">${esc(STAV_POPIS[r.stav])}</span>` },
  { k: "n", t: "Obchod", sir: 1, f: (r) => `<a href="#" data-lead="${esc(r.id)}">${esc(r.n)}</a><div class="tlumene">${esc(r.druh || "")}${r.pozn ? " · " + esc(r.pozn.slice(0, 120)) : ""}</div>` },
  { k: "kdo", t: "Kdo", f: (r) => r.ico ? `<a href="#" data-ucet="${esc(r.ico)}">${esc(r.kdo || r.ico)}</a>` : esc(r.kdo) },
  { k: "h", t: "Hodnota", c: 1, f: (r) => kcK(r.h) },
  { k: "fu", t: "Připomenout", f: (r) => r.fu ? (r.fu < dnes() ? `<b>${datum(r.fu)}</b>` : datum(r.fu)) : "" },
  { k: "termin", t: "Lhůta", f: (r) => datum(r.termin) },
  { k: "zmeneno", t: "Změna", f: (r) => datum(r.zmeneno) },
];
const radkyP = () => Object.entries(P).map(([id, p]) => ({ id, ...p }));
function kresliPipeline(zpet) {
  if (zpet === true) stavP.n = NA_STRANKU;
  stavP.prekresli = kresliPipeline;
  const vse = radkyP(), st = $("#p-stav").value, r = vse.filter((x) => !st || x.stav === st);
  const akt = vse.filter((p) => !["vyhrano", "prohrano", "odlozeno"].includes(p.stav)), vyhr = vse.filter((p) => p.stav === "vyhrano"), proh = vse.filter((p) => p.stav === "prohrano");
  $("#p-dlazdice").innerHTML = [
    [cislo(akt.length), "rozpracovaných", kcK(akt.reduce((s, p) => s + (p.h || 0), 0)) || ""],
    [cislo(akt.filter((p) => p.fu && p.fu <= dnes()).length), "připomínek na dnes a dřív", ""],
    [cislo(vyhr.length), "vyhráno", kcK(vyhr.reduce((s, p) => s + (p.h || 0), 0))],
    [vyhr.length + proh.length ? Math.round(100 * vyhr.length / (vyhr.length + proh.length)) + " %" : "–", "úspěšnost", `${vyhr.length} z ${vyhr.length + proh.length} rozhodnutých`],
  ].map(([c, p, s]) => `<div class="karta"><div class="dl-cislo">${c}</div><div class="dl-popis">${p}</div><div class="dl-pod">${s}</div></div>`).join("");
  $("#p-pocet").textContent = `${cislo(r.length)} záznamů`;
  const ukoly = vse.filter((p) => !["vyhrano", "prohrano", "odlozeno"].includes(p.stav) && p.fu && p.fu <= posun(3)).sort((a, b) => (a.fu > b.fu ? 1 : -1));
  const lhuty = filtrLeadu({ skryt: false }).filter((l) => l.druh === "veřejná zakázka" && P[l.id] && dniDo(l.termin) <= 7);
  $("#p-ukoly").innerHTML = [...ukoly.map((p) => `<div class="polozka"><span class="stitek${p.fu < dnes() ? " horko" : ""}">připomenout ${datum(p.fu)}</span>
      <div><a href="#" data-lead="${esc(p.id)}">${esc(p.n)}</a></div><div class="meta">${esc(STAV_POPIS[p.stav])}${p.pozn ? " · " + esc(p.pozn.slice(0, 80)) : ""}</div></div>`),
    ...lhuty.map(kartaLeadu)].join("") || '<p class="tlumene">Na příští 3 dny nic. Sledovat jde z detailu kteréhokoli objevu nebo položky.</p>';
  tabulka($("#t-pipeline"), SL_P, r, stavP);
}
napoj(["#p-stav"], kresliPipeline);
$("#p-csv").onclick = () => stahniCsv("muj-obchod", [["stav", (r) => STAV_POPIS[r.stav]], ["nazev", (r) => r.n], ["druh", (r) => r.druh], ["kdo", (r) => r.kdo], ["ico", (r) => r.ico],
  ["kraj", (r) => r.kr], ["hodnota_kc", (r) => r.h ? Math.round(r.h) : ""], ["pripomenout", (r) => r.fu], ["lhuta", (r) => r.termin], ["poznamka", (r) => r.pozn],
  ["pridano", (r) => r.pridano], ["zmeneno", (r) => r.zmeneno], ["odkaz", (r) => bezpecnaUrl(r.u)]], radkyP());
$("#p-ics").onclick = () => {
  const ics = (s) => String(s || "").replace(/[\\;,]/g, (c) => "\\" + c).replace(/\r\n|\r|\n/g, "\\n");
  const ev = radkyP().filter((p) => p.fu && !["vyhrano", "prohrano", "odlozeno"].includes(p.stav)).map((p) => [
    "BEGIN:VEVENT", `UID:obchod-${p.id.replace(/[^\w-]/g, "")}@datasety`, `DTSTAMP:${new Date().toISOString().replace(/[-:]/g, "").slice(0, 15)}Z`,
    `DTSTART;VALUE=DATE:${p.fu.replace(/-/g, "")}`, `SUMMARY:${ics(STAV_POPIS[p.stav] + ": " + p.n.slice(0, 120))}`,
    `DESCRIPTION:${ics((p.kdo || "") + (p.pozn ? " – " + p.pozn : "") + (bezpecnaUrl(p.u) ? " " + p.u : ""))}`, "END:VEVENT"].join("\r\n"));
  stahniSoubor(`pripominky-${dnes()}.ics`, ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//datasety//obchod//CS", ...ev, "END:VCALENDAR"].join("\r\n"), "text/calendar");
};
$("#p-zaloha").onclick = () => stahniSoubor(`muj-obchod-zaloha-${dnes()}.json`, JSON.stringify({ verze: 1, pipeline: P, nastaveni: S }, null, 1), "application/json");
$("#p-obnova").onchange = async (e) => {
  const f = e.target.files[0]; if (!f) return;
  try {
    const j = JSON.parse(await f.text());
    if (!j || typeof j.pipeline !== "object") throw new Error("neznámý formát");
    for (const [id, v] of Object.entries(j.pipeline)) if (v && typeof v === "object" && STAV_POPIS[v.stav]) P[id] = { ...P[id], ...v };
    if (j.nastaveni && Array.isArray(j.nastaveni.obory)) S = { ...VYCHOZI, ...j.nastaveni };
    ulozP(); ulozS(); priprav(); kresliPipeline(true);
  } catch (x) { alert("Zálohu se nepodařilo načíst: " + x.message); }
  e.target.value = "";
};

/* ------------------------------------------------------------------ ZÁKAZNÍCI */
const stavU = { razeni: "utrata", smer: -1 };
const obdobiSmluv = () => (SML_OD > posun(-3 * 365) ? "od " + datum(SML_OD) : "3 roky");
function souhrnUctu(u) {
  const dod = [...u.dod.values()].sort((a, b) => b.h - a.h), cel = dod.reduce((s, d) => s + d.h, 0);
  return `<table class="info">${radek(`Útrata ve vašich oborech (${obdobiSmluv()})`, `<b>${kc(u.utrata)}</b> · ${cislo(u.smluv)} smluv`)}
    ${radek("Za co", Object.entries(u.kat).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${esc(k)} ${kcK(v)}`).join("<br>"))}
    ${radek("Kdo jim dodává", dod.slice(0, 5).map((d) => `${d.ico ? `<a href="#" data-firma="${esc(d.ico)}">${esc(d.n)}</a>` : esc(d.n)} · ${cel ? Math.round(100 * d.h / cel) : 0} % (${d.c}×)`).join("<br>"))}
    ${radek("Poslední nákup / zakázka", datum(u.posledni))}${radek("Otevřené zakázky teď", u.otevrene ? `<b>${u.otevrene}</b>` : "")}
    ${radek("Opakované poptávky", u.opak || "")}${radek("Stavby v přípravě (rok)", u.stavby.length || "")}</table>`;
}
function detailUctu(ico) {
  const u = UCTY.get(ico);
  const leady = LEADY.filter((l) => l.ico === ico);
  const sml = D.smlouvy.filter((s) => s.oi === ico).sort((a, b) => (b.d > a.d ? 1 : -1)).slice(0, 25);
  const opak = OPAK.filter((g) => g.zi === ico);
  otevriPanel(`<h2>${esc(u ? u.n : ico)}</h2><p class="tlumene">IČO ${esc(ico)}${u && u.kr ? " · " + esc(u.kr) : ""} · <a href="https://ares.gov.cz/ekonomicke-subjekty?ico=${esc(ico)}" target="_blank" rel="noopener noreferrer">ARES</a></p>
    ${u ? souhrnUctu(u) : '<p class="tlumene">V registru smluv ve vašich oborech nic.</p>'}
    ${leady.length ? `<h3>Aktuální příležitosti (${leady.length})</h3>${leady.sort((a, b) => b.skore - a.skore).map(kartaLeadu).join("")}` : ""}
    ${opak.length ? `<h3>Opakované poptávky</h3>${opak.map((g) => `<div class="pp">${odkaz(g.u, g.n)} · ${g.pocet}× vypsáno, ${g.zrus}× zrušeno${g.cena ? " · naposledy " + kcK(g.cena) + " (" + esc(g.vitez) + ")" : ""}</div>`).join("")}` : ""}
    ${u && u.stavby.length ? `<h3>Stavby, kde je investorem</h3>${u.stavby.slice(0, 15).map((x) => `<div class="pp">${esc(x.n)} · ${esc(x.f)} ${datum(x.df)}${x.hon ? " · honorář cca " + kcK(x.hon) : ""}</div>`).join("")}` : ""}
    ${sml.length ? `<h3>Poslední smlouvy (všechny obory)</h3>${sml.map((s) => `<div class="pp">${datum(s.d)} · ${odkaz(s.u, s.p)} · ${esc(s.do)}${s.h ? " · " + kcK(s.h) : ""}</div>`).join("")}` : ""}`);
}
function filtrU() {
  const h = $("#u-hledat").value, kr = $("#u-kraj").value, typ = $("#u-typ").value;
  return [...UCTY.values()].filter((u) => (u.utrata > 0 || u.otevrene || u.stavby.length) && vUzemi(u.kr, kr) && hledej(h, u.n, u.ico)
    && (!typ || (typ === "otevrene" && u.otevrene) || (typ === "stavby" && u.stavby.length) || (typ === "opak" && u.opak)));
}
const SL_U = [
  { k: "n", t: "Zákazník", sir: 1, f: (u) => `<a href="#" data-ucet="${esc(u.ico)}">${esc(u.n)}</a><div class="tlumene">${esc(Object.keys(u.kat).join(", "))}</div>` },
  { k: "kr", t: "Kraj", f: (u) => esc(u.kr) },
  { k: "utrata", t: "Útrata", c: 1, f: (u) => kcK(u.utrata) },
  { k: "smluv", t: "Smluv", c: 1, f: (u) => cislo(u.smluv) },
  { k: "hlavni", t: "Hlavní dodavatel", h: (u) => { const d = [...u.dod.values()].sort((a, b) => b.h - a.h)[0]; return d ? d.h / (u.utrata || 1) : null; }, c: 1,
    f: (u) => { const d = [...u.dod.values()].sort((a, b) => b.h - a.h)[0]; return d ? `${esc(d.n)}<div class="tlumene">${Math.round(100 * d.h / (u.utrata || 1))} % útraty</div>` : ""; } },
  { k: "otevrene", t: "Otevřené zakázky", c: 1, f: (u) => u.otevrene ? `<b>${u.otevrene}</b>` : "" },
  { k: "st", t: "Stavby v přípravě", c: 1, h: (u) => u.stavby.length, f: (u) => u.stavby.length || "" },
  { k: "opak", t: "Opakované poptávky", c: 1, f: (u) => u.opak || "" },
  { k: "posledni", t: "Poslední", f: (u) => datum(u.posledni) },
];
function kresliUcty(zpet) {
  if (zpet === true) stavU.n = NA_STRANKU;
  stavU.prekresli = kresliUcty;
  const r = filtrU();
  $("#u-pocet").textContent = `${cislo(r.length)} zákazníků · útrata celkem ${kcK(r.reduce((s, u) => s + u.utrata, 0))} (${obdobiSmluv()})`;
  tabulka($("#t-ucty"), SL_U, r, stavU);
}
napoj(["#u-hledat", "#u-kraj", "#u-typ"], kresliUcty);

/* ------------------------------------------------------------------ KONKURENCE */
let KONK = null;
function sestavKonkurenci() {
  const m = new Map(), od = posun(-3 * 365), ted = dnes();
  const st = new Map(D.souvislosti.konkurence.map((k) => [k.ico, k]));
  const pridej = (ico, n, h, kr, zak, kat, d) => {
    if (!ico || ico === S.ico) return;
    if (!m.has(ico)) m.set(ico, { ico, n, h: 0, c: 0, kraje: {}, zak: new Map(), kat: {}, posledni: "", st: st.get(ico) });
    const k = m.get(ico); k.h += h || 0; k.c++; if (kr) k.kraje[kr] = (k.kraje[kr] || 0) + 1;
    if (zak) { const z = k.zak.get(zak.ico) || { n: zak.n, ico: zak.ico, h: 0, c: 0 }; z.h += h || 0; z.c++; k.zak.set(zak.ico, z); }
    for (const x of kat) k.kat[x] = (k.kat[x] || 0) + 1; if (d > k.posledni) k.posledni = d;
  };
  for (const s of D.smlouvy) {
    if (!s.d || s.d < od || s.d > ted) continue;
    const kat = seznam(s.kat); if (!shoda(kat)) continue;
    pridej(s.di, s.do, s.h, s.kr, { n: s.ob, ico: s.oi }, kat, s.d);
  }
  KONK = m;
}
function topKonkurenti(kat, kr, n) {
  if (!KONK) sestavKonkurenci();
  const v = [];
  for (const k of KONK.values()) if (kat.some((x) => k.kat[x]) && (!kr || k.kraje[kr])) v.push(k);
  return v.sort((a, b) => b.h - a.h).slice(0, n);
}
function detailKonkurenta(ico) {
  if (!KONK) sestavKonkurenci();
  const k = KONK.get(ico), st = (k && k.st) || D.souvislosti.konkurence.find((x) => x.ico === ico);
  const zak = k ? [...k.zak.values()].sort((a, b) => b.h - a.h).slice(0, 10) : [];
  otevriPanel(`<h2>${esc(k ? k.n : st ? st.nazev : ico)}</h2><p class="tlumene">IČO ${esc(ico)} · <a href="https://ares.gov.cz/ekonomicke-subjekty?ico=${esc(ico)}" target="_blank" rel="noopener noreferrer">ARES</a></p>
    <table class="info">${k ? radek("Smlouvy ve vašich oborech (3 roky)", `<b>${kc(k.h)}</b> · ${cislo(k.c)}×`) : ""}
    ${st ? radek("V soutěžích", `${cislo(st.nabidek)} nabídek, ${cislo(st.vyher)} výher (${esc(st.uspesnost_pct)} %)`) : ""}
    ${st && st.median_nahskok_pct ? radek("Když vyhraje, je levnější o", `${esc(st.median_nahskok_pct)} % (medián)`) : ""}
    ${st && st.median_ztrata_pct ? radek("Když prohraje, je dražší o", `${esc(st.median_ztrata_pct)} % (medián)`) : ""}
    ${k ? radek("Obory", esc(Object.entries(k.kat).sort((a, b) => b[1] - a[1]).map(([x, n]) => `${x} (${n})`).join(", "))) : ""}
    ${k ? radek("Kraje", esc(Object.entries(k.kraje).sort((a, b) => b[1] - a[1]).map(([x, n]) => `${x} (${n})`).join(", "))) : ""}</table>
    ${zak.length ? `<h3>Hlavní zákazníci</h3>${zak.map((z) => `<div class="pp"><a href="#" data-ucet="${esc(z.ico)}">${esc(z.n)}</a> · ${kcK(z.h)} (${z.c}×)</div>`).join("")}` : ""}`);
}
const stavK = { razeni: "h", smer: -1 };
const SL_K = [
  { k: "n", t: "Firma", sir: 1, f: (k) => `<a href="#" data-firma="${esc(k.ico)}">${esc(k.n)}</a><div class="tlumene">${esc(Object.keys(k.kat).join(", "))}</div>` },
  { k: "h", t: "Smlouvy 3 roky", c: 1, f: (k) => kcK(k.h) },
  { k: "c", t: "Počet", c: 1, f: (k) => cislo(k.c) },
  { k: "zk", t: "Zákazníků", c: 1, h: (k) => k.zak.size, f: (k) => cislo(k.zak.size) },
  { k: "us", t: "Úspěšnost v soutěžích", c: 1, h: (k) => k.st ? +k.st.uspesnost_pct : null, f: (k) => k.st ? `${esc(k.st.uspesnost_pct)} %<div class="tlumene">${esc(k.st.nabidek)} nabídek</div>` : "" },
  { k: "na", t: "Vyhrává o", c: 1, h: (k) => k.st && k.st.median_nahskok_pct ? +k.st.median_nahskok_pct : null, f: (k) => k.st && k.st.median_nahskok_pct ? esc(k.st.median_nahskok_pct) + " %" : "" },
  { k: "kr", t: "Hlavní kraj", h: (k) => Object.entries(k.kraje).sort((a, b) => b[1] - a[1])[0]?.[0] || "", f: (k) => esc(Object.entries(k.kraje).sort((a, b) => b[1] - a[1])[0]?.[0] || "") },
  { k: "posledni", t: "Poslední", f: (k) => datum(k.posledni) },
];
function kresliKonkurenci(zpet) {
  if (!KONK) sestavKonkurenci();
  if (zpet === true) stavK.n = NA_STRANKU;
  stavK.prekresli = kresliKonkurenci;
  const h = $("#k-hledat").value, kr = $("#k-kraj").value;
  const r = [...KONK.values()].filter((k) => hledej(h, k.n, k.ico) && (kr ? k.kraje[kr] : (!mojeKraje() || S.kraje.some((x) => k.kraje[x]))));
  $("#k-pocet").textContent = `${cislo(r.length)} firem`;
  tabulka($("#t-konkurence"), SL_K, r, stavK);
}
napoj(["#k-hledat", "#k-kraj"], kresliKonkurenci);

/* ------------------------------------------------------------------ NACENĚNÍ */
function srovnatelne(text, kat, kr) {
  const slova = (String(text).toLowerCase().match(/[a-zá-ž0-9]{4,}/g) || []).filter((x) => !STOP.has(x));
  const skore = (t) => { if (!slova.length) return 1; const s = String(t).toLowerCase(); return slova.filter((w) => s.includes(w.slice(0, Math.max(4, w.length - 2)))).length / slova.length; };
  const v = [];
  for (const z of D.zakazky) {
    if (!(z.cb > 0) || !seznam(z.kat).some((k) => kat.includes(k)) || (kr && z.kr !== kr)) continue;
    const s = skore(z.n + " " + z.c + " " + z.p); if (s < 0.5) continue;
    v.push({ zdroj: "zakázka", n: z.c ? `${z.n} – ${z.c}` : z.n, kdo: z.zd, d: z.ds || z.dz, cena: z.cb, pn: z.pn, k: z.k, u: z.u, s });
  }
  for (const x of D.smlouvy) {
    if (!(x.h > 0) || !seznam(x.kat).some((k) => kat.includes(k)) || (kr && x.kr !== kr) || x.d > dnes()) continue;
    const s = skore(x.p); if (s < 0.5) continue;
    v.push({ zdroj: "smlouva", n: x.p, kdo: `${x.ob} → ${x.do}`, d: x.d, cena: x.h, pn: null, u: x.u, s });
  }
  return v.sort((a, b) => b.s - a.s || (b.d > a.d ? 1 : -1));
}
function nahskok(k) {
  const c = (NAB_ZAK_INDEX().get(k) || []).map((n) => n.c).filter((x) => x > 0).sort((a, b) => a - b);
  return c.length >= 2 ? (c[1] - c[0]) / c[1] : null;
}
let _NZ = null;
const NAB_ZAK_INDEX = () => { if (!_NZ) { _NZ = new Map(); for (const n of D.nabidky_zak || []) { if (!_NZ.has(n.k)) _NZ.set(n.k, []); _NZ.get(n.k).push(n); } } return _NZ; };
const stavC = { razeni: "s", smer: -1 };
const SL_C = [
  { k: "d", t: "Datum", f: (r) => datum(r.d) },
  { k: "n", t: "Předmět", sir: 1, f: (r) => `${odkaz(r.u, r.n)}<div class="tlumene">${esc(r.zdroj)} · ${esc(r.kdo)}</div>` },
  { k: "cena", t: "Cena bez DPH", c: 1, f: (r) => kc(r.cena) },
  { k: "pn", t: "Nabídek", c: 1, f: (r) => r.pn ? cislo(r.pn) : "" },
  { k: "s", t: "Shoda", c: 1, f: (r) => Math.round(100 * r.s) + " %" },
];
function kresliCenu(zpet) {
  if (zpet === true) stavC.n = NA_STRANKU;
  stavC.prekresli = kresliCenu;
  const kat = $("#c-kat").value ? [$("#c-kat").value] : (S.obory.length ? S.obory : OBORY), kr = $("#c-kraj").value;
  const r = srovnatelne($("#c-hledat").value, kat, kr);
  const ceny = r.map((x) => x.cena), zak = r.filter((x) => x.zdroj === "zakázka");
  const ns = zak.map((x) => nahskok(x.k)).filter((x) => x != null);
  $("#c-pocet").textContent = `${cislo(r.length)} srovnatelných (${zak.length} zakázek, ${r.length - zak.length} smluv)`;
  $("#c-dlazdice").innerHTML = [
    [kcK(median(ceny)) || "–", "medián ceny", `${cislo(r.length)} případů`],
    [kcK(kvantil(ceny, 0.25)) || "–", "dolní čtvrtina (P25)", "levnější čtvrtina zakázek"],
    [kcK(kvantil(ceny, 0.75)) || "–", "horní čtvrtina (P75)", ""],
    [median(zak.map((x) => x.pn)) ?? "–", "nabídek obvykle", `${zak.filter((x) => x.pn === 1).length} z ${zak.filter((x) => x.pn).length} s jedinou nabídkou`],
    [ns.length ? (100 * median(ns)).toFixed(1).replace(".", ",") + " %" : "–", "vítěz levnější než druhý", `medián z ${ns.length} soutěží`],
  ].map(([c, p, s]) => `<div class="karta"><div class="dl-cislo">${c}</div><div class="dl-popis">${p}</div><div class="dl-pod">${s}</div></div>`).join("");
  grafRozlozeni($("#c-graf"), ceny);
  tabulka($("#t-cena"), SL_C, r, stavC);
}
function grafRozlozeni(el, ceny) {
  const c = ceny.filter((x) => x > 0);
  if (c.length < 3) { el.innerHTML = '<p class="tlumene">Málo dat pro graf – zkuste obecnější hledání.</p>'; return; }
  const lo = Math.floor(Math.log10(Math.min(...c)) * 4) / 4, hi = Math.ceil(Math.log10(Math.max(...c)) * 4) / 4 + 0.25;
  const n = Math.max(1, Math.round((hi - lo) * 4)), bins = Array(n).fill(0);
  for (const x of c) bins[Math.min(n - 1, Math.floor((Math.log10(x) - lo) * 4))]++;
  const W = 640, H = 180, L = 30, B = 34, max = Math.max(...bins), sw = (W - L) / n, med = median(c);
  const xm = L + (Math.log10(med) - lo) * 4 * sw;
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Rozložení cen">${bins.map((b, i) => {
    const h = (H - B - 10) * b / max, x = L + i * sw;
    return `<rect class="sl" x="${x + 1}" y="${H - B - h}" width="${Math.max(1, sw - 2)}" height="${h}"><title>${kcK(10 ** (lo + i / 4))} – ${kcK(10 ** (lo + (i + 1) / 4))}: ${b}</title></rect>`
      + (i % 2 === 0 ? `<text x="${x}" y="${H - 18}">${kcK(10 ** (lo + i / 4)).replace(" Kč", "")}</text>` : "");
  }).join("")}<line x1="${xm}" x2="${xm}" y1="6" y2="${H - B}" stroke="var(--s2)" stroke-dasharray="4 3"/><text x="${xm + 4}" y="14">medián ${kcK(med)}</text>
    <text x="${L}" y="${H - 2}">cena bez DPH (logaritmická osa)</text></svg>`;
}
napoj(["#c-hledat", "#c-kat", "#c-kraj"], kresliCenu);

/* ------------------------------------------------------------------ KDE VYDĚLAT */
function kresliTrhy() {
  const ted = dnes(), r1 = posun(-365), r2 = posun(-730), srovnat = SML_OD && SML_OD <= posun(-700), katF = $("#m-kat").value, jenMoje = $("#m-moje").checked;
  const m = new Map();
  const bunka = (k, kr) => { const key = k + "|" + kr; if (!m.has(key)) m.set(key, { kat: k, kr, h: 0, hp: 0, c: 0, dod: new Map(), zak: 0, jedna: 0, snab: 0, zrus: 0 }); return m.get(key); };
  for (const s of D.smlouvy) {
    if (!s.d || s.d > ted || s.d < r2 || !s.kr) continue;
    for (const k of seznam(s.kat)) {
      if ((katF && k !== katF) || (jenMoje && !S.obory.includes(k))) continue;
      const b = bunka(k, s.kr);
      if (s.d >= r1) { b.h += s.h || 0; b.c++; const key = s.di || s.do; b.dod.set(key, (b.dod.get(key) || 0) + (s.h || 0)); } else b.hp += s.h || 0;
    }
  }
  for (const z of D.zakazky) {
    if (!z.kr || (z.dz || "") < r1) continue;
    for (const k of seznam(z.kat)) {
      if ((katF && k !== katF) || (jenMoje && !S.obory.includes(k))) continue;
      const b = bunka(k, z.kr); b.zak++; if (z.s === "zrušen") b.zrus++; if (z.pn > 0) { b.snab++; if (z.pn === 1) b.jedna++; }
    }
  }
  const radky = [...m.values()].filter((b) => b.c >= 3).map((b) => {
    const d = [...b.dod.values()].sort((x, y) => y - x), top3 = d.slice(0, 3).reduce((s, x) => s + x, 0);
    return { ...b, dodavatelu: d.length, top3: b.h ? top3 / b.h : null, zmena: srovnat && b.hp ? (b.h - b.hp) / b.hp : null, jednaPct: b.snab >= 5 ? b.jedna / b.snab : null, zrusPct: b.zak >= 5 ? b.zrus / b.zak : null };
  });
  const pct = (x) => (x == null ? "" : Math.round(100 * x) + " %");
  const st = window._stavT || (window._stavT = { razeni: "h", smer: -1 });
  st.prekresli = kresliTrhy;
  tabulka($("#t-trhy"), [
    { k: "kat", t: "Obor", f: (b) => esc(b.kat) }, { k: "kr", t: "Kraj", f: (b) => esc(b.kr) },
    { k: "h", t: SML_OD > r1 ? "Objem od " + datum(SML_OD) : "Objem 12 měs.", c: 1, f: (b) => kcK(b.h) },
    { k: "zmena", t: srovnat ? "Změna proti předchozím 12 měs." : `Změna (až budou 2 roky dat)`, c: 1, f: (b) => b.zmena == null ? "" : `${b.zmena > 0 ? "+" : ""}${pct(b.zmena)}` },
    { k: "c", t: "Smluv", c: 1, f: (b) => cislo(b.c) },
    { k: "dodavatelu", t: "Dodavatelů", c: 1, f: (b) => cislo(b.dodavatelu) },
    { k: "top3", t: "Podíl 3 největších", c: 1, f: (b) => pct(b.top3) },
    { k: "jednaPct", t: "Jediná nabídka", c: 1, f: (b) => pct(b.jednaPct) },
    { k: "zrusPct", t: "Zrušeno", c: 1, f: (b) => pct(b.zrusPct) },
  ], radky, st);
  const so = window._stavO || (window._stavO = { razeni: "pocet", smer: -1 });
  so.prekresli = kresliTrhy;
  tabulka($("#t-opak"), [
    { k: "zd", t: "Zadavatel", f: (g) => `<a href="#" data-ucet="${esc(g.zi)}">${esc(g.zd)}</a><div class="tlumene">${esc(g.kr)}</div>` },
    { k: "n", t: "Poptávka (poslední vypsání)", sir: 1, f: (g) => `${odkaz(g.u, g.n)}<div class="tlumene">${esc(g.kat.join(", "))}</div>` },
    { k: "pocet", t: "Vypsáno", c: 1, f: (g) => cislo(g.pocet) }, { k: "zrus", t: "Zrušeno", c: 1, f: (g) => g.zrus || "" },
    { k: "cena", t: "Poslední cena", c: 1, f: (g) => kcK(g.cena) }, { k: "vitez", t: "Vítěz", f: (g) => esc(g.vitez) },
    { k: "do", t: "Naposledy", f: (g) => datum(g.do) },
  ], OPAK.filter((g) => (!jenMoje || shoda(g.kat)) && (!katF || g.kat.includes(katF)) && vUzemi(g.kr, "")), so);
  const pt = new Map();
  for (const p of D.projekty) { if (!p.a) continue; const t = String(p.t || "jiné").replace(/_/g, " "); const v = pt.get(t) || { t, pop: 0, nab: 0, fin: 0 }; if (p.sm === "poptavka") v.pop++; else if (p.sm === "nabidka") v.nab++; else v.fin++; pt.set(t, v); }
  $("#t-poptavka").innerHTML = `<thead><tr><th>Typ projektu</th><th class="cis">Shání se</th><th class="cis">Nabízí se</th><th class="cis">Financuje se</th><th class="cis">Poměr</th></tr></thead><tbody>` +
    [...pt.values()].filter((v) => v.pop + v.nab >= 5).sort((a, b) => (b.pop / (b.nab + 1)) - (a.pop / (a.nab + 1))).slice(0, 25)
      .map((v) => `<tr><td>${esc(v.t)}</td><td class="cis">${v.pop}</td><td class="cis">${v.nab}</td><td class="cis">${v.fin || ""}</td><td class="cis">${(v.pop / Math.max(1, v.nab)).toFixed(1).replace(".", ",")}×</td></tr>`).join("") + "</tbody>";
  const mez = D.souvislosti.trh.filter((t) => t.kraj !== "celá ČR" && t.kategorie !== "vše" && +t.s_nabidkami >= 8 && (!jenMoje || S.obory.includes(t.kategorie)))
    .sort((a, b) => +b.jedna_nabidka_pct - +a.jedna_nabidka_pct).slice(0, 25);
  $("#t-mezery").innerHTML = `<thead><tr><th>Obor</th><th>Kraj</th><th class="cis">Jediná nabídka</th><th class="cis">Zakázek</th><th class="cis">Medián ceny</th></tr></thead><tbody>` +
    mez.map((t) => `<tr><td>${esc(t.kategorie)}</td><td>${esc(t.kraj)}</td><td class="cis"><b>${esc(t.jedna_nabidka_pct)} %</b></td><td class="cis">${esc(t.s_nabidkami)}</td><td class="cis">${kcK(+t.median_cena)}</td></tr>`).join("") + "</tbody>";
}
napoj(["#m-kat", "#m-moje"], kresliTrhy);

/* ------------------------------------------------------------------ NASTAVENÍ */
function kresliNastaveni() {
  $("#n-obory").innerHTML = OBORY.map((o) => `<label><input type="checkbox" data-obor="${esc(o)}"${S.obory.includes(o) ? " checked" : ""}> ${esc(o)}</label>`).join("");
  $("#n-kraje").innerHTML = `<label><input type="checkbox" data-kraj=""${!S.kraje.length ? " checked" : ""}> celá ČR</label>` + KRAJE.map((k) => `<label><input type="checkbox" data-kraj="${esc(k)}"${S.kraje.includes(k) ? " checked" : ""}> ${esc(k)}</label>`).join("");
  $("#n-ico").value = S.ico || "";
}
document.addEventListener("change", (e) => {
  const t = e.target;
  if (t.dataset.obor !== undefined) { S.obory = [...document.querySelectorAll("[data-obor]:checked")].map((x) => x.dataset.obor); }
  else if (t.dataset.kraj !== undefined) {
    if (t.dataset.kraj === "") { S.kraje = []; document.querySelectorAll("[data-kraj]").forEach((x) => (x.checked = x.dataset.kraj === "")); }
    else { S.kraje = [...document.querySelectorAll("[data-kraj]:checked")].map((x) => x.dataset.kraj).filter(Boolean); const v = document.querySelector('[data-kraj=""]'); if (v) v.checked = !S.kraje.length; }
  } else if (t.id === "n-ico") { S.ico = (t.value.match(/\d{8}/) || [""])[0]; }
  else return;
  ulozS(); KONK = null; sestavLeady(); sestavUcty(); sestavObjevy();
});
