"use strict";
/* Datasety – přehled. Data (data.enc) jsou šifrovaná AES-256-GCM; klíč = PBKDF2-SHA256(heslo, sůl, iterace).
   Stejné parametry používá prehled/export.py v repozitáři datasety. */

const SOUBOR = "data.enc";
const INFO = "info.json";
const KONTROLA_MS = 3 * 60 * 1000; // jak často se ptát, zda boti nepřinesli nová data
const ULOZ_KLIC = "prehled-klic-v1";
const NA_STRANKU = 200;

let D = null;          // dešifrovaná data
let KLIC = null;       // CryptoKey
let VERZE = null;      // "vytvoreno" aktuálně načtených dat
const $ = (s) => document.querySelector(s);

/* ------------------------------------------------------------------ úložiště (může selhat) */
const uloz = {
  cti(k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
  pis(k, v) { try { localStorage.setItem(k, v); } catch (e) { /* nic */ } },
  smaz(k) { try { localStorage.removeItem(k); } catch (e) { /* nic */ } },
};

/* ------------------------------------------------------------------ kryptografie */
const b64naBajty = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const bajtyNaB64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));

async function stahniObalku() {
  const r = await fetch(SOUBOR + "?t=" + Date.now(), { cache: "no-store" });
  if (!r.ok) throw new Error("Data se nepodařilo stáhnout (" + r.status + ").");
  return r.json();
}

async function klicZHesla(heslo, obalka) {
  const zaklad = await crypto.subtle.importKey("raw", new TextEncoder().encode(heslo), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt: b64naBajty(obalka.sul), iterations: obalka.iter },
    zaklad, { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
}

async function desifruj(obalka, klic) {
  const zip = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64naBajty(obalka.iv) }, klic, b64naBajty(obalka.data));
  const proud = new Blob([zip]).stream().pipeThrough(new DecompressionStream("gzip"));
  return JSON.parse(await new Response(proud).text());
}

/* ------------------------------------------------------------------ přihlášení */
async function otevri(data, klic) {
  D = data; KLIC = klic; VERZE = data.vytvoreno;
  $("#zamek").hidden = true; $("#aplikace").hidden = false;
  pripravData(); vykresliVse();
  setInterval(zkontrolujNovaData, KONTROLA_MS);
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
    if ($("#pamatovat").checked) {
      uloz.pis(ULOZ_KLIC, JSON.stringify({ sul: obalka.sul, k: bajtyNaB64(await crypto.subtle.exportKey("raw", klic)) }));
    }
    $("#heslo").value = "";
    await otevri(data, klic);
  } catch (x) {
    chyba.textContent = x.message; chyba.hidden = false;
  } finally { tl.disabled = false; tl.textContent = "Otevřít"; }
});

$("#odhlasit").addEventListener("click", () => { uloz.smaz(ULOZ_KLIC); location.reload(); });

(async function automatickePrihlaseni() {
  const ul = uloz.cti(ULOZ_KLIC);
  if (!ul) return;
  try {
    const { sul, k } = JSON.parse(ul);
    const obalka = await stahniObalku();
    if (obalka.sul !== sul) { uloz.smaz(ULOZ_KLIC); return; }
    const klic = await crypto.subtle.importKey("raw", b64naBajty(k), "AES-GCM", false, ["decrypt"]);
    await otevri(await desifruj(obalka, klic), klic);
  } catch (x) { uloz.smaz(ULOZ_KLIC); }
})();

/* ------------------------------------------------------------------ "realtime": nová data od botů */
async function zkontrolujNovaData() {
  try {
    const r = await fetch(INFO + "?t=" + Date.now(), { cache: "no-store" });
    if (!r.ok) return;
    const info = await r.json();
    if (!info.vytvoreno || info.vytvoreno === VERZE) return;
    const data = await desifruj(await stahniObalku(), KLIC);
    D = data; VERZE = data.vytvoreno;
    pripravData(); vykresliVse(true);
  } catch (x) { /* zkusí se příště */ }
}

/* ------------------------------------------------------------------ číselníky a pomocné funkce */
const POPISY = {
  zdroj: { cevd: "CEVD (dražby)", uzsvm: "ÚZSVM", nnm: "Nepotřebný majetek státu", spu: "SPÚ", edesky: "Úřední desky (exekuce)" },
  druh: {
    nabidka_statni_organizace: "nabídka státní organizace", aukce_stat: "elektronická aukce státu",
    drazba_dobrovolna: "dražba dobrovolná", drazba_nedobrovolna: "dražba nedobrovolná", drazba_exekucni: "dražba exekuční",
    drazba_insolvence: "dražba v insolvenci", drazba_jiny: "dražba – jiná", nabidka_spu_stavby: "SPÚ – stavby",
    nabidka_stat_prodej: "prodej státu",
  },
  stav: {
    archiv: "archiv", bez_podani: "bez podání", ukonceno_s_podanim: "ukončeno s podáním", zverejneno: "zveřejněno",
    vydrazeno: "vydraženo", vyhlaseno: "vyhlášeno", aktivni: "aktivní", zruseno: "zrušeno",
    probehla_vysledek_neznamy: "proběhla (výsledek neznámý)", zmarena: "zmařena", ukoncena_prekazkou: "ukončena překážkou",
    stazeno: "staženo", zmizelo: "zmizelo ze zdroje",
  },
  typ: { pozemek: "pozemek", stavba: "stavba", dum: "dům", byt: "byt", jine: "jiné", komercni: "komerční" },
  dtyp: {
    uzemni_plan: "územní plán", prodej_majetku: "prodej majetku obce", ochrana_prirody: "ochrana přírody",
    rozhodnuti_stavebni: "stavební rozhodnutí", vyzva_zakazka: "výzva / zakázka", zahajeni_rizeni: "zahájení řízení",
    jine: "jiné", dotace: "dotace", usneseni: "usnesení", povoleni_zameru: "povolení záměru", drazba: "dražba",
    stavebni_zamer: "stavební záměr", uzemni_studie: "územní studie", environmentalni_stanovisko: "EIA / stanovisko",
    uzemni_rozhodnuti: "územní rozhodnutí", projektova_dokumentace: "projektová dokumentace", eia: "EIA",
    pozvanka_zasedani: "pozvánka na zasedání", stavebni_povoleni: "stavební povolení", pozemkove_upravy: "pozemkové úpravy",
  },
  faze: {
    navrh_na_porizeni: "návrh na pořízení", rozhodnuti_o_porizeni: "rozhodnutí o pořízení", zadani: "zadání",
    spolecne_jednani: "společné jednání", verejne_projednani: "veřejné projednání", vydani: "vydání",
  },
  udalost: { zmena_stavu: "změna stavu", zmena: "změna", zmizelo: "zmizelo", cena: "změna ceny" },
};
const pop = (skup, k) => (POPISY[skup] && POPISY[skup][k]) || (k ? String(k).replace(/_/g, " ") : "");
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const cislo = (n) => (n == null || n === "" ? "" : Number(n).toLocaleString("cs-CZ"));
const kc = (n) => (n == null || n === "" ? "" : Number(n).toLocaleString("cs-CZ") + " Kč");
const datum = (s) => { if (!s) return ""; const [r, m, d] = s.slice(0, 10).split("-"); return d ? `${+d}. ${+m}. ${r}` : s; };
const dnesIso = () => new Date().toISOString().slice(0, 10);
const predDny = (n) => new Date(Date.now() - n * 864e5).toISOString().slice(0, 10);
const odkaz = (u, t) => (u ? `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(t)}</a>` : esc(t));

let NAB_PODLE_KLICE = new Map(), DOK_PODLE_ID = new Map();
function pripravData() {
  NAB_PODLE_KLICE = new Map(D.nabidky.map((x) => [x.k, x]));
  DOK_PODLE_ID = new Map(D.dokumenty.map((x) => [x.id, x]));
  naplnVyber("#n-zdroj", D.nabidky, "z", "zdroj");
  naplnVyber("#n-stav", D.nabidky, "s", "stav");
  naplnVyber("#n-typ", D.nabidky, "t", "typ");
  naplnVyber("#m-typ", D.nabidky, "t", "typ");
  naplnVyber("#n-okres", D.nabidky, "ok");
  naplnVyber("#d-typ", D.dokumenty, "t", "dtyp");
  naplnVyber("#m-dtyp", D.dokumenty, "t", "dtyp");
  naplnVyber("#d-kraj", D.dokumenty, "kr");
  naplnVyber("#u-faze", D.zmeny_up, "f", "faze");
  naplnVyber("#u-kraj", D.zmeny_up, "kr");
  const st = $("#stari");
  st.textContent = "data: " + datum(D.vytvoreno) + " " + (D.vytvoreno || "").slice(11, 16);
}

function naplnVyber(sel, radky, pole, skup) {
  const el = $(sel), puvodni = el.value, prvni = el.options[0].outerHTML;
  const pocty = new Map();
  for (const r of radky) if (r[pole]) pocty.set(r[pole], (pocty.get(r[pole]) || 0) + 1);
  const hodnoty = [...pocty.keys()].sort((a, b) => (skup ? pocty.get(b) - pocty.get(a) : a.localeCompare(b, "cs")));
  el.innerHTML = prvni + hodnoty.map((h) => `<option value="${esc(h)}">${esc(skup ? pop(skup, h) : h)} (${pocty.get(h)})</option>`).join("");
  el.value = hodnoty.includes(puvodni) ? puvodni : "";
}

/* ------------------------------------------------------------------ záložky */
let ZALOZKA = "prehled";
const vykreslene = new Set();
$("#zalozky").addEventListener("click", (e) => {
  const b = e.target.closest("button[data-z]"); if (!b) return;
  ZALOZKA = b.dataset.z;
  document.querySelectorAll("#zalozky button").forEach((x) => x.classList.toggle("aktivni", x === b));
  document.querySelectorAll(".zalozka").forEach((s) => (s.hidden = s.id !== "z-" + ZALOZKA));
  uloz.pis("prehled-zalozka", ZALOZKA);
  vykresliZalozku();
});

const KRESLI = {
  prehled: kresliPrehled, mapa: kresliMapu, nabidky: kresliNabidky, desky: kresliDesky, up: kresliUp, stav: kresliStav,
};
function vykresliZalozku() { KRESLI[ZALOZKA](); vykreslene.add(ZALOZKA); }
function vykresliVse(obnova) {
  if (!obnova) {
    const ul = uloz.cti("prehled-zalozka");
    const b = ul && document.querySelector(`#zalozky button[data-z="${ul}"]`);
    if (b) { b.click(); return; }
  }
  vykreslene.clear(); vykresliZalozku();
}

/* ------------------------------------------------------------------ tooltip */
const tip = $("#tooltip");
function ukazTip(e, html) {
  tip.innerHTML = html; tip.hidden = false;
  const x = Math.min(e.clientX + 12, innerWidth - tip.offsetWidth - 8);
  tip.style.left = x + "px"; tip.style.top = (e.clientY + 12) + "px";
}
const skryjTip = () => (tip.hidden = true);

/* ------------------------------------------------------------------ grafy (SVG) */
function grafSloupce(el, data, popisHodnoty) {
  // data: [{l: popisek, v: hodnota, t: text tooltipu}]
  const W = 640, H = 220, L = 36, B = 26, T = 10, R = 6;
  const max = Math.max(1, ...data.map((d) => d.v));
  const krok = hezkyKrok(max), vrch = Math.ceil(max / krok) * krok;
  const sw = (W - L - R) / data.length, y = (v) => T + (H - T - B) * (1 - v / vrch);
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img">`;
  for (let v = 0; v <= vrch; v += krok) s += `<line class="mriz" x1="${L}" x2="${W - R}" y1="${y(v)}" y2="${y(v)}"/><text x="${L - 6}" y="${y(v) + 4}" text-anchor="end">${cislo(v)}</text>`;
  data.forEach((d, i) => {
    const x = L + i * sw + 1, w = Math.max(1, sw - 2), h = y(0) - y(d.v);
    if (d.v > 0) s += `<path class="sl" data-i="${i}" d="M${x},${y(0)} v${-(h - Math.min(4, h))} q0,${-Math.min(4, h)} ${Math.min(4, w / 2)},${-Math.min(4, h)} h${w - 2 * Math.min(4, w / 2)} q${Math.min(4, w / 2)},0 ${Math.min(4, w / 2)},${Math.min(4, h)} v${h - Math.min(4, h)} z"/>`;
    s += `<rect data-i="${i}" x="${L + i * sw}" y="${T}" width="${sw}" height="${H - T - B}" fill="transparent"/>`;
    if (i % Math.ceil(data.length / 8) === 0) s += `<text x="${x + w / 2}" y="${H - 8}" text-anchor="middle">${esc(d.l)}</text>`;
  });
  s += `<line class="osa" x1="${L}" x2="${W - R}" y1="${y(0)}" y2="${y(0)}"/></svg>`;
  el.innerHTML = s;
  el.onmousemove = (e) => {
    const i = e.target.dataset && e.target.dataset.i;
    el.querySelectorAll(".sl").forEach((p) => p.classList.toggle("hover", p.dataset.i === i));
    if (i == null) return skryjTip();
    ukazTip(e, data[i].t || `${esc(data[i].l)}: <b>${cislo(data[i].v)}</b> ${popisHodnoty || ""}`);
  };
  el.onmouseleave = () => { skryjTip(); el.querySelectorAll(".sl").forEach((p) => p.classList.remove("hover")); };
}

function grafVodorovne(el, data, popisHodnoty) {
  const W = 640, radek = 22, L = 150, R = 50, H = data.length * radek + 6;
  const max = Math.max(1, ...data.map((d) => d.v));
  let s = `<svg viewBox="0 0 ${W} ${H}" role="img">`;
  data.forEach((d, i) => {
    const y = i * radek + 3, w = Math.max(2, (W - L - R) * d.v / max), r = Math.min(4, w / 2);
    s += `<text x="${L - 8}" y="${y + 14}" text-anchor="end">${esc(d.l)}</text>`;
    s += `<path class="sl" data-i="${i}" d="M${L},${y + 2} h${w - r} q${r},0 ${r},${r} v${16 - 2 * r} q0,${r} ${-r},${r} h${-(w - r)} z"/>`;
    s += `<text class="hodnota" x="${L + w + 6}" y="${y + 14}">${cislo(d.v)}</text>`;
    s += `<rect data-i="${i}" x="0" y="${y}" width="${W}" height="${radek}" fill="transparent"/>`;
  });
  el.innerHTML = s + `<line class="osa" x1="${L}" x2="${L}" y1="0" y2="${H}"/></svg>`;
  el.onmousemove = (e) => {
    const i = e.target.dataset && e.target.dataset.i;
    el.querySelectorAll(".sl").forEach((p) => p.classList.toggle("hover", p.dataset.i === i));
    if (i == null) return skryjTip();
    ukazTip(e, `${esc(data[i].l)}: <b>${cislo(data[i].v)}</b> ${popisHodnoty || ""}`);
  };
  el.onmouseleave = () => { skryjTip(); el.querySelectorAll(".sl").forEach((p) => p.classList.remove("hover")); };
}

function hezkyKrok(max) {
  const hrube = max / 4, mag = 10 ** Math.floor(Math.log10(hrube)), n = hrube / mag;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * mag;
}

function pondeli(iso) {
  const d = new Date(iso + "T00:00:00Z"); d.setUTCDate(d.getUTCDate() - ((d.getUTCDay() + 6) % 7));
  return d.toISOString().slice(0, 10);
}

/* ------------------------------------------------------------------ PŘEHLED */
function kresliPrehled() {
  const t7 = predDny(7), t30 = predDny(30);
  const aktivni = D.nabidky.filter((x) => x.a);
  const drazby = aktivni.filter((x) => x.z === "cevd" || x.z === "edesky");
  const dok7 = D.dokumenty.filter((x) => x.dt >= t7);
  const up30 = D.zmeny_up.filter((x) => x.df >= t30);
  const nove7 = D.nabidky.filter((x) => (x.dz || x.pz) >= t7);
  const dl = [
    [cislo(aktivni.length), "aktivních nabídek a dražeb", `z toho ${cislo(drazby.length)} dražeb`],
    [cislo(nove7.length), "nově zveřejněných nabídek za 7 dní", ""],
    [cislo(dok7.length), "dokumentů z úředních desek za 7 dní", `${cislo(dok7.filter((x) => !x.h).length)} bez hlučných`],
    [cislo(up30.length), "územních plánů s pohybem za 30 dní", `sledováno ${cislo(D.zmeny_up.length)}`],
    [cislo(D.dokumenty.filter((x) => x.t === "vyzva_zakazka" && x.lh && x.lh >= dnesIso()).length), "výzev s běžící lhůtou", ""],
  ];
  $("#dlazdice").innerHTML = dl.map(([c, p, s]) =>
    `<div class="karta"><div class="dl-cislo">${c}</div><div class="dl-popis">${p}</div><div class="dl-pod">${s}</div></div>`).join("");

  // dokumenty po týdnech (26 týdnů)
  const tydny = []; let t = pondeli(dnesIso());
  for (let i = 0; i < 26; i++) { tydny.unshift(t); const d = new Date(t + "T00:00:00Z"); d.setUTCDate(d.getUTCDate() - 7); t = d.toISOString().slice(0, 10); }
  const pocty = new Map(tydny.map((x) => [x, 0]));
  for (const x of D.dokumenty) { if (!x.dt) continue; const p = pondeli(x.dt); if (pocty.has(p)) pocty.set(p, pocty.get(p) + 1); }
  grafSloupce($("#g-tydny"), tydny.map((x) => ({ l: datum(x).replace(/ \d{4}$/, ""), v: pocty.get(x), t: `týden od ${datum(x)}: <b>${cislo(pocty.get(x))}</b> dokumentů` })), "dokumentů");

  const okr = new Map();
  for (const x of aktivni) if (x.ok) okr.set(x.ok, (okr.get(x.ok) || 0) + 1);
  grafVodorovne($("#g-okresy"), [...okr].sort((a, b) => b[1] - a[1]).slice(0, 15).map(([l, v]) => ({ l, v })), "aktivních nabídek");

  const dokSer = dok7.filter((x) => !x.h).sort((a, b) => (b.dt > a.dt ? 1 : -1)).slice(0, 80);
  $("#nove-desky").innerHTML = dokSer.length ? dokSer.map((x) =>
    `<div class="polozka"><span class="stitek">${esc(pop("dtyp", x.t))}</span><div>${odkaz(x.u, x.n)}</div>
     <div class="meta">${esc(x.d)} · ${esc(x.ok)} · ${datum(x.dt)}${x.ku ? " · k.ú. " + esc(x.ku) : ""}</div></div>`).join("")
    : `<p class="tlumene">Za posledních 7 dní nic.</p>`;

  const zm = D.zmeny.filter((x) => x.datum >= t7).sort((a, b) => (b.datum > a.datum ? 1 : -1)).slice(0, 80);
  $("#nove-zmeny").innerHTML = zm.length ? zm.map((x) => {
    const n = NAB_PODLE_KLICE.get(x.klic) || {};
    const co = x.pole === "stav" ? `${esc(pop("stav", x.stara))} → <b>${esc(pop("stav", x.nova))}</b>`
      : `${esc(x.pole)}: ${esc(x.stara)} → <b>${esc(x.nova)}</b>`;
    return `<div class="polozka"><span class="stitek">${esc(pop("udalost", x.udalost))}</span><div>${odkaz(n.u, n.n || x.klic)}</div>
      <div class="meta">${co} · ${esc(pop("zdroj", n.z))} · ${datum(x.datum)}</div></div>`;
  }).join("") : `<p class="tlumene">Za posledních 7 dní žádné změny.</p>`;
}

/* ------------------------------------------------------------------ tabulky (společné) */
function tabulka(el, sloupce, radky, stav) {
  // sloupce: [{k: klíč řazení, t: titulek, f: (r)=>html, c: číselný?}]
  stav.n = stav.n || NA_STRANKU;
  if (stav.razeni) {
    const s = sloupce.find((x) => x.k === stav.razeni), sm = stav.smer;
    const hod = s.h || ((r) => r[s.k]);
    radky = [...radky].sort((a, b) => {
      const x = hod(a), y = hod(b);
      if (x == null || x === "") return 1; if (y == null || y === "") return -1;
      return (s.c ? x - y : String(x).localeCompare(String(y), "cs")) * sm;
    });
  }
  const zobraz = radky.slice(0, stav.n);
  el.innerHTML = `<thead><tr>${sloupce.map((s) => `<th data-k="${s.k}" class="${s.c ? "cis" : ""}">${esc(s.t)}${stav.razeni === s.k ? (stav.smer > 0 ? " ▲" : " ▼") : ""}</th>`).join("")}</tr></thead>
    <tbody>${zobraz.map((r) => `<tr>${sloupce.map((s) => `<td class="${s.c ? "cis" : ""}${s.sir ? " nazev-bunka" : ""}">${s.f(r)}</td>`).join("")}</tr>`).join("")}</tbody>
    ${radky.length > stav.n ? `<tfoot><tr><td colspan="${sloupce.length}" class="vice"><button class="maly" data-vice>Zobrazit dalších ${NA_STRANKU} (zbývá ${cislo(radky.length - stav.n)})</button></td></tr></tfoot>` : ""}`;
  el.querySelectorAll("th").forEach((th) => th.onclick = () => {
    stav.smer = stav.razeni === th.dataset.k ? -stav.smer : (sloupce.find((s) => s.k === th.dataset.k).c ? -1 : 1);
    stav.razeni = th.dataset.k; stav.prekresli();
  });
  const v = el.querySelector("[data-vice]"); if (v) v.onclick = () => { stav.n += NA_STRANKU; stav.prekresli(); };
}

function stahniCsv(nazev, sloupce, radky) {
  const q = (v) => { const s = String(v ?? ""); return /[;"\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  const text = "﻿" + sloupce.map((s) => q(s[0])).join(";") + "\n" + radky.map((r) => sloupce.map((s) => q(s[1](r))).join(";")).join("\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "text/csv;charset=utf-8" }));
  a.download = `${nazev}-${dnesIso()}.csv`; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

function napoj(ids, fn) {
  ids.forEach((id) => { const el = $(id); el.oninput = el.onchange = () => fn(true); });
}
const hledej = (text, ...pole) => { const t = text.trim().toLowerCase(); return !t || pole.some((p) => (p || "").toLowerCase().includes(t)); };

/* ------------------------------------------------------------------ NABÍDKY */
const stavN = { razeni: "pz", smer: -1 };
function filtrNabidky() {
  const h = $("#n-hledat").value, z = $("#n-zdroj").value, s = $("#n-stav").value, t = $("#n-typ").value, o = $("#n-okres").value, a = $("#n-aktivni").checked;
  return D.nabidky.filter((x) => (!z || x.z === z) && (!s || x.s === s) && (!t || x.t === t) && (!o || x.ok === o) && (!a || x.a) && hledej(h, x.n, x.ku, x.p, x.ok));
}
const SL_NAB = [
  { k: "pz", t: "Zachyceno", f: (r) => datum(r.pz) },
  { k: "n", t: "Předmět", sir: 1, f: (r) => `${odkaz(r.u, r.n)}<div class="tlumene">${esc(pop("typ", r.t))}${r.dp ? " · " + esc(r.dp) : ""}${r.po ? " · podíl " + esc(r.po) : ""}</div>` },
  { k: "z", t: "Zdroj", f: (r) => `${esc(pop("zdroj", r.z))}<div class="tlumene">${esc(pop("druh", r.dr))}</div>` },
  { k: "s", t: "Stav", f: (r) => `<span class="stitek${r.a ? " ok" : ""}">${esc(pop("stav", r.s))}</span>${r.op === "1" ? ' <span class="stitek">opakovaná</span>' : ""}` },
  { k: "ok", t: "Okres / k.ú.", f: (r) => `${esc(r.ok)}<div class="tlumene">${esc(r.ku)}</div>` },
  { k: "v", t: "Výměra m²", c: 1, f: (r) => cislo(r.v) },
  { k: "cv", t: "Vyvolávací cena", c: 1, f: (r) => kc(r.cv) },
  { k: "co", t: "Odhad", c: 1, f: (r) => kc(r.co) },
  { k: "cd", t: "Dosažená", c: 1, f: (r) => kc(r.cd) + (r.dk ? `<div class="tlumene">${esc(r.dk)} × odhad</div>` : "") },
  { k: "cm", t: "Kč/m²", c: 1, f: (r) => cislo(r.cm) },
  { k: "da", t: "Konání", f: (r) => datum(r.da || r.dz) },
  { k: "p", t: "Prodávající", f: (r) => esc(r.p) },
];
function kresliNabidky(zpet) {
  if (zpet === true) stavN.n = NA_STRANKU;
  stavN.prekresli = kresliNabidky;
  const r = filtrNabidky();
  $("#n-pocet").textContent = `${cislo(r.length)} záznamů`;
  tabulka($("#t-nabidky"), SL_NAB, r, stavN);
}
napoj(["#n-hledat", "#n-zdroj", "#n-stav", "#n-typ", "#n-okres", "#n-aktivni"], kresliNabidky);
$("#n-csv").onclick = () => stahniCsv("nabidky", [
  ["klic", (r) => r.k], ["zdroj", (r) => r.z], ["druh", (r) => r.dr], ["stav", (r) => r.s], ["aktivni", (r) => r.a],
  ["predmet_typ", (r) => r.t], ["nazev", (r) => r.n], ["prodavajici", (r) => r.p], ["okres", (r) => r.ok],
  ["katastralni_uzemi", (r) => r.ku], ["vymera_m2", (r) => r.v], ["druh_pozemku", (r) => r.dp], ["podil", (r) => r.po],
  ["cena_vyvolavaci", (r) => r.cv], ["cena_odhad", (r) => r.co], ["cena_dosazena", (r) => r.cd], ["cena_za_m2", (r) => r.cm],
  ["datum_zverejneni", (r) => r.dz], ["datum_zahajeni", (r) => r.da], ["datum_ukonceni", (r) => r.du],
  ["prvni_zachyceni", (r) => r.pz], ["url", (r) => r.u],
], filtrNabidky());

/* ------------------------------------------------------------------ ÚŘEDNÍ DESKY */
const stavD = { razeni: "dt", smer: -1 };
function filtrDesky() {
  const h = $("#d-hledat").value, t = $("#d-typ").value, k = $("#d-kraj").value, dny = +$("#d-obdobi").value, hl = $("#d-hlucne").checked;
  const od = dny ? predDny(dny) : "";
  return D.dokumenty.filter((x) => (!t || x.t === t) && (!k || x.kr === k) && (!od || x.dt >= od) && (hl || !x.h) && hledej(h, x.n, x.d, x.sn, x.ku, x.ok));
}
const SL_DOK = [
  { k: "dt", t: "Vyvěšeno", f: (r) => datum(r.dt) },
  { k: "n", t: "Dokument", sir: 1, f: (r) => `${odkaz(r.u, r.n)}<div class="tlumene">${[r.ds, r.pt && "příroda: " + r.pt, r.uf && "ÚP: " + pop("faze", r.uf), r.lh && "lhůta " + datum(r.lh)].filter(Boolean).map(esc).join(" · ")}</div>` },
  { k: "t", t: "Typ", f: (r) => `<span class="stitek">${esc(pop("dtyp", r.t))}</span>` },
  { k: "d", t: "Deska", f: (r) => `${esc(r.d)}<div class="tlumene">${esc(r.ok)}</div>` },
  { k: "ku", t: "K.ú. / parcely", f: (r) => `${esc(r.ku)}<div class="tlumene">${esc((r.par || "").slice(0, 80))}</div>` },
  { k: "sn", t: "Stavebník", f: (r) => r.st === "fyzicka_osoba" ? '<span class="tlumene">fyzická osoba</span>' : `${esc(r.sn)}${r.si ? `<div class="tlumene">IČO ${esc(r.si)}</div>` : ""}` },
  { k: "zp", t: "Zastavěná m²", c: 1, f: (r) => cislo(r.zp) },
  { k: "op", t: "Obestavěný m³", c: 1, f: (r) => cislo(r.op) },
];
function kresliDesky(zpet) {
  if (zpet === true) stavD.n = NA_STRANKU;
  stavD.prekresli = kresliDesky;
  const r = filtrDesky();
  $("#d-pocet").textContent = `${cislo(r.length)} dokumentů`;
  tabulka($("#t-desky"), SL_DOK, r, stavD);
}
napoj(["#d-hledat", "#d-typ", "#d-kraj", "#d-obdobi", "#d-hlucne"], kresliDesky);
$("#d-csv").onclick = () => stahniCsv("uredni-desky", [
  ["edesky_id", (r) => r.id], ["nacteno", (r) => r.dt], ["typ", (r) => r.t], ["nazev", (r) => r.n], ["deska", (r) => r.d],
  ["kraj", (r) => r.kr], ["okres", (r) => r.ok], ["katastralni_uzemi", (r) => r.ku], ["parcely", (r) => r.par],
  ["stavebnik_typ", (r) => r.st], ["stavebnik", (r) => (r.st === "fyzicka_osoba" ? "" : r.sn)], ["stavebnik_ico", (r) => r.si],
  ["druh_stavby", (r) => r.ds], ["zastavena_plocha_m2", (r) => r.zp], ["obestaveny_prostor_m3", (r) => r.op],
  ["lhuta", (r) => r.lh], ["priroda", (r) => r.pt], ["up_faze", (r) => r.uf], ["url", (r) => r.u],
], filtrDesky());

/* ------------------------------------------------------------------ ÚZEMNÍ PLÁNY */
const stavU = { razeni: "df", smer: -1 };
const FAZE_PORADI = ["navrh_na_porizeni", "rozhodnuti_o_porizeni", "zadani", "spolecne_jednani", "verejne_projednani", "vydani"];
function filtrUp() {
  const h = $("#u-hledat").value, f = $("#u-faze").value, k = $("#u-kraj").value;
  return D.zmeny_up.filter((x) => (!f || x.f === f) && (!k || x.kr === k) && hledej(h, x.ob, x.ok));
}
const SL_UP = [
  { k: "df", t: "Poslední pohyb", f: (r) => datum(r.df) },
  { k: "ob", t: "Obec", f: (r) => `<b>${esc(r.ob)}</b><div class="tlumene">${esc(r.ok)} · ${esc(r.kr)}</div>` },
  { k: "c", t: "Změna", f: (r) => `${esc(r.ur === "obec" ? "" : r.ur)} ${esc(r.c === "BEZ_CISLA" ? "změna (bez čísla)" : r.c ? "změna č. " + r.c : "územní plán")}${r.zk ? ' <span class="stitek">zkrácený postup</span>' : ""}` },
  { k: "f", t: "Fáze", h: (r) => FAZE_PORADI.indexOf(r.f), c: 0, f: (r) => `<span class="stitek">${esc(pop("faze", r.f))}</span>` },
  { k: "fd", t: "Průběh", h: () => 0, f: (r) => FAZE_PORADI.filter((f) => r.fd[f]).map((f) => `${esc(pop("faze", f))}: ${datum(r.fd[f])}`).join("<br>") },
  { k: "nd", t: "Dokumentů", c: 1, f: (r) => {
    const posl = DOK_PODLE_ID.get(r.ids[r.ids.length - 1]);
    return cislo(r.nd) + (posl && posl.u ? `<div>${odkaz(posl.u, "poslední")}</div>` : "");
  } },
];
function kresliUp(zpet) {
  if (zpet === true) stavU.n = NA_STRANKU;
  stavU.prekresli = kresliUp;
  const r = filtrUp();
  $("#u-pocet").textContent = `${cislo(r.length)} územních plánů a změn`;
  tabulka($("#t-up"), SL_UP, r, stavU);
}
napoj(["#u-hledat", "#u-faze", "#u-kraj"], kresliUp);
$("#u-csv").onclick = () => stahniCsv("uzemni-plany", [
  ["up_klic", (r) => r.k], ["obec", (r) => r.ob], ["okres", (r) => r.ok], ["kraj", (r) => r.kr], ["cislo_zmeny", (r) => r.c],
  ["faze_posledni", (r) => r.f], ["datum_posledni_faze", (r) => r.df],
  ...FAZE_PORADI.map((f) => ["datum_" + f, (r) => r.fd[f] || ""]), ["pocet_dokumentu", (r) => r.nd],
], filtrUp());

/* ------------------------------------------------------------------ STAV BOTŮ */
function kresliStav() {
  const tab = (el, radky) => {
    if (!radky.length) { el.innerHTML = "<tr><td>Zatím žádné běhy.</td></tr>"; return; }
    const kl = Object.keys(radky[0]);
    el.innerHTML = `<thead><tr>${kl.map((k) => `<th>${esc(k.replace(/_/g, " "))}</th>`).join("")}</tr></thead><tbody>` +
      [...radky].reverse().map((r) => `<tr>${kl.map((k) => `<td class="${/^\d+$/.test(r[k]) ? "cis" : ""}">${esc(r[k])}</td>`).join("")}</tr>`).join("") + "</tbody>";
  };
  tab($("#t-beh-edesky"), D.behy.edesky || []);
  tab($("#t-beh-majetek"), D.behy.majetek || []);
}

/* ------------------------------------------------------------------ MAPA */
let MAPA = null, VRSTVY = {};
const tmava = () => document.documentElement.dataset.theme === "dark" ||
  (document.documentElement.dataset.theme !== "light" && matchMedia("(prefers-color-scheme: dark)").matches);

function souradnice(m) {
  if (!m) return null;
  const b = (m[0] === "k" ? D.body.k : D.body.o)[m[1]];
  return b ? b : null;
}

function vytvorShluk(trida) {
  return L.markerClusterGroup({
    maxClusterRadius: 45, showCoverageOnHover: false, chunkedLoading: true,
    iconCreateFunction: (c) => {
      const n = c.getChildCount ? c.getAllChildMarkers().reduce((s, m) => s + (m.options.pocet || 1), 0) : 1;
      const v = n < 10 ? 28 : n < 100 ? 34 : n < 1000 ? 40 : 46;
      return L.divIcon({ html: `<div class="shluk ${trida}" style="width:${v}px;height:${v}px">${cislo(n)}</div>`, className: "", iconSize: [v, v] });
    },
  });
}

function kresliMapu() {
  if (!MAPA) {
    MAPA = L.map("mapa", { preferCanvas: true }).setView([49.8, 15.5], 7);
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18, attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>',
    }).addTo(MAPA);
    if (tmava()) document.documentElement.setAttribute("data-tmava", "");
    napoj(["#v-nabidky", "#v-desky", "#v-up", "#m-aktivni", "#m-typ", "#m-dtyp", "#m-obdobi"], kresliMapu);
  }
  setTimeout(() => MAPA.invalidateSize(), 0);
  Object.values(VRSTVY).forEach((v) => MAPA.removeLayer(v));
  VRSTVY = {};
  const dny = +$("#m-obdobi").value, od = dny ? predDny(dny) : "";
  const jenAkt = $("#m-aktivni").checked, typ = $("#m-typ").value, dtyp = $("#m-dtyp").value;
  let celkem = 0, bezMista = 0;

  const vrstva = (trida, radky, nadpis, polozka) => {
    const skup = new Map();
    for (const r of radky) {
      const b = souradnice(r.m);
      if (!b) { bezMista++; continue; }
      const k = r.m.join(":");
      if (!skup.has(k)) skup.set(k, { b, r: [] });
      skup.get(k).r.push(r);
    }
    const shluk = vytvorShluk(trida);
    const ikona = L.divIcon({ className: "znacka " + trida, iconSize: [14, 14] });
    for (const { b, r } of skup.values()) {
      celkem += r.length;
      const m = L.marker([b[0], b[1]], { icon: r.length > 1 ? L.divIcon({ html: `<div class="shluk ${trida}" style="width:24px;height:24px">${r.length}</div>`, className: "", iconSize: [24, 24] }) : ikona, pocet: r.length });
      m.bindPopup(() => `<h3>${esc(b[2])} – ${esc(nadpis)} (${r.length})</h3>` + r.slice(0, 50).map((x) => `<div class="pp">${polozka(x)}</div>`).join("") + (r.length > 50 ? `<div class="pp">… a dalších ${r.length - 50}</div>` : ""), { maxWidth: 360 });
      m.bindTooltip(`${esc(b[2])}: ${r.length}× ${esc(nadpis)}`);
      shluk.addLayer(m);
    }
    shluk.addTo(MAPA);
    return shluk;
  };

  if ($("#v-nabidky").checked) {
    const r = D.nabidky.filter((x) => (jenAkt ? x.a : (!od || (x.pz || x.dz) >= od)) && (!typ || x.t === typ));
    VRSTVY.n = vrstva("s1", r, "nabídky a dražby", (x) =>
      `${odkaz(x.u, x.n)}<br><span style="opacity:.75">${esc(pop("zdroj", x.z))} · ${esc(pop("stav", x.s))}${x.v ? " · " + cislo(x.v) + " m²" : ""}${x.cv ? " · " + kc(x.cv) : ""}${x.da ? " · " + datum(x.da) : ""}</span>`);
  }
  if ($("#v-desky").checked) {
    const r = D.dokumenty.filter((x) => !x.h && (!od || x.dt >= od) && (!dtyp || x.t === dtyp));
    VRSTVY.d = vrstva("s2", r, "dokumenty z úředních desek", (x) =>
      `${odkaz(x.u, x.n)}<br><span style="opacity:.75">${esc(pop("dtyp", x.t))} · ${esc(x.d)} · ${datum(x.dt)}</span>`);
  }
  if ($("#v-up").checked) {
    const r = D.zmeny_up.filter((x) => !od || x.df >= od);
    VRSTVY.u = vrstva("s3", r, "územní plány", (x) =>
      `<b>${esc(x.c === "BEZ_CISLA" ? "Změna (bez čísla)" : x.c ? "Změna č. " + x.c : "Územní plán")}</b> – ${esc(pop("faze", x.f))} (${datum(x.df)})`);
  }
  $("#m-pocet").textContent = `${cislo(celkem)} na mapě` + (bezMista ? ` · ${cislo(bezMista)} bez polohy` : "");
}
