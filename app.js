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
    kolaudace: "kolaudace",
  },
  zfaze: { zamer: "záměr", eia: "EIA", stanovisko: "stanovisko", rizeni: "řízení o povolení", povoleni: "povoleno", kolaudace: "kolaudace" },
  stavup: { probiha: "probíhá", vydano: "vydáno", bez_pohybu: "bez pohybu přes rok" },
  ini: { vlastnik: "návrh vlastníka / investora", obec: "z podnětu obce" },
  udup: { nova_zmena: "nová změna v evidenci", nova_dokumentace: "nová dokumentace", nabyti_ucinnosti: "nabytí účinnosti",
    zprava_o_uplatnovani: "zpráva o uplatňování", ukonceni_platnosti: "ukončení platnosti", nova_etapa: "nová etapa" },
  faze: {
    zprava_o_uplatnovani: "zpráva o uplatňování", navrh_na_porizeni: "návrh na pořízení", rozhodnuti_o_porizeni: "rozhodnutí o pořízení", zadani: "zadání",
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
let ZAK_PODLE_KLICE = new Map(), NAB_ZAK = new Map();
function pripravData() {
  for (const k of ["zamery", "zakazky", "nabidky_zak", "smlouvy", "tipy", "udalosti_up"]) D[k] = D[k] || [];
  D.obce_up = D.obce_up || {}; D.investori = D.investori || {};
  ZAK_PODLE_KLICE = new Map(D.zakazky.map((x) => [x.k, x]));
  NAB_ZAK = new Map();
  for (const n of D.nabidky_zak) { if (!NAB_ZAK.has(n.k)) NAB_ZAK.set(n.k, []); NAB_ZAK.get(n.k).push(n); }
  naplnCinnosti();
  naplnVyber("#s-faze", D.zamery, "f", "zfaze");
  naplnVyber("#s-kraj", D.zamery, "kr");
  naplnVyberSeznam("#s-druh", D.zamery, "ds");
  naplnVyberSeznam("#k-kategorie", D.zakazky, "kat");
  naplnVyber("#k-stav", D.zakazky, "s");
  naplnVyber("#k-kraj", D.zakazky, "kr");
  naplnVyber("#k-druh", D.zakazky, "dr");
  naplnVyberSeznam("#c-kategorie", [...D.zakazky, ...D.smlouvy], "kat");
  naplnVyber("#c-kraj", [...D.zakazky, ...D.smlouvy], "kr");
  naplnVyber("#t-segment", D.tipy, "sg");
  naplnVyber("#t-kraj", D.tipy, "kr");
  naplnVyber("#t-velikost", D.tipy, "zam");
  naplnVyberSignaly();
  naplnVyber("#u-stav", D.zmeny_up, "st", "stavup");
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

// pro pole se seznamem hodnot oddělených „; “
function naplnVyberSeznam(sel, radky, pole) {
  const el = $(sel), puvodni = el.value, prvni = el.options[0].outerHTML, pocty = new Map();
  for (const r of radky) for (const h of (r[pole] || "").split("; ")) if (h) pocty.set(h, (pocty.get(h) || 0) + 1);
  const hodnoty = [...pocty.keys()].sort((a, b) => pocty.get(b) - pocty.get(a));
  el.innerHTML = prvni + hodnoty.map((h) => `<option value="${esc(h)}">${esc(h)} (${pocty.get(h)})</option>`).join("");
  el.value = hodnoty.includes(puvodni) ? puvodni : "";
}
function naplnVyberSignaly() {
  const el = $("#t-signal"), puvodni = el.value, pocty = new Map();
  for (const t of D.tipy) for (const s of (t.si || "").split(" | ")) {
    const druh = s.replace(/\s*[\(:].*$/, "").replace(/ \d{4}-.*$/, "").trim();
    if (druh) pocty.set(druh, (pocty.get(druh) || 0) + 1);
  }
  el.innerHTML = el.options[0].outerHTML + [...pocty].sort((a, b) => b[1] - a[1]).map(([h, n]) => `<option value="${esc(h)}">${esc(h)} (${n})</option>`).join("");
  el.value = pocty.has(puvodni) ? puvodni : "";
}

/* ------------------------------------------------------------------ „Hledám práci pro“ (navazující činnosti) */
function naplnCinnosti() {
  const el = $("#cinnost"), puvodni = el.value || uloz.cti("prehled-cinnost") || "", pocty = new Map();
  const vse = [...D.zamery, ...D.zmeny_up, ...D.dokumenty, ...D.nabidky];
  for (const x of vse) for (const c of (x.nc || "").split("; ")) if (c && !c.startsWith("dle ")) pocty.set(c, (pocty.get(c) || 0) + 1);
  for (const z of D.zakazky) for (const c of (z.kat || "").split("; ")) if (c) pocty.set(c, (pocty.get(c) || 0) + 1);
  el.innerHTML = el.options[0].outerHTML + [...pocty.keys()].sort((a, b) => a.localeCompare(b, "cs"))
    .map((c) => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  el.value = pocty.has(puvodni) ? puvodni : "";
}
// shoda činnosti: v navazujících činnostech, v kategoriích zakázek, nebo (u dokumentů „dle bodu/předmětu“) v textu
const CINNOST_SLOVA = {
  "PENB": /penb|energetick/i, "projekce": /projekt|dokumentac|studi/i, "biologické hodnocení": /biolog|přírod|dřevin/i,
};
function cinnostSedi(x) {
  const c = $("#cinnost").value;
  if (!c) return true;
  if ((x.nc || "").split("; ").some((v) => v === c || v.startsWith(c))) return true;
  if ((x.kat || "").split("; ").includes(c)) return true;
  if ((x.nc || "").startsWith("dle ")) {
    const slovo = Object.entries(CINNOST_SLOVA).find(([k]) => c.toLowerCase().includes(k.toLowerCase()));
    return slovo ? slovo[1].test((x.n || "") + " " + (x.zb || "")) : false;
  }
  return false;
}
$("#cinnost").addEventListener("change", () => { uloz.pis("prehled-cinnost", $("#cinnost").value); vykreslene.clear(); vykresliZalozku(); });

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
  zamery: kresliZamery, zakazky: kresliZakazky, ceny: kresliCeny, tipy: kresliTipy, kalendar: kresliKalendar,
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
  const ted = new Date().toISOString().slice(0, 16).replace("T", " ");
  const zak = D.zakazky.filter((x) => cinnostSedi(x));
  const zakOtevrene = zak.filter((x) => x.lh && x.lh >= ted);
  const stavby30 = D.zamery.filter((x) => x.pd >= t30 && cinnostSedi(x));
  const dl = [
    [cislo(zakOtevrene.length), "zakázek s běžící lhůtou", `${cislo(D.dokumenty.filter((x) => x.t === "vyzva_zakazka" && x.lh && x.lh >= dnesIso()).length)} dalších výzev z úředních desek`],
    [cislo(stavby30.length), "staveb s novým dokumentem za 30 dní", `${cislo(stavby30.filter((x) => x.f === "povoleni").length)} povolených, ${cislo(stavby30.filter((x) => x.f === "kolaudace").length)} kolaudací`],
    [cislo(up30.length), "územních plánů s pohybem za 30 dní", `sledováno ${cislo(D.zmeny_up.length)}`],
    [cislo(aktivni.length), "aktivních nabídek a dražeb", `z toho ${cislo(drazby.length)} dražeb`],
    [cislo(nove7.length), "nově zveřejněných nabídek za 7 dní", ""],
    [cislo(D.tipy.length), "tipů na klienty", D.tipy.length ? `${cislo(D.tipy.filter((x) => x.ps >= 2).length)} s více signály` : "bot zatím neběžel"],
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

  kresliMista();
  const dokSer = dok7.filter((x) => cinnostSedi(x)).sort((a, b) => (b.dt > a.dt ? 1 : -1)).slice(0, 80);
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
  return D.nabidky.filter((x) => (!z || x.z === z) && (!s || x.s === s) && (!t || x.t === t) && (!o || x.ok === o) && (!a || x.a) && cinnostSedi(x) && hledej(h, x.n, x.ku, x.p, x.ok));
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
  return D.dokumenty.filter((x) => (!t || x.t === t) && (!k || x.kr === k) && (!od || x.dt >= od) && (hl || !x.h) && cinnostSedi(x) && hledej(h, x.n, x.d, x.sn, x.ku, x.ok, x.zb));
}
const SL_DOK = [
  { k: "dt", t: "Vyvěšeno", f: (r) => datum(r.dt) },
  { k: "n", t: "Dokument", sir: 1, f: (r) => `${odkaz(r.u, r.n)}<div class="tlumene">${[r.ds, r.h && "soukromá stavba", r.pt && "příroda: " + r.pt, r.uf && "ÚP: " + pop("faze", r.uf), r.lh && "lhůta " + datum(r.lh)].filter(Boolean).map(esc).join(" · ")}</div>${r.zb ? `<div class="body-zast">${r.zb.split(" | ").map((b) => "▸ " + esc(b)).join("<br>")}</div>` : ""}` },
  { k: "t", t: "Typ", f: (r) => `<span class="stitek">${esc(pop("dtyp", r.t))}</span>` },
  { k: "d", t: "Deska", f: (r) => `${esc(r.d)}<div class="tlumene">${esc(r.ok)}</div>` },
  { k: "ku", t: "K.ú. / parcely", f: (r) => `${esc(r.ku)}<div class="tlumene">${esc((r.par || "").slice(0, 80))}</div>` },
  { k: "sn", t: "Stavebník", f: (r) => r.st === "fyzicka_osoba" ? '<span class="tlumene">fyzická osoba</span>' : `${esc(r.sn)}${r.si ? `<div class="tlumene">IČO ${esc(r.si)}</div>` : ""}` },
  { k: "nc", t: "Navazující činnosti", f: (r) => `<span class="tlumene">${esc(r.nc)}</span>` },
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
  for (const b of ["zakazky", "upd", "firmy"]) tab($("#t-beh-" + b), D.behy[b] || []);
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
    napoj(["#v-nabidky", "#v-desky", "#v-up", "#v-zamery", "#v-zakazky", "#m-aktivni", "#m-typ", "#m-dtyp", "#m-obdobi"], kresliMapu);
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
    const r = D.nabidky.filter((x) => (jenAkt ? x.a : (!od || (x.pz || x.dz) >= od)) && (!typ || x.t === typ) && cinnostSedi(x));
    VRSTVY.n = vrstva("s1", r, "nabídky a dražby", (x) =>
      `${odkaz(x.u, x.n)}<br><span style="opacity:.75">${esc(pop("zdroj", x.z))} · ${esc(pop("stav", x.s))}${x.v ? " · " + cislo(x.v) + " m²" : ""}${x.cv ? " · " + kc(x.cv) : ""}${x.da ? " · " + datum(x.da) : ""}</span>`);
  }
  if ($("#v-desky").checked) {
    const r = D.dokumenty.filter((x) => (!od || x.dt >= od) && (!dtyp || x.t === dtyp) && cinnostSedi(x)
      && !["povoleni_zameru", "zahajeni_rizeni", "stavebni_povoleni", "uzemni_rozhodnuti", "rozhodnuti_stavebni", "kolaudace", "uzemni_plan"].includes(x.t));
    VRSTVY.d = vrstva("s2", r, "dokumenty z úředních desek", (x) =>
      `${odkaz(x.u, x.n)}<br><span style="opacity:.75">${esc(pop("dtyp", x.t))} · ${esc(x.d)} · ${datum(x.dt)}</span>`);
  }
  if ($("#v-up").checked) {
    const r = D.zmeny_up.filter((x) => (!od || x.df >= od) && cinnostSedi(x));
    VRSTVY.u = vrstva("s3", r, "územní plány", (x) =>
      `<b>${esc(x.c === "BEZ_CISLA" ? "Změna (bez čísla)" : x.c ? "Změna č. " + x.c : "Územní plán")}</b> – ${esc(pop("faze", x.f))} (${datum(x.df)})`);
  }
  if ($("#v-zamery").checked) {
    const r = D.zamery.filter((x) => (!od || x.pd >= od) && cinnostSedi(x));
    VRSTVY.s = vrstva("s4", r, "stavby", (x) =>
      `<a href="#" data-zamer="${esc(x.k)}">${esc(x.n)}</a><br><span style="opacity:.75">${esc(pop("zfaze", x.f))} ${datum(x.df)}${x.ds ? " · " + esc(x.ds) : ""}${x.cena ? " · cca " + kc(x.cena) : ""}</span>`);
  }
  if ($("#v-zakazky").checked) {
    const r = D.zakazky.filter((x) => (!od || (x.dz || x.pz) >= od) && cinnostSedi(x));
    VRSTVY.k = vrstva("s5", r, "zakázky", (x) =>
      `${odkaz(x.u, x.n)}<br><span style="opacity:.75">${esc(x.zd)} · ${esc(x.s)}${x.lh ? " · lhůta " + datum(x.lh) : ""}${x.cb ? " · " + kc(x.cb) : ""}</span>`);
  }
  $("#m-pocet").textContent = `${cislo(celkem)} na mapě` + (bezMista ? ` · ${cislo(bezMista)} bez polohy` : "");
}

/* ================================================================== ROZŠÍŘENÍ: obce, stavby, ÚP, zakázky, ceny, tipy, kalendář */
const median = (a) => { const b = a.filter((x) => x != null && x !== "" && !isNaN(x)).map(Number).sort((x, y) => x - y); if (!b.length) return null; const i = b.length / 2; return b.length % 2 ? b[i | 0] : (b[i - 1] + b[i]) / 2; };
const kvantil = (a, q) => { const b = a.filter((x) => x != null && x !== "").map(Number).sort((x, y) => x - y); if (!b.length) return null; return b[Math.min(b.length - 1, Math.floor(q * (b.length - 1)))]; };
const dniMezi = (a, b) => Math.round((new Date(b) - new Date(a)) / 864e5);
const kcKratce = (n) => n == null || n === "" ? "" : n >= 1e6 ? (n / 1e6).toLocaleString("cs-CZ", { maximumFractionDigits: 1 }) + " mil. Kč" : Math.round(n / 1e3).toLocaleString("cs-CZ") + " tis. Kč";

// obec z místa (k.ú. -> obec přes body.k[..][3])
function obecZMista(m) {
  if (!m) return "";
  if (m[0] === "o") return m[1];
  const b = D.body.k[m[1]];
  return b && b[3] ? b[3] : "";
}
function nazevObce(kod) {
  if (!kod) return "";
  if (D.obce_up[kod] && D.obce_up[kod].on) return D.obce_up[kod].on;
  const b = D.body.o[kod];
  return b ? b[2] : kod;
}
const odkazObce = (kod, text) => kod ? `<a href="#" data-obec="${esc(kod)}">${esc(text || nazevObce(kod))}</a>` : esc(text || "");

/* ------------------------------------------------------------------ boční panel (detail) */
function otevriPanel(html) {
  $("#panel-obsah").innerHTML = html; $("#panel").hidden = false; $("#panel").scrollTop = 0;
}
$("#panel-zavrit").onclick = () => ($("#panel").hidden = true);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") $("#panel").hidden = true; });
document.addEventListener("click", (e) => {
  const a = e.target.closest("[data-obec],[data-zamer],[data-up],[data-zakazka],[data-firma]");
  if (!a) return;
  e.preventDefault();
  if (a.dataset.obec) profilObce(a.dataset.obec);
  else if (a.dataset.zamer) detailZameru(a.dataset.zamer);
  else if (a.dataset.up) detailUp(a.dataset.up);
  else if (a.dataset.zakazka) detailZakazky(a.dataset.zakazka);
  else if (a.dataset.firma) profilFirmy(a.dataset.firma);
});

function casovaOsa(polozky) {
  // polozky: [[datum, popis, budouci?]]
  const p = polozky.filter((x) => x[0]).sort((a, b) => (a[0] > b[0] ? 1 : -1));
  if (!p.length) return '<p class="tlumene">Bez dat.</p>';
  return `<ol class="osa-cas">${p.map(([d, t, b]) => `<li class="${b ? "budouci" : ""}"><span class="osa-datum">${datum(d)}</span> ${t}</li>`).join("")}</ol>`;
}
const radekInfo = (k, v) => (v === "" || v == null ? "" : `<tr><th>${esc(k)}</th><td>${v}</td></tr>`);
const tabInfo = (radky) => `<table class="info">${radky.join("")}</table>`;

/* ------------------------------------------------------------------ ÚZEMNÍ PLÁNY */
const stavU = { razeni: "df", smer: -1 };
const FAZE_PORADI = ["zprava_o_uplatnovani", "navrh_na_porizeni", "rozhodnuti_o_porizeni", "zadani", "spolecne_jednani", "verejne_projednani", "vydani"];
function filtrUp() {
  const h = $("#u-hledat").value, f = $("#u-faze").value, k = $("#u-kraj").value, st = $("#u-stav").value,
    pl = $("#u-plochy").value, vl = $("#u-vlastnik").checked;
  return D.zmeny_up.filter((x) => (!f || x.f === f) && (!k || x.kr === k) && (!st || x.st === st)
    && (!pl || (x.pl || "").includes(pl)) && (!vl || x.ini === "vlastnik") && cinnostSedi(x) && hledej(h, x.ob, x.ok));
}
const nazevZmeny = (r) => r.c === "BEZ_CISLA" ? "změna (bez čísla)" : r.c ? "změna č. " + r.c : r.ur === "kraj" ? "zásady územního rozvoje" : "územní plán";
const SL_UP = [
  { k: "df", t: "Poslední pohyb", f: (r) => datum(r.df) + (r.dbp != null && r.dbp !== "" ? `<div class="tlumene">před ${cislo(r.dbp)} dny</div>` : "") },
  { k: "ob", t: "Obec", f: (r) => `<b>${odkazObce(obecZMista(r.m), r.ob)}</b><div class="tlumene">${esc(r.ok)} · ${esc(r.kr)}</div>` },
  { k: "c", t: "Změna", f: (r) => `<a href="#" data-up="${esc(r.k)}">${esc(nazevZmeny(r))}</a>${r.zk ? ' <span class="stitek">zkrácený postup</span>' : ""}` },
  { k: "f", t: "Fáze", h: (r) => FAZE_PORADI.indexOf(r.f), c: 1, f: (r) => `<span class="stitek">${esc(pop("faze", r.f))}</span>` },
  { k: "st", t: "Stav", f: (r) => `<span class="stitek${r.st === "probiha" ? " ok" : ""}">${esc(pop("stavup", r.st))}</span>${r.uc ? `<div class="tlumene">účinnost ${datum(r.uc)}</div>` : ""}${r.dpj && r.dpj >= dnesIso() ? `<div><b>projednání ${datum(r.dpj)}</b></div>` : ""}` },
  { k: "pl", t: "Čeho se týká", f: (r) => `${esc(r.pl || "")}${r.ini ? `<div class="tlumene">${esc(pop("ini", r.ini))}</div>` : ""}` },
  { k: "zpl", t: "Ploch", c: 1, f: (r) => cislo(r.zpl) },
  { k: "ha", t: "ha", c: 1, h: (r) => r.ha === "" ? null : +r.ha, f: (r) => r.ha ? Number(r.ha).toLocaleString("cs-CZ") : "" },
  { k: "nd", t: "Dok.", c: 1, f: (r) => cislo(r.nd) },
];
function kresliUp(zpet) {
  if (zpet === true) stavU.n = NA_STRANKU;
  stavU.prekresli = kresliUp;
  const sel = $("#u-plochy");
  if (sel.options.length < 2) {
    const druhy = new Map();
    for (const z of D.zmeny_up) for (const p of (z.pl || "").split("; ")) { const d = p.replace(/\s*\(\d+\)$/, ""); if (d) druhy.set(d, (druhy.get(d) || 0) + 1); }
    sel.innerHTML += [...druhy].sort((a, b) => b[1] - a[1]).map(([d, n]) => `<option value="${esc(d)}">${esc(d)} (${n})</option>`).join("");
  }
  const r = filtrUp();
  $("#u-pocet").textContent = `${cislo(r.length)} územních plánů a změn`;
  tabulka($("#t-up"), SL_UP, r, stavU);
  kresliObceUp();
  const ud = [...D.udalosti_up].sort((a, b) => (b.d > a.d ? 1 : -1)).slice(0, 300);
  $("#t-up-evidence").innerHTML = ud.length ? `<thead><tr><th>Zachyceno</th><th>Obec</th><th>Událost</th><th>Popis</th></tr></thead><tbody>` +
    ud.map((u) => `<tr><td>${datum(u.d)}</td><td>${odkazObce(u.o)}</td><td><span class="stitek">${esc(pop("udup", u.u))}</span></td><td>${esc(u.p)}</td></tr>`).join("") + "</tbody>"
    : '<tr><td class="tlumene">Zatím nic (první běh bota jen založí výchozí stav, změny se hlásí od dalšího).</td></tr>';
}
napoj(["#u-hledat", "#u-faze", "#u-kraj", "#u-stav", "#u-plochy", "#u-vlastnik"], kresliUp);

function kresliObceUp() {
  const vse = Object.entries(D.obce_up).map(([kod, o]) => ({ kod, ...o }));
  const ks = $("#o-kraj");
  if (ks.options.length < 2) ks.innerHTML += [...new Set(vse.map((o) => o.kr).filter(Boolean))].sort((a, b) => a.localeCompare(b, "cs")).map((k) => `<option>${esc(k)}</option>`).join("");
  const k = ks.value, f = $("#o-filtr").value, dnes = dnesIso();
  const r = vse.filter((o) => (!k || o.kr === k) && (!f
    || (f === "stary" && o.sz) || (f === "zprava" && o.dz && o.dz < dnes) || (f === "stari15" && +o.st >= 15)
    || (f === "bez" && !o.t) || (f === "rozprac" && o.roz)));
  $("#o-pocet").textContent = `${cislo(r.length)} obcí`;
  r.sort((a, b) => (a.dz || "9") > (b.dz || "9") ? 1 : -1);
  $("#t-obce-up").innerHTML = `<thead><tr><th>Obec</th><th>Platný plán</th><th class="cis">Let</th><th class="cis">Změn</th><th>4 roky od zprávy</th></tr></thead><tbody>` +
    r.slice(0, 600).map((o) => `<tr><td>${odkazObce(o.kod, o.on)}<div class="tlumene">${esc(o.kr)}</div></td><td>${esc(o.t)}${o.sz ? ' <span class="stitek">před 2007</span>' : ""}${o.roz ? ' <span class="stitek">nový rozpracován</span>' : ""}<div class="tlumene">${esc(o.zh)}</div></td><td class="cis">${esc(String(o.st || "").replace(".", ","))}</td><td class="cis">${cislo(o.pz)}</td><td>${o.dz ? (o.dz < dnes ? `<b>${datum(o.dz)}</b>` : datum(o.dz)) : ""}</td></tr>`).join("") + "</tbody>";
  const zh = new Map();
  for (const o of vse.filter((o) => !k || o.kr === k)) if (o.t && o.zh) { const key = o.zi || o.zh; if (!zh.has(key)) zh.set(key, { n: o.zh, i: o.zi, c: 0, nove: 0 }); const z = zh.get(key); z.c++; if (o.uc >= predDny(5 * 365)) z.nove++; }
  $("#t-zhotovitele").innerHTML = `<thead><tr><th>Zhotovitel</th><th class="cis">Platných ÚP</th><th class="cis">z toho za 5 let</th></tr></thead><tbody>` +
    [...zh.values()].sort((a, b) => b.c - a.c).slice(0, 60).map((z) => `<tr><td>${esc(z.n)}${z.i ? `<div class="tlumene">IČO ${esc(z.i)}</div>` : ""}</td><td class="cis">${z.c}</td><td class="cis">${z.nove || ""}</td></tr>`).join("") + "</tbody>";
}
napoj(["#o-kraj", "#o-filtr"], kresliObceUp);
$("#u-csv").onclick = () => stahniCsv("uzemni-plany", [
  ["up_klic", (r) => r.k], ["obec", (r) => r.ob], ["okres", (r) => r.ok], ["kraj", (r) => r.kr], ["cislo_zmeny", (r) => r.c],
  ["faze_posledni", (r) => r.f], ["datum_posledni_faze", (r) => r.df], ["stav", (r) => r.st], ["dni_bez_pohybu", (r) => r.dbp],
  ["plochy", (r) => r.pl], ["zastavitelnych_ploch", (r) => r.zpl], ["vymera_ha", (r) => r.ha], ["iniciator", (r) => r.ini],
  ["datum_ucinnosti", (r) => r.uc], ["datum_projednani", (r) => r.dpj],
  ...FAZE_PORADI.map((f) => ["datum_" + f, (r) => (r.fd || {})[f] || ""]), ["pocet_dokumentu", (r) => r.nd],
], filtrUp());

// obvyklé délky mezi fázemi (medián přes všechny sledované změny, kde jsou obě fáze zachycené)
function obvykleDelky() {
  const vys = {};
  for (let i = 0; i < FAZE_PORADI.length - 1; i++) {
    const a = FAZE_PORADI[i];
    for (let j = i + 1; j < FAZE_PORADI.length; j++) {
      const b = FAZE_PORADI[j], d = [];
      for (const z of D.zmeny_up) if (z.fd && z.fd[a] && z.fd[b] && z.fd[b] >= z.fd[a]) d.push(dniMezi(z.fd[a], z.fd[b]));
      if (d.length >= 3) vys[a + ">" + b] = { m: median(d), n: d.length };
    }
  }
  return vys;
}
function detailUp(klic) {
  const r = D.zmeny_up.find((x) => x.k === klic);
  if (!r) return;
  const delky = obvykleDelky(), obec = obecZMista(r.m), ev = D.obce_up[obec];
  const osa = FAZE_PORADI.filter((f) => r.fd && r.fd[f]).map((f) => [r.fd[f], esc(pop("faze", f))]);
  if (r.dpj) osa.push([r.dpj, "<b>termín projednání</b>", r.dpj >= dnesIso()]);
  if (r.uc) osa.push([r.uc, "nabytí účinnosti", r.uc >= dnesIso()]);
  // odhad dalšího kroku: obvyklá délka od poslední zachycené fáze k vydání
  const dalsi = [];
  const posl = FAZE_PORADI.filter((f) => r.fd && r.fd[f]).pop();
  if (posl && posl !== "vydani") {
    const d = delky[posl + ">vydani"];
    if (d) dalsi.push(`Od fáze „${esc(pop("faze", posl))}“ k vydání to v datech trvalo obvykle <b>${cislo(Math.round(d.m))} dní</b> (medián z ${d.n} změn).`);
  }
  const docs = r.ids.map((i) => DOK_PODLE_ID.get(i)).filter(Boolean);
  otevriPanel(`<h2>${esc(r.ob)} – ${esc(nazevZmeny(r))}</h2>
    <p class="tlumene">${esc(r.ok)} · ${esc(r.kr)} · ${odkazObce(obec, "vše v obci →")}</p>
    ${tabInfo([radekInfo("Stav", esc(pop("stavup", r.st)) + (r.dbp !== "" ? ` (poslední dokument před ${cislo(r.dbp)} dny)` : "")),
      radekInfo("Fáze", esc(pop("faze", r.f))), radekInfo("Čeho se týká", esc(r.pl || "")),
      radekInfo("Zastavitelných ploch / dílčích změn", cislo(r.zpl)), radekInfo("Výměra (největší uvedená)", r.ha ? esc(r.ha) + " ha" : ""),
      radekInfo("Kdo změnu vyvolal", esc(pop("ini", r.ini))), radekInfo("Zkrácený postup", r.zk ? "ano" : ""),
      radekInfo("Navazující činnosti", esc(r.nc || ""))])}
    <h3>Časová osa</h3>${casovaOsa(osa)}${dalsi.map((x) => `<p class="tlumene">${x}</p>`).join("")}
    ${ev ? `<h3>Územní plán obce (celostátní evidence)</h3>${panelEvidence(ev)}` : ""}
    <h3>Dokumenty (${docs.length})</h3>${docs.map((d) => `<div class="pp">${datum(d.dt)} · ${odkaz(d.u, d.n)}</div>`).join("") || '<p class="tlumene">—</p>'}`);
}
function panelEvidence(ev) {
  return tabInfo([radekInfo("Platný", `${esc(ev.t)} ${esc(ev.n)}`), radekInfo("Účinnost od", datum(ev.uc) + (ev.st ? ` (${esc(String(ev.st).replace(".", ","))} let)` : "")),
    radekInfo("Plán podle zákona před 2007", ev.sz ? "ano" : ""), radekInfo("Vydaných změn v evidenci", cislo(ev.pz)),
    radekInfo("Poslední zpráva o uplatňování", datum(ev.zp)), radekInfo("4 roky od poslední zprávy / účinnosti", datum(ev.dz)),
    radekInfo("Rozpracovaný nový ÚP", ev.roz ? "ano" : ""), radekInfo("Územní studie / regulační plány", `${cislo(ev.us) || 0} / ${cislo(ev.rp) || 0}`),
    radekInfo("Zhotovitel ÚP", `${esc(ev.zh)}${ev.zi ? ` <span class="tlumene">IČO ${esc(ev.zi)}</span>` : ""}`),
    radekInfo("Pořizovatel", esc(ev.por)), radekInfo("Poslední pohyb v evidenci", `${datum(ev.pp)} ${esc(ev.ppc)}`)]);
}

/* ------------------------------------------------------------------ PROFIL OBCE */
function profilObce(kod) {
  const ev = D.obce_up[kod], jmeno = nazevObce(kod);
  const vObci = (x) => obecZMista(x.m) === kod;
  const up = D.zmeny_up.filter(vObci), zam = D.zamery.filter(vObci), nab = D.nabidky.filter((x) => vObci(x) && x.a);
  const zak = D.zakazky.filter(vObci), tipy = D.tipy.filter(vObci);
  const zast = D.dokumenty.filter((x) => vObci(x) && x.zb).slice(0, 15);
  const ud = D.udalosti_up.filter((u) => u.o === kod);
  const sml = D.smlouvy.filter((s) => zak.some((z) => z.zi === s.oi)).slice(0, 20);
  otevriPanel(`<h2>${esc(jmeno)}</h2><p class="tlumene">kód obce ${esc(kod)}${ev && ev.kr ? " · " + esc(ev.kr) : ""}</p>
    ${ev ? `<h3>Územní plán (celostátní evidence ÚÚR)</h3>${panelEvidence(ev)}` : ""}
    ${ud.length ? `<h3>Novinky v evidenci</h3>${ud.map((u) => `<div class="pp">${datum(u.d)} · ${esc(pop("udup", u.u))}: ${esc(u.p)}</div>`).join("")}` : ""}
    <h3>Změny územního plánu (${up.length})</h3>${up.map((r) => `<div class="pp"><a href="#" data-up="${esc(r.k)}">${esc(nazevZmeny(r))}</a> · ${esc(pop("faze", r.f))} ${datum(r.df)}${r.pl ? ` · <span class="tlumene">${esc(r.pl)}</span>` : ""}</div>`).join("") || '<p class="tlumene">—</p>'}
    <h3>Stavby (${zam.length})</h3>${zam.slice(0, 30).map((r) => `<div class="pp"><a href="#" data-zamer="${esc(r.k)}">${esc(r.n)}</a> · ${esc(pop("zfaze", r.f))} ${datum(r.df)}${r.cena ? " · cca " + kcKratce(r.cena) : ""}</div>`).join("") || '<p class="tlumene">—</p>'}
    <h3>Zastupitelstvo – stavební body</h3>${zast.map((d) => `<div class="pp">${datum(d.dt)} · ${odkaz(d.u, d.n)}<div class="body-zast">${d.zb.split(" | ").slice(0, 6).map((b) => "▸ " + esc(b)).join("<br>")}</div></div>`).join("") || '<p class="tlumene">—</p>'}
    <h3>Zakázky (${zak.length})</h3>${zak.slice(0, 20).map((r) => `<div class="pp"><a href="#" data-zakazka="${esc(r.k)}">${esc(r.n)}</a> · ${esc(r.s)}${r.cb ? " · " + kcKratce(r.cb) : ""}</div>`).join("") || '<p class="tlumene">—</p>'}
    ${sml.length ? `<h3>Smlouvy zadavatelů z obce (registr smluv)</h3>${sml.map((s) => `<div class="pp">${datum(s.d)} · ${odkaz(s.u, s.p)} · ${esc(s.do)}${s.h ? " · " + kcKratce(s.h) : ""}</div>`).join("")}` : ""}
    <h3>Aktivní nabídky a dražby (${nab.length})</h3>${nab.slice(0, 20).map((r) => `<div class="pp">${odkaz(r.u, r.n)} · ${esc(pop("stav", r.s))}${r.cv ? " · " + kcKratce(r.cv) : ""}</div>`).join("") || '<p class="tlumene">—</p>'}
    <h3>Tipy na klienty se sídlem v obci (${tipy.length})</h3>${tipy.slice(0, 20).map((t) => `<div class="pp"><a href="#" data-firma="${esc(t.i)}">${esc(t.n)}</a> · ${esc(t.sg)}<div class="tlumene">${esc(t.si)}</div></div>`).join("") || '<p class="tlumene">—</p>'}`);
}

/* ------------------------------------------------------------------ MÍSTA S NEJVÍCE SIGNÁLY */
function kresliMista() {
  const od = predDny(180), m = new Map();
  const pridej = (x, druh) => { const o = obecZMista(x.m); if (!o) return; if (!m.has(o)) m.set(o, { o, up: 0, st: 0, pr: 0, zk: 0, zb: 0 }); m.get(o)[druh]++; };
  for (const x of D.zmeny_up) if (x.df >= od && cinnostSedi(x)) pridej(x, "up");
  for (const x of D.zamery) if (x.pd >= od && cinnostSedi(x)) pridej(x, "st");
  for (const x of D.nabidky) if (x.a && cinnostSedi(x)) pridej(x, "pr");
  for (const x of D.zakazky) if ((x.dz || x.pz) >= od && cinnostSedi(x)) pridej(x, "zk");
  for (const x of D.dokumenty) if (x.zb && x.dt >= od) pridej(x, "zb");
  const radky = [...m.values()].map((r) => ({ ...r, c: r.up + r.st + r.pr + r.zk + r.zb })).sort((a, b) => b.c - a.c).slice(0, 25);
  $("#t-mista").innerHTML = `<thead><tr><th>Obec</th><th class="cis">Signálů</th><th class="cis">Změny ÚP</th><th class="cis">Stavby</th><th class="cis">Prodeje a dražby</th><th class="cis">Zakázky</th><th class="cis">Zastupitelstvo</th></tr></thead><tbody>` +
    radky.map((r) => `<tr><td>${odkazObce(r.o)}</td><td class="cis"><b>${r.c}</b></td><td class="cis">${r.up || ""}</td><td class="cis">${r.st || ""}</td><td class="cis">${r.pr || ""}</td><td class="cis">${r.zk || ""}</td><td class="cis">${r.zb || ""}</td></tr>`).join("") + "</tbody>";
}

/* ------------------------------------------------------------------ STAVBY (záměry) */
const stavS = { razeni: "pd", smer: -1 };
function filtrZamery() {
  const h = $("#s-hledat").value, f = $("#s-faze").value, dr = $("#s-druh").value, sb = $("#s-stavebnik").value,
    k = $("#s-kraj").value, dny = +$("#s-obdobi").value, vel = +$("#s-velikost").value, od = dny ? predDny(dny) : "";
  return D.zamery.filter((x) => (!f || x.f === f) && (!dr || (x.ds || "").split("; ").includes(dr)) && (!k || x.kr === k)
    && (!od || x.pd >= od) && (!vel || (x.cena || 0) >= vel)
    && (!sb || (sb === "soukroma" ? x.sk : x.st === sb && !x.sk)) && cinnostSedi(x) && hledej(h, x.n, x.ku, x.sn, x.si, x.d));
}
const SL_ZAM = [
  { k: "pd", t: "Poslední dokument", f: (r) => datum(r.pd) },
  { k: "n", t: "Stavba", sir: 1, f: (r) => `<a href="#" data-zamer="${esc(r.k)}">${esc(r.n)}</a><div class="tlumene">${esc(r.ds || "")}${r.sk ? " · soukromá stavba" : ""}</div>` },
  { k: "f", t: "Fáze", f: (r) => `<span class="stitek">${esc(pop("zfaze", r.f))}</span><div class="tlumene">${datum(r.df)}</div>` },
  { k: "sn", t: "Stavebník", f: (r) => r.sk ? '<span class="tlumene">soukromá osoba</span>' : `${r.si ? `<a href="#" data-firma="${esc(r.si)}">${esc(r.sn || r.si)}</a>` : esc(r.sn)}` },
  { k: "ku", t: "Místo", f: (r) => `${odkazObce(obecZMista(r.m), r.ku || nazevObce(obecZMista(r.m)))}<div class="tlumene">${esc(r.ok)}</div>` },
  { k: "op", t: "Obestavěný m³", c: 1, f: (r) => cislo(r.op) || (r.zp ? `<span class="tlumene">${cislo(r.zp)} m² zast.</span>` : "") },
  { k: "cena", t: "Odhad ceny", c: 1, f: (r) => r.cena ? kcKratce(r.cena) + (r.oz === "plocha" ? '<div class="tlumene">z plochy</div>' : "") : "" },
  { k: "hon", t: "Honorář cca", c: 1, f: (r) => r.hon ? kcKratce(r.hon) : "" },
  { k: "nc", t: "Navazující činnosti", f: (r) => `<span class="tlumene">${esc(r.nc)}</span>` },
];
function kresliZamery(zpet) {
  if (zpet === true) stavS.n = NA_STRANKU;
  stavS.prekresli = kresliZamery;
  const r = filtrZamery();
  $("#s-pocet").textContent = `${cislo(r.length)} staveb`;
  tabulka($("#t-zamery"), SL_ZAM, r, stavS);
}
napoj(["#s-hledat", "#s-faze", "#s-druh", "#s-stavebnik", "#s-kraj", "#s-obdobi", "#s-velikost"], kresliZamery);
$("#s-csv").onclick = () => stahniCsv("stavby", [
  ["klic", (r) => r.k], ["nazev", (r) => r.n], ["faze", (r) => r.f], ["datum_faze", (r) => r.df], ["posledni_dokument", (r) => r.pd],
  ["druh_stavby", (r) => r.ds], ["soukroma", (r) => r.sk], ["stavebnik", (r) => r.sn], ["stavebnik_ico", (r) => r.si],
  ["katastralni_uzemi", (r) => r.ku], ["okres", (r) => r.ok], ["kraj", (r) => r.kr], ["parcely", (r) => r.par],
  ["zastavena_plocha_m2", (r) => r.zp], ["obestaveny_prostor_m3", (r) => r.op], ["podlazi", (r) => r.pdl], ["byty", (r) => r.pb],
  ["odhad_ceny_kc", (r) => r.cena], ["honorar_kc", (r) => r.hon], ["navazujici_cinnosti", (r) => r.nc],
], filtrZamery());
function detailZameru(klic) {
  const r = D.zamery.find((x) => x.k === klic);
  if (!r) return;
  const inv = r.si ? D.investori[r.si] : null;
  const dalsi = r.si ? D.zamery.filter((x) => x.si === r.si && x.k !== r.k) : [];
  const docs = r.ids.map((i) => DOK_PODLE_ID.get(i)).filter(Boolean);
  const osa = Object.entries(r.fz || {}).map(([k, d]) => [d, esc(pop("zfaze", k))]);
  otevriPanel(`<h2>${esc(r.n)}</h2><p class="tlumene">${odkazObce(obecZMista(r.m), r.ku || nazevObce(obecZMista(r.m)) || "obec")} · ${esc(r.ok)} · ${esc(r.kr)}</p>
    ${tabInfo([radekInfo("Fáze", esc(pop("zfaze", r.f)) + " " + datum(r.df)), radekInfo("Druh stavby", esc(r.ds)),
      radekInfo("Stavebník", r.sk ? "soukromá osoba (jméno se neukládá, je v původním dokumentu)" : `${esc(r.sn)}${r.si ? ` <span class="tlumene">IČO ${esc(r.si)}</span>` : ""}`),
      radekInfo("Zastavěná plocha", r.zp ? cislo(r.zp) + " m²" : ""), radekInfo("Obestavěný prostor", r.op ? cislo(r.op) + " m³" : ""),
      radekInfo("Podlaží / byty", [r.pdl, r.pb].some(Boolean) ? `${cislo(r.pdl) || "–"} / ${cislo(r.pb) || "–"}` : ""),
      radekInfo("Odhad ceny stavby", r.cena ? `${kc(r.cena)} <span class="tlumene">(${r.oz === "plocha" ? "ze zastavěné plochy × podlaží × 3,3 m" : "obestavěný prostor × ukazatel"}, ±25 %)</span>` : ""),
      radekInfo("Honorář orientačně", r.hon ? kc(r.hon) : ""), radekInfo("Parcely", esc(r.par)), radekInfo("Úřad", esc(r.d)),
      radekInfo("Navazující činnosti", esc(r.nc))])}
    <h3>Časová osa</h3>${casovaOsa(osa)}
    ${inv ? `<h3>Investor (ARES)</h3>${tabInfo([radekInfo("Název", esc(inv.n)), radekInfo("Sídlo", esc(inv.ob) + (inv.kr ? ", " + esc(inv.kr) : "")),
      radekInfo("Hlavní činnost (CZ-NACE)", esc(inv.nace)), radekInfo("Vznik", datum(inv.dv)),
      radekInfo("Odkaz", `<a href="https://ares.gov.cz/ekonomicke-subjekty?ico=${esc(r.si)}" target="_blank" rel="noopener">ARES</a> · <a href="https://or.justice.cz/ias/ui/rejstrik-$firma?ico=${esc(r.si)}" target="_blank" rel="noopener">obchodní rejstřík</a>`)])}` : ""}
    ${dalsi.length ? `<h3>Další stavby stejného investora (${dalsi.length})</h3>${dalsi.slice(0, 20).map((x) => `<div class="pp"><a href="#" data-zamer="${esc(x.k)}">${esc(x.n)}</a> · ${esc(pop("zfaze", x.f))} ${datum(x.df)}</div>`).join("")}` : ""}
    <h3>Dokumenty (${docs.length})</h3>${docs.map((d) => `<div class="pp">${datum(d.dt)} · ${esc(pop("dtyp", d.t))} · ${odkaz(d.u, d.n)}</div>`).join("") || '<p class="tlumene">—</p>'}`);
}

/* ------------------------------------------------------------------ ZAKÁZKY */
const stavK = { razeni: "dz", smer: -1 };
function filtrZakazky() {
  const h = $("#k-hledat").value, ka = $("#k-kategorie").value, s = $("#k-stav").value, k = $("#k-kraj").value,
    dr = $("#k-druh").value, ot = $("#k-otevrene").checked, ted = new Date().toISOString().slice(0, 16).replace("T", " ");
  return D.zakazky.filter((x) => (!ka || (x.kat || "").split("; ").includes(ka)) && (!s || x.s === s) && (!k || x.kr === k)
    && (!dr || x.dr === dr) && (!ot || (x.lh && x.lh >= ted)) && cinnostSedi(x) && hledej(h, x.n, x.c, x.zd, x.zi, x.v, x.vi, x.p));
}
const SL_ZAK = [
  { k: "dz", t: "Zveřejněno", f: (r) => datum(r.dz || r.pz) },
  { k: "n", t: "Zakázka", sir: 1, f: (r) => `<a href="#" data-zakazka="${esc(r.k)}">${esc(r.n)}</a>${r.c ? `<div>${esc(r.c)}</div>` : ""}<div class="tlumene">${esc(r.kat)}</div>` },
  { k: "zd", t: "Zadavatel", f: (r) => `${esc(r.zd)}<div class="tlumene">${r.zt === "soukromy" ? "soukromý · " : ""}${odkazObce(obecZMista(r.m), r.ob)}${r.kr ? " · " + esc(r.kr) : ""}</div>` },
  { k: "s", t: "Stav", f: (r) => `<span class="stitek${r.s === "zahájen" ? " ok" : ""}">${esc(r.s)}</span><div class="tlumene">${esc(r.dr)}</div>` },
  { k: "lh", t: "Lhůta nabídek", f: (r) => r.lh ? (r.lh >= dnesIso() ? `<b>${datum(r.lh)}</b>` : datum(r.lh)) : "" },
  { k: "pn", t: "Nabídek", c: 1, f: (r) => cislo(r.pn) },
  { k: "cb", t: "Cena (bez DPH)", c: 1, f: (r) => r.cb ? kc(r.cb) : "" },
  { k: "v", t: "Vítěz", f: (r) => r.v ? `${esc(r.v)}${r.vi ? `<div class="tlumene">IČO ${esc(r.vi)}</div>` : ""}` : "" },
];
function kresliZakazky(zpet) {
  if (zpet === true) stavK.n = NA_STRANKU;
  stavK.prekresli = kresliZakazky;
  const r = filtrZakazky();
  $("#k-pocet").textContent = `${cislo(r.length)} zakázek`;
  tabulka($("#t-zakazky"), SL_ZAK, r, stavK);
}
napoj(["#k-hledat", "#k-kategorie", "#k-stav", "#k-kraj", "#k-druh", "#k-otevrene"], kresliZakazky);
$("#k-csv").onclick = () => stahniCsv("zakazky", [
  ["klic", (r) => r.k], ["nazev", (r) => r.n], ["cast", (r) => r.c], ["kategorie", (r) => r.kat], ["cpv", (r) => r.cpv],
  ["zadavatel", (r) => r.zd], ["zadavatel_ico", (r) => r.zi], ["zadavatel_typ", (r) => r.zt], ["kraj", (r) => r.kr], ["obec", (r) => r.ob],
  ["druh_rizeni", (r) => r.dr], ["stav", (r) => r.s], ["zverejneno", (r) => r.dz], ["lhuta", (r) => r.lh], ["pocet_nabidek", (r) => r.pn],
  ["nabidka_min", (r) => r.nmin], ["nabidka_max", (r) => r.nmax], ["vitez", (r) => r.v], ["vitez_ico", (r) => r.vi],
  ["cena_bez_dph", (r) => r.cb], ["datum_smlouvy", (r) => r.ds], ["url", (r) => r.u],
], filtrZakazky());
function detailZakazky(klic) {
  const r = ZAK_PODLE_KLICE.get(klic);
  if (!r) return;
  const nab = (NAB_ZAK.get(klic) || []).slice().sort((a, b) => (a.c || 9e15) - (b.c || 9e15));
  otevriPanel(`<h2>${esc(r.n)}</h2>${r.c ? `<p>${esc(r.c)}</p>` : ""}<p class="tlumene">${esc(r.zd)} · ${odkazObce(obecZMista(r.m), r.ob)} · ${esc(r.kr)}</p>
    ${tabInfo([radekInfo("Kategorie", esc(r.kat)), radekInfo("CPV", esc(r.cpv)), radekInfo("Druh řízení", esc(r.dr) + (r.rez ? ` (${esc(r.rez)})` : "")),
      radekInfo("Stav", esc(r.s)), radekInfo("Zveřejněno", datum(r.dz)), radekInfo("Lhůta pro nabídky", r.lh ? datum(r.lh) + " " + esc(r.lh.slice(11)) : ""),
      radekInfo("Vítěz", r.v ? `${esc(r.v)} <span class="tlumene">IČO ${esc(r.vi)}</span>` : ""), radekInfo("Smluvní cena bez DPH", r.cb ? kc(r.cb) : ""),
      radekInfo("Smlouva uzavřena", datum(r.ds)), radekInfo("Zadavatel", `${esc(r.zd)} <span class="tlumene">IČO ${esc(r.zi)}${r.zt === "soukromy" ? ", soukromý" : ""}</span>`),
      radekInfo("Odkaz", odkaz(r.u, "profil zadavatele / detail"))])}
    ${r.p ? `<h3>Předmět</h3><p>${esc(r.p)}</p>` : ""}
    <h3>Nabídky (${nab.length})</h3>${nab.length ? `<table class="info"><tr><th>Účastník</th><th class="cis">Cena bez DPH</th></tr>${nab.map((n) => `<tr><td>${n.v ? "<b>" : ""}${esc(n.n)}${n.v ? " ✓</b>" : ""} <span class="tlumene">${esc(n.i)}</span></td><td class="cis">${n.c ? kc(n.c) : ""}</td></tr>`).join("")}</table>` : '<p class="tlumene">—</p>'}`);
}

/* ------------------------------------------------------------------ CENY (srovnání) */
function vysledkyCen() {
  const ka = $("#c-kategorie").value, k = $("#c-kraj").value, dny = +$("#c-obdobi").value, od = dny ? predDny(dny) : "";
  const doDne = new Date(Date.now() + 60 * 864e5).toISOString().slice(0, 10);   // chybná data v budoucnosti pryč
  const z = D.zakazky.filter((x) => x.cb && x.v && (!ka || (x.kat || "").split("; ").includes(ka)) && (!k || x.kr === k) && (!od || (x.ds || x.dz) >= od))
    .map((x) => ({ d: x.ds || x.dz, ob: x.zd, oi: x.zi, do: x.v, di: x.vi, p: x.n + (x.c ? " – " + x.c : ""), h: x.cb, kat: x.kat, kr: x.kr, u: x.u, pn: x.pn, zdroj: "zakázka", k: x.k }));
  const s = D.smlouvy.filter((x) => (x.h || x.hs) && (!ka || (x.kat || "").split("; ").includes(ka)) && (!k || x.kr === k) && (!od || x.d >= od))
    .map((x) => ({ ...x, h: x.h || Math.round(x.hs / 1.21), zdroj: "registr smluv" }));
  return [...z, ...s].filter((x) => !x.d || x.d <= doDne);
}
function kresliCeny() {
  const r = vysledkyCen(), ceny = r.map((x) => x.h);
  $("#c-pocet").textContent = `${cislo(r.length)} zakázek a smluv s cenou`;
  const pn = r.filter((x) => x.pn).map((x) => x.pn);
  $("#c-souhrn").innerHTML = [
    [cislo(r.length), "zakázek a smluv s cenou", ""],
    [kcKratce(median(ceny)), "medián ceny bez DPH", ceny.length ? `polovina mezi ${kcKratce(kvantil(ceny, 0.25))} a ${kcKratce(kvantil(ceny, 0.75))}` : ""],
    [pn.length ? String(median(pn)).replace(".", ",") : "–", "medián počtu nabídek", pn.length ? `u ${cislo(pn.length)} zakázek z profilů` : "počty nabídek jsou jen u zakázek z profilů"],
    [cislo(new Set(r.map((x) => x.di || x.do)).size), "různých dodavatelů", ""],
  ].map(([c, p, s]) => `<div class="karta"><div class="dl-cislo">${c}</div><div class="dl-popis">${p}</div><div class="dl-pod">${s}</div></div>`).join("");
  // vítězové
  const m = new Map();
  for (const x of r) { if (!x.di) continue; const k = x.di; if (!m.has(k)) m.set(k, { n: x.do, i: x.di, c: 0, s: 0, ceny: [] }); const a = m.get(k); a.c++; a.s += x.h; a.ceny.push(x.h); }
  const vit = [...m.values()].sort((a, b) => b.c - a.c || b.s - a.s).slice(0, 40);
  $("#t-vitezove").innerHTML = `<thead><tr><th>Dodavatel</th><th class="cis">Počet</th><th class="cis">Medián ceny</th><th class="cis">Celkem</th></tr></thead><tbody>` +
    vit.map((v) => `<tr><td>${esc(v.n)}${v.i ? `<div class="tlumene">IČO ${esc(v.i)}</div>` : ""}</td><td class="cis">${v.c}</td><td class="cis">${kcKratce(median(v.ceny))}</td><td class="cis">${kcKratce(v.s)}</td></tr>`).join("") + "</tbody>";
  // rozložení cen (logaritmické koše)
  const kose = [[0, 50e3, "do 50 tis."], [50e3, 100e3, "50–100 tis."], [100e3, 250e3, "100–250 tis."], [250e3, 500e3, "250–500 tis."],
    [500e3, 1e6, "0,5–1 mil."], [1e6, 2e6, "1–2 mil."], [2e6, 5e6, "2–5 mil."], [5e6, 1e7, "5–10 mil."], [1e7, 5e7, "10–50 mil."], [5e7, Infinity, "nad 50 mil."]];
  grafSloupce($("#g-ceny"), kose.map(([a, b, l]) => ({ l, v: ceny.filter((c) => c >= a && c < b).length, t: `${l} Kč: <b>${cislo(ceny.filter((c) => c >= a && c < b).length)}</b>` })), "zakázek a smluv");
  const pos = r.sort((a, b) => (b.d > a.d ? 1 : -1)).slice(0, 400);
  $("#t-vysledky").innerHTML = `<thead><tr><th>Datum</th><th>Předmět</th><th>Objednatel</th><th>Dodavatel</th><th class="cis">Cena bez DPH</th><th>Zdroj</th></tr></thead><tbody>` +
    pos.map((x) => `<tr><td>${datum(x.d)}</td><td class="nazev-bunka">${x.k ? `<a href="#" data-zakazka="${esc(x.k)}">${esc(x.p)}</a>` : odkaz(x.u, x.p)}<div class="tlumene">${esc(x.kat)}</div></td><td>${esc(x.ob)}<div class="tlumene">${esc(x.kr || "")}</div></td><td>${esc(x.do)}</td><td class="cis">${kc(x.h)}</td><td class="tlumene">${esc(x.zdroj)}${x.pn ? `, ${x.pn} nab.` : ""}</td></tr>`).join("") + "</tbody>";
}
napoj(["#c-kategorie", "#c-kraj", "#c-obdobi"], kresliCeny);

/* ------------------------------------------------------------------ TIPY NA KLIENTY */
const stavT = { razeni: "ps", smer: -1 };
function filtrTipy() {
  const h = $("#t-hledat").value, sg = $("#t-segment").value, si = $("#t-signal").value, k = $("#t-kraj").value, v = $("#t-velikost").value;
  return D.tipy.filter((x) => (!sg || x.sg === sg) && (!si || (x.si || "").includes(si)) && (!k || x.kr === k) && (!v || x.zam === v)
    && hledej(h, x.n, x.i, x.ob));
}
const SL_TIP = [
  { k: "ps", t: "Signálů", c: 1, f: (r) => `<b>${r.ps}</b>` },
  { k: "n", t: "Firma / organizace", sir: 1, f: (r) => `<a href="#" data-firma="${esc(r.i)}">${esc(r.n)}</a><div class="tlumene">IČO ${esc(r.i)} · ${esc(r.sg)} · ${esc(r.zam)} zam.</div>` },
  { k: "si", t: "Signály", sir: 1, f: (r) => (r.si || "").split(" | ").map((x) => "▸ " + esc(x)).join("<br>") },
  { k: "ob", t: "Sídlo", f: (r) => `${odkazObce(obecZMista(r.m), r.ob)}<div class="tlumene">${esc(r.kr)}</div>` },
  { k: "po", t: "Typické potřeby segmentu", f: (r) => `<span class="tlumene">${esc(r.po)}</span>` },
];
function kresliTipy(zpet) {
  if (zpet === true) stavT.n = NA_STRANKU;
  stavT.prekresli = kresliTipy;
  const r = filtrTipy();
  $("#t-pocet").textContent = `${cislo(r.length)} tipů`;
  tabulka($("#t-tipy"), SL_TIP, r, stavT);
}
napoj(["#t-hledat", "#t-segment", "#t-signal", "#t-kraj", "#t-velikost"], kresliTipy);
$("#t-csv").onclick = () => stahniCsv("tipy-na-klienty", [
  ["ico", (r) => r.i], ["nazev", (r) => r.n], ["segment", (r) => r.sg], ["zamestnanci", (r) => r.zam], ["kraj", (r) => r.kr],
  ["obec", (r) => r.ob], ["pocet_signalu", (r) => r.ps], ["signaly", (r) => r.si], ["potreby", (r) => r.po], ["datum_vzniku", (r) => r.dv],
  ["nace", (r) => r.nace],
], filtrTipy());
function profilFirmy(ico) {
  const t = D.tipy.find((x) => x.i === ico), inv = D.investori[ico];
  const zam = D.zamery.filter((x) => x.si === ico), zak = D.zakazky.filter((x) => x.zi === ico || x.vi === ico);
  const sml = D.smlouvy.filter((x) => x.di === ico || x.oi === ico).slice(0, 30);
  const nazev = (t && t.n) || (inv && inv.n) || (zak[0] && (zak[0].zi === ico ? zak[0].zd : zak[0].v)) || ico;
  otevriPanel(`<h2>${esc(nazev)}</h2><p class="tlumene">IČO ${esc(ico)} · <a href="https://ares.gov.cz/ekonomicke-subjekty?ico=${esc(ico)}" target="_blank" rel="noopener">ARES</a> · <a href="https://or.justice.cz/ias/ui/rejstrik-$firma?ico=${esc(ico)}" target="_blank" rel="noopener">obchodní rejstřík</a></p>
    ${t ? tabInfo([radekInfo("Segment", esc(t.sg)), radekInfo("Zaměstnanci", esc(t.zam)), radekInfo("Sídlo", odkazObce(obecZMista(t.m), t.ob) + ", " + esc(t.kr)),
      radekInfo("Vznik", datum(t.dv)), radekInfo("CZ-NACE", esc(t.nace)), radekInfo("Signály", (t.si || "").split(" | ").map(esc).join("<br>")),
      radekInfo("Typické potřeby segmentu", esc(t.po))]) : inv ? tabInfo([radekInfo("Sídlo", esc(inv.ob) + ", " + esc(inv.kr)), radekInfo("CZ-NACE", esc(inv.nace)), radekInfo("Vznik", datum(inv.dv))]) : ""}
    ${zam.length ? `<h3>Stavby, kde je stavebníkem (${zam.length})</h3>${zam.map((x) => `<div class="pp"><a href="#" data-zamer="${esc(x.k)}">${esc(x.n)}</a> · ${esc(pop("zfaze", x.f))} ${datum(x.df)}</div>`).join("")}` : ""}
    ${zak.length ? `<h3>Zakázky (${zak.length})</h3>${zak.slice(0, 30).map((x) => `<div class="pp"><a href="#" data-zakazka="${esc(x.k)}">${esc(x.n)}</a> · ${x.zi === ico ? "zadavatel" : "vítěz"}${x.cb ? " · " + kcKratce(x.cb) : ""}</div>`).join("")}` : ""}
    ${sml.length ? `<h3>Smlouvy v registru smluv (${sml.length})</h3>${sml.map((x) => `<div class="pp">${datum(x.d)} · ${odkaz(x.u, x.p)} · ${x.di === ico ? "dodavatel" : "objednatel"}${x.h ? " · " + kcKratce(x.h) : ""}</div>`).join("")}` : ""}`);
}

/* ------------------------------------------------------------------ KALENDÁŘ */
function udalostiKalendare() {
  const dnes = dnesIso(), ev = [];
  if ($("#kal-vyzvy").checked) {
    for (const z of D.zakazky) if (z.lh && z.lh.slice(0, 10) >= dnes && cinnostSedi(z))
      ev.push({ d: z.lh.slice(0, 10), cas: z.lh.slice(11, 16), typ: "lhůta zakázky", n: z.n, kde: z.zd, u: z.u, id: "zak-" + z.k });
    for (const d of D.dokumenty) if (d.t === "vyzva_zakazka" && d.lh && d.lh >= dnes && cinnostSedi(d))
      ev.push({ d: d.lh, cas: "", typ: "lhůta výzvy", n: d.n, kde: d.d, u: d.u, id: "vyz-" + d.id });
  }
  if ($("#kal-up").checked)
    for (const z of D.zmeny_up) if (z.dpj && z.dpj >= dnes && cinnostSedi(z))
      ev.push({ d: z.dpj, cas: "", typ: "projednání ÚP", n: `${z.ob} – ${nazevZmeny(z)} (${pop("faze", z.f)})`, kde: z.ob, u: (DOK_PODLE_ID.get(z.ids[z.ids.length - 1]) || {}).u, id: "up-" + z.k });
  if ($("#kal-drazby").checked)
    for (const n of D.nabidky) if (n.a && n.da && n.da.slice(0, 10) >= dnes && cinnostSedi(n))
      ev.push({ d: n.da.slice(0, 10), cas: (n.da.slice(11, 16) || ""), typ: pop("druh", n.dr), n: n.n, kde: n.ku || n.ok, u: n.u, id: "nab-" + n.k });
  if ($("#kal-prodeje").checked)
    for (const d of D.dokumenty) if (d.t === "prodej_majetku" && d.lh && d.lh >= dnes && cinnostSedi(d))
      ev.push({ d: d.lh, cas: "", typ: "lhůta prodeje obce", n: d.n, kde: d.d, u: d.u, id: "pro-" + d.id });
  return ev.sort((a, b) => (a.d + a.cas > b.d + b.cas ? 1 : -1));
}
function kresliKalendar() {
  const ev = udalostiKalendare();
  $("#kal-pocet").textContent = `${cislo(ev.length)} událostí`;
  let mesic = "";
  $("#t-kalendar").innerHTML = `<thead><tr><th>Datum</th><th>Druh</th><th>Co</th><th>Kde</th></tr></thead><tbody>` + ev.slice(0, 1500).map((e) => {
    const m = e.d.slice(0, 7), hl = m !== mesic ? `<tr class="mesic"><td colspan="4">${new Date(e.d + "T00:00:00").toLocaleDateString("cs-CZ", { month: "long", year: "numeric" })}</td></tr>` : "";
    mesic = m;
    return hl + `<tr><td>${datum(e.d)}${e.cas && e.cas !== "00:00" ? " " + esc(e.cas) : ""}</td><td><span class="stitek">${esc(e.typ)}</span></td><td class="nazev-bunka">${odkaz(e.u, e.n)}</td><td>${esc(e.kde)}</td></tr>`;
  }).join("") + "</tbody>";
}
napoj(["#kal-vyzvy", "#kal-up", "#kal-drazby", "#kal-prodeje"], kresliKalendar);
function ics(ev) {
  const t = (s) => String(s || "").replace(/\\/g, "\\\\").replace(/[,;]/g, (c) => "\\" + c).replace(/\n/g, "\\n");
  const zalom = (r) => { const out = []; let x = r; while (x.length > 74) { out.push(x.slice(0, 74)); x = " " + x.slice(74); } out.push(x); return out.join("\r\n"); };
  const ted = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15) + "Z";
  const radky = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//datasety-prehled//CS", "CALSCALE:GREGORIAN"];
  for (const e of ev) {
    const d = e.d.replace(/-/g, "");
    radky.push("BEGIN:VEVENT", `UID:${t(e.id)}@datasety-prehled`, `DTSTAMP:${ted}`);
    if (e.cas && e.cas !== "00:00") {
      const c = e.cas.replace(":", "") + "00";
      radky.push(`DTSTART;TZID=Europe/Prague:${d}T${c}`, `DURATION:PT1H`);
    } else {
      const dalsi = new Date(e.d + "T00:00:00Z"); dalsi.setUTCDate(dalsi.getUTCDate() + 1);
      radky.push(`DTSTART;VALUE=DATE:${d}`, `DTEND;VALUE=DATE:${dalsi.toISOString().slice(0, 10).replace(/-/g, "")}`);
    }
    radky.push(`SUMMARY:${t(e.typ + ": " + e.n)}`, `LOCATION:${t(e.kde)}`, `DESCRIPTION:${t(e.u || "")}`);
    if (e.u) radky.push(`URL:${t(e.u)}`);
    radky.push("BEGIN:VALARM", "TRIGGER:-P2D", "ACTION:DISPLAY", `DESCRIPTION:${t(e.typ)}`, "END:VALARM", "END:VEVENT");
  }
  radky.push("END:VCALENDAR");
  return radky.map(zalom).join("\r\n") + "\r\n";
}
$("#kal-ics").onclick = () => {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([ics(udalostiKalendare())], { type: "text/calendar;charset=utf-8" }));
  a.download = `lhuty-${dnesIso()}.ics`; a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
};
