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
  sig: {
    drazba_parcela_v_zmene_up: "dražba parcely, které se týká změna ÚP", drazba_v_obci_se_zmenou_up: "dražba / nabídka v obci se změnou ÚP",
    uzemni_studie_schvalena: "územní studie schválena", uzemni_studie_zadana: "územní studie zadána",
    zakazka_zrusena_znovu_vypsana: "zrušená zakázka – znovu vypsaná", zakazka_zrusena_zatim_nevypsana: "zrušená zakázka – zatím nevypsaná",
    pd_hotova_stavba_nevypsana: "PD hotová, stavba nevypsaná", stavba_bez_tdi: "stavba bez zakázky na TDI / BOZP",
    zastupitelstvo_pd_bez_zakazky: "zastupitelstvo o PD, zakázka nevypsaná", nabidka_pod_cenou_okresu: "nabídka pod mediánem okresu",
    investor_vice_staveb: "investor s více stavbami", kolaudace_bytoveho_domu: "kolaudace bytového domu (+ nové SVJ)",
    stavba_a_priroda: "stavba v k.ú. s Naturou / ZCHÚ", kompenzacni_opatreni: "kompenzační opatření", prunik_zdroju: "průnik zdrojů",
  },
};
const SIG_NAPOVEDA = {
  drazba_parcela_v_zmene_up: "Dražená / nabízená parcela je přímo uvedena ve změně územního plánu – nový vlastník bude řešit využití plochy.",
  drazba_v_obci_se_zmenou_up: "V obci probíhá změna ÚP a zároveň je tu aktivní dražba nebo nabídka nemovitosti.",
  uzemni_studie_schvalena: "Územní studie byla schválena k využití (2 roky) – plocha je připravená na parcelaci, sítě a projekty.",
  uzemni_studie_zadana: "Obec zadala územní studii – studie se teprve zpracovává.",
  zakazka_zrusena_znovu_vypsana: "Zakázka byla zrušena a zadavatel vypsal podobnou znovu (podobnost názvu ≥ 50 %).",
  zakazka_zrusena_zatim_nevypsana: "Zakázka byla zrušena a podobná zatím vypsaná není – zadavatel potřebu pořád má.",
  pd_hotova_stavba_nevypsana: "Zadavatel má smlouvu na projektovou dokumentaci starší než 120 dní a stavbu zatím nevypsal.",
  stavba_bez_tdi: "Vypsaná stavba od 5 mil. Kč, ke které zadavatel do 180 dní nevypsal TDI ani BOZP koordinátora.",
  zastupitelstvo_pd_bez_zakazky: "Zastupitelstvo projednávalo projektovou dokumentaci, zakázka ani smlouva na PD od zadavatele v datech není.",
  nabidka_pod_cenou_okresu: "Cena za m² je pod 70 % mediánu okresu pro stejný druh pozemku (aspoň 5 cen v okrese).",
  investor_vice_staveb: "Stejné IČO je stavebníkem u více staveb – opakovaný investor.",
  kolaudace_bytoveho_domu: "Kolaudace bytového domu; pokud v obci vzniklo nové SVJ, je uvedeno.",
  stavba_a_priroda: "Stavba v katastru s Naturou 2000 nebo ZCHÚ – může být potřeba naturové hodnocení (§45i) nebo výjimka (§56) / souhlas (§67).",
  kompenzacni_opatreni: "Text dokumentu zmiňuje kompenzační / náhradní opatření (výsadby, biotopy).",
  prunik_zdroju: "Na stejné parcele nebo u stejného IČO se během 12 měsíců sešly dva a více různé druhy událostí.",
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
let ZAK_PODLE_KLICE = new Map(), NAB_ZAK = new Map(), KONK = new Map();
function pripravData() {
  for (const k of ["zamery", "zakazky", "nabidky_zak", "smlouvy", "tipy", "udalosti_up"]) D[k] = D[k] || [];
  D.obce_up = D.obce_up || {}; D.investori = D.investori || {};
  for (const k of ["prodeje", "studie", "signaly"]) D[k] = D[k] || [];
  for (const k of ["predmety", "zmeny_ev", "firmy_obce"]) D[k] = D[k] || {};
  D.souvislosti = D.souvislosti || {}; D.kontext = D.kontext || {};
  for (const k of ["ceny_pozemku", "trh", "trendy", "pipeline", "navaznosti", "konkurence", "pruniky"]) D.souvislosti[k] = D.souvislosti[k] || [];
  for (const k of ["obce", "ku", "budovy", "insolvence"]) D.kontext[k] = D.kontext[k] || {};
  KONK = new Map(D.souvislosti.konkurence.map((x) => [x.ico, x]));
  naplnVyber("#g-typ", D.signaly, "t", "sig");
  naplnVyber("#g-kraj", D.signaly, "kr");
  naplnVyber("#p-druh", D.prodeje, "dr");
  naplnVyber("#p-kraj", D.prodeje, "kr");
  naplnVyber("#us-kraj", D.studie, "kr");
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
  signaly: kresliSignaly, trh: kresliTrh,
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
  { k: "n", t: "Předmět", sir: 1, f: (r) => `<a href="#" data-nabidka="${esc(r.k)}">${esc(r.n)}</a>${stitkyNabidky(r)}<div class="tlumene">${esc(pop("typ", r.t))}${r.dp ? " · " + esc(r.dp) : ""}${r.po ? " · podíl " + esc(r.po) : ""}${(D.predmety[r.k] || []).length > 1 ? ` · ${D.predmety[r.k].length} položek` : ""}</div>` },
  { k: "z", t: "Zdroj", f: (r) => `${esc(pop("zdroj", r.z))}<div class="tlumene">${esc(pop("druh", r.dr))}</div>` },
  { k: "s", t: "Stav", f: (r) => `<span class="stitek${r.a ? " ok" : ""}">${esc(pop("stav", r.s))}</span>${r.op === "1" ? ' <span class="stitek">opakovaná</span>' : ""}` },
  { k: "ok", t: "Okres / k.ú.", f: (r) => `${esc(r.ok)}<div class="tlumene">${esc(r.ku)}</div>` },
  { k: "v", t: "Výměra m²", c: 1, f: (r) => cislo(r.v) },
  { k: "cv", t: "Vyvolávací cena", c: 1, f: (r) => kc(r.cv) },
  { k: "co", t: "Odhad", c: 1, f: (r) => kc(r.co) },
  { k: "cd", t: "Dosažená", c: 1, f: (r) => kc(r.cd) + (r.dk ? `<div class="tlumene">${esc(r.dk)} × odhad</div>` : "") },
  { k: "cm", t: "Kč/m²", c: 1, f: (r) => cislo(r.cm) },
  { k: "da", t: "Konání", f: (r) => datum(r.da || r.dz) },
  { k: "p", t: "Prodávající", f: (r) => `${r.pi ? `<a href="#" data-firma="${esc(r.pi)}">${esc(r.p)}</a>` : esc(r.p)}${r.pi ? `<div class="tlumene">IČO ${esc(r.pi)}</div>` : ""}` },
];
function stitkyNabidky(r) {
  const s = [];
  if (r.pm) s.push('<span class="stitek">památka</span>');
  if (r.pr) s.push(`<span class="stitek" title="${esc(r.pr)}">opakovaná (${(r.pr.match(/;/g) || []).length + 1}×)</span>`);
  if (r.j) s.push(`<span class="stitek" title="jistota">jistota ${kcKratce(r.j)}</span>`);
  return s.length ? " " + s.join(" ") : "";
}
function kresliNabidky(zpet) {
  if (zpet === true) stavN.n = NA_STRANKU;
  stavN.prekresli = kresliNabidky;
  const r = filtrNabidky();
  $("#n-pocet").textContent = `${cislo(r.length)} záznamů`;
  tabulka($("#t-nabidky"), SL_NAB, r, stavN);
  if (zpet !== true || !$("#t-prodeje").innerHTML) kresliProdeje();
}
napoj(["#n-hledat", "#n-zdroj", "#n-stav", "#n-typ", "#n-okres", "#n-aktivni"], kresliNabidky);
$("#n-csv").onclick = () => stahniCsv("nabidky", [
  ["klic", (r) => r.k], ["zdroj", (r) => r.z], ["druh", (r) => r.dr], ["stav", (r) => r.s], ["aktivni", (r) => r.a],
  ["predmet_typ", (r) => r.t], ["nazev", (r) => r.n], ["prodavajici", (r) => r.p], ["okres", (r) => r.ok],
  ["katastralni_uzemi", (r) => r.ku], ["vymera_m2", (r) => r.v], ["druh_pozemku", (r) => r.dp], ["podil", (r) => r.po],
  ["cena_vyvolavaci", (r) => r.cv], ["cena_odhad", (r) => r.co], ["cena_dosazena", (r) => r.cd], ["cena_za_m2", (r) => r.cm],
  ["datum_zverejneni", (r) => r.dz], ["datum_zahajeni", (r) => r.da], ["datum_ukonceni", (r) => r.du],
  ["prvni_zachyceni", (r) => r.pz], ["pamatka", (r) => r.pm], ["predchozi_drazby", (r) => r.pr], ["jistota", (r) => r.j],
  ["prodavajici_ico", (r) => r.pi], ["posledni_zmena", (r) => r.oz], ["url", (r) => r.u],
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
  { k: "n", t: "Dokument", sir: 1, f: (r) => `${odkaz(r.u, r.n)}<div class="tlumene">${[r.ds, r.h && "soukromá stavba", r.pt && "příroda: " + r.pt, r.sz && "sp. zn. " + r.sz, r.cj && "č. j. " + r.cj, r.uf && "ÚP: " + pop("faze", r.uf), r.lh && "lhůta " + datum(r.lh)].filter(Boolean).map(esc).join(" · ")}</div>${r.zb ? `<div class="body-zast">${r.zb.split(" | ").map((b) => "▸ " + esc(b)).join("<br>")}</div>` : ""}` },
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
  ["lhuta", (r) => r.lh], ["priroda", (r) => r.pt], ["up_faze", (r) => r.uf], ["spisova_znacka", (r) => r.sz], ["cislo_jednaci", (r) => r.cj], ["url", (r) => r.u],
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
  for (const b of ["zakazky", "upd", "firmy", "souvislosti", "kontext"]) tab($("#t-beh-" + b), D.behy[b] || []);
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
  const a = e.target.closest("[data-obec],[data-zamer],[data-up],[data-zakazka],[data-firma],[data-nabidka]");
  if (!a) return;
  e.preventDefault();
  if (a.dataset.obec) profilObce(a.dataset.obec);
  else if (a.dataset.zamer) detailZameru(a.dataset.zamer);
  else if (a.dataset.up) detailUp(a.dataset.up);
  else if (a.dataset.zakazka) detailZakazky(a.dataset.zakazka);
  else if (a.dataset.firma) profilFirmy(a.dataset.firma);
  else if (a.dataset.nabidka) detailNabidky(a.dataset.nabidka);
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
  kresliStudie();
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
  const us = D.studie.filter((x) => x.o === kod), zev = D.zmeny_ev[kod] || [], fo = D.firmy_obce[kod] || {};
  const pro = D.prodeje.filter(vObci).slice(0, 30), sig = D.signaly.filter((x) => x.o === kod);
  otevriPanel(`<h2>${esc(jmeno)}</h2><p class="tlumene">kód obce ${esc(kod)}${ev && ev.kr ? " · " + esc(ev.kr) : ""}</p>
    ${panelKontextObce(kod)}
    ${signalyHtml(sig, "Signály v obci")}
    ${ev ? `<h3>Územní plán (celostátní evidence ÚÚR)</h3>${panelEvidence(ev)}` : ""}
    ${zev.length ? `<h3>Změny ÚP v celostátní evidenci (${zev.length})</h3>${zev.slice(-15).reverse().map(([n, d]) => `<div class="pp">${esc(n)} <span class="tlumene">· zachyceno ${datum(d)}</span></div>`).join("")}` : ""}
    ${us.length ? `<h3>Územní studie a regulační plány (${us.length})</h3>${us.map((x) => `<div class="pp"><b>${esc(x.t)}</b> ${esc(x.n)} · ${esc(x.e)} ${datum(x.d)}${x.zh ? `<div class="tlumene">zhotovitel: ${esc(x.zh)}${x.zi ? " (IČO " + esc(x.zi) + ")" : ""}</div>` : ""}</div>`).join("")}` : ""}
    ${ud.length ? `<h3>Novinky v evidenci</h3>${ud.map((u) => `<div class="pp">${datum(u.d)} · ${esc(pop("udup", u.u))}: ${esc(u.p)}</div>`).join("")}` : ""}
    <h3>Změny územního plánu (${up.length})</h3>${up.map((r) => `<div class="pp"><a href="#" data-up="${esc(r.k)}">${esc(nazevZmeny(r))}</a> · ${esc(pop("faze", r.f))} ${datum(r.df)}${r.pl ? ` · <span class="tlumene">${esc(r.pl)}</span>` : ""}</div>`).join("") || '<p class="tlumene">—</p>'}
    <h3>Stavby (${zam.length})</h3>${zam.slice(0, 30).map((r) => `<div class="pp"><a href="#" data-zamer="${esc(r.k)}">${esc(r.n)}</a> · ${esc(pop("zfaze", r.f))} ${datum(r.df)}${r.cena ? " · cca " + kcKratce(r.cena) : ""}</div>`).join("") || '<p class="tlumene">—</p>'}
    <h3>Zastupitelstvo – stavební body</h3>${zast.map((d) => `<div class="pp">${datum(d.dt)} · ${odkaz(d.u, d.n)}<div class="body-zast">${d.zb.split(" | ").slice(0, 6).map((b) => "▸ " + esc(b)).join("<br>")}</div></div>`).join("") || '<p class="tlumene">—</p>'}
    <h3>Zakázky (${zak.length})</h3>${zak.slice(0, 20).map((r) => `<div class="pp"><a href="#" data-zakazka="${esc(r.k)}">${esc(r.n)}</a> · ${esc(r.s)}${r.cb ? " · " + kcKratce(r.cb) : ""}</div>`).join("") || '<p class="tlumene">—</p>'}
    ${sml.length ? `<h3>Smlouvy zadavatelů z obce (registr smluv)</h3>${sml.map((s) => `<div class="pp">${datum(s.d)} · ${odkaz(s.u, s.p)} · ${esc(s.do)}${s.h ? " · " + kcKratce(s.h) : ""}</div>`).join("")}` : ""}
    <h3>Aktivní nabídky a dražby (${nab.length})</h3>${nab.slice(0, 20).map((r) => `<div class="pp"><a href="#" data-nabidka="${esc(r.k)}">${esc(r.n)}</a>${stitkyNabidky(r)} · ${esc(pop("stav", r.s))}${r.cv ? " · " + kcKratce(r.cv) : ""}</div>`).join("") || '<p class="tlumene">—</p>'}
    ${pro.length ? `<h3>Prodeje a dražby obce – parcely (${pro.length})</h3>${pro.map((x) => `<div class="pp">${datum(x.d)} · ${odkaz(x.u, (x.par || x.ku || "parcela"))} · ${esc(x.dr)}${x.v ? " · " + cislo(x.v) + " m²" : ""}${x.cm ? " · " + cislo(x.cm) + " Kč/m²" : ""}</div>`).join("")}` : ""}
    ${Object.keys(fo).length ? `<h3>Firmy a organizace se sídlem v obci (podle segmentu)</h3>${tabInfo(Object.entries(fo).sort((a, b) => b[1] - a[1]).slice(0, 15).map(([k, v]) => radekInfo(k, cislo(v))))}` : ""}
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
  ["cena_bez_dph", (r) => r.cb], ["cena_s_dph", (r) => r.cs], ["evidencni_cislo_vvz", (r) => r.vvz], ["posledni_zmena", (r) => r.zm],
  ["datum_smlouvy", (r) => r.ds], ["url", (r) => r.u],
], filtrZakazky());
function detailZakazky(klic) {
  const r = ZAK_PODLE_KLICE.get(klic);
  if (!r) return;
  const nab = (NAB_ZAK.get(klic) || []).slice().sort((a, b) => (a.c || 9e15) - (b.c || 9e15));
  otevriPanel(`<h2>${esc(r.n)}</h2>${r.c ? `<p>${esc(r.c)}</p>` : ""}<p class="tlumene">${esc(r.zd)} · ${odkazObce(obecZMista(r.m), r.ob)} · ${esc(r.kr)}</p>
    ${tabInfo([radekInfo("Kategorie", esc(r.kat)), radekInfo("CPV", esc(r.cpv)), radekInfo("Druh řízení", esc(r.dr) + (r.rez ? ` (${esc(r.rez)})` : "")),
      radekInfo("Stav", esc(r.s)), radekInfo("Zveřejněno", datum(r.dz)), radekInfo("Lhůta pro nabídky", r.lh ? datum(r.lh) + " " + esc(r.lh.slice(11)) : ""),
      radekInfo("Vítěz", r.v ? `${esc(r.v)} <span class="tlumene">IČO ${esc(r.vi)}</span>` : ""), radekInfo("Smluvní cena bez DPH", r.cb ? kc(r.cb) : ""), radekInfo("Cena s DPH", r.cs ? kc(r.cs) : ""),
      radekInfo("Evidenční číslo ve VVZ", esc(r.vvz)),
      radekInfo("Poslední změna na profilu", datum(r.zm)),
      radekInfo("Smlouva uzavřena", datum(r.ds)), radekInfo("Zadavatel", `${esc(r.zd)} <span class="tlumene">IČO ${esc(r.zi)}${r.zt === "soukromy" ? ", soukromý" : ""}</span>`),
      radekInfo("Odkaz", odkaz(r.u, "profil zadavatele / detail"))])}
    ${r.p ? `<h3>Předmět</h3><p>${esc(r.p)}</p>` : ""}
    <h3>Nabídky (${nab.length})</h3>${nab.length ? `<table class="info"><tr><th>Účastník</th><th class="cis">Cena bez DPH</th></tr>${nab.map((n) => `<tr><td>${n.v ? "<b>" : ""}${n.i ? `<a href="#" data-firma="${esc(n.i)}">${esc(n.n)}</a>` : esc(n.n)}${n.v ? " ✓</b>" : ""} <span class="tlumene">${esc(n.i)}</span></td><td class="cis">${n.c ? kc(n.c) : ""}</td></tr>`).join("")}</table>` : '<p class="tlumene">—</p>'}`);
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
  { k: "si", t: "Signály", sir: 1, f: (r) => (D.kontext.insolvence[r.i] ? '<span class="stitek varovani">insolvence</span><br>' : "") + (r.si || "").split(" | ").map((x) => "▸ " + esc(x)).join("<br>") + (r.bu ? `<div class="tlumene">budova v sídle: ${esc(r.bu)}</div>` : "") },
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
  ["nace", (r) => r.nace], ["budova_v_sidle", (r) => r.bu], ["insolvence", (r) => (D.kontext.insolvence[r.i] || {}).spisova_znacka || ""],
], filtrTipy());
function profilFirmy(ico) {
  const t = D.tipy.find((x) => x.i === ico), inv = D.investori[ico];
  const zam = D.zamery.filter((x) => x.si === ico), zak = D.zakazky.filter((x) => x.zi === ico || x.vi === ico);
  const sml = D.smlouvy.filter((x) => x.di === ico || x.oi === ico).slice(0, 30);
  const nazev = (t && t.n) || (inv && inv.n) || (zak[0] && (zak[0].zi === ico ? zak[0].zd : zak[0].v)) || ico;
  otevriPanel(`<h2>${esc(nazev)}</h2><p class="tlumene">IČO ${esc(ico)} · <a href="https://ares.gov.cz/ekonomicke-subjekty?ico=${esc(ico)}" target="_blank" rel="noopener">ARES</a> · <a href="https://or.justice.cz/ias/ui/rejstrik-$firma?ico=${esc(ico)}" target="_blank" rel="noopener">obchodní rejstřík</a></p>
    ${t ? tabInfo([radekInfo("Segment", esc(t.sg)), radekInfo("Zaměstnanci", esc(t.zam)), radekInfo("Sídlo", odkazObce(obecZMista(t.m), t.ob) + ", " + esc(t.kr)),
      radekInfo("Vznik", datum(t.dv)), radekInfo("CZ-NACE", esc(t.nace)), radekInfo("Signály", (t.si || "").split(" | ").map(esc).join("<br>")),
      radekInfo("Typické potřeby segmentu", esc(t.po)), radekInfo("Budova v sídle (RÚIAN)", panelBudovy(D.kontext.budovy[t.am]) || esc(t.bu || ""))]) : inv ? tabInfo([radekInfo("Sídlo", esc(inv.ob) + ", " + esc(inv.kr)), radekInfo("CZ-NACE", esc(inv.nace)), radekInfo("Vznik", datum(inv.dv))]) : ""}
    ${panelInsolvence(ico)}${panelKonkurenta(ico)}
    ${zam.length ? `<h3>Stavby, kde je stavebníkem (${zam.length})</h3>${zam.map((x) => `<div class="pp"><a href="#" data-zamer="${esc(x.k)}">${esc(x.n)}</a> · ${esc(pop("zfaze", x.f))} ${datum(x.df)}</div>`).join("")}` : ""}
    ${zak.length ? `<h3>Zakázky (${zak.length})</h3>${zak.slice(0, 30).map((x) => `<div class="pp"><a href="#" data-zakazka="${esc(x.k)}">${esc(x.n)}</a> · ${x.zi === ico ? "zadavatel" : "vítěz"}${x.cb ? " · " + kcKratce(x.cb) : ""}</div>`).join("")}` : ""}
    ${sml.length ? `<h3>Smlouvy v registru smluv (${sml.length})</h3>${sml.map((x) => `<div class="pp">${datum(x.d)} · ${odkaz(x.u, x.p)} · ${x.di === ico ? "dodavatel" : "objednatel"}${x.h ? " · " + kcKratce(x.h) : ""}</div>`).join("")}` : ""}
    ${signalyHtml(D.signaly.filter((x) => x.k === ico || (x.s || "").split("; ").includes(ico)), "Signály s tímto IČO")}`);
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

/* ================================================================== SOUVISLOSTI, KONTEXT, SIGNÁLY, TRH */
function signalyHtml(sig, nadpis) {
  if (!sig.length) return "";
  return `<h3>${esc(nadpis)} (${sig.length})</h3>` + sig.slice(0, 25).map((x) =>
    `<div class="pp"><span class="stitek">${esc(pop("sig", x.t))}</span> ${odkaz(x.u, x.p)}<div class="tlumene">${datum(x.d)} · ${esc(x.z)}</div></div>`).join("");
}
function panelKontextObce(kod) {
  const o = D.kontext.obce[kod], ku = D.kontext.ku[kod] || [];
  const r = [];
  if (o) {
    r.push(radekInfo("Obyvatel", `${cislo(o.obyvatel)}${o.rok ? ` <span class="tlumene">(${esc(o.rok)})</span>` : ""}${o.zmena_5let_pct !== "" && o.zmena_5let_pct != null ? ` · za 5 let ${+o.zmena_5let_pct > 0 ? "+" : ""}${esc(String(o.zmena_5let_pct).replace(".", ","))} %` : ""}`));
    r.push(radekInfo("Dokončené byty za 5 let", o.byty_5let ? `${cislo(o.byty_5let)}${o.byty_na_1000_obyv ? ` <span class="tlumene">(${esc(String(o.byty_na_1000_obyv).replace(".", ","))} na 1000 obyv.)</span>` : ""}` : ""));
  }
  const nat = ku.filter((k) => k[1]), zchu = ku.filter((k) => k[2]), q = ku.filter((k) => +k[3] > 0);
  if (nat.length) r.push(radekInfo("Natura 2000", nat.map((k) => `${esc(k[0])}: ${esc(k[1])}`).join("<br>")));
  if (zchu.length) r.push(radekInfo("Zvláště chráněná území", zchu.map((k) => `${esc(k[0])}: ${esc(k[2])}`).join("<br>")));
  if (q.length) r.push(radekInfo("Záplavové území Q100", q.map((k) => `${esc(k[0])}: ${esc(String(k[3]).replace(".", ","))} % plochy k.ú.`).join("<br>")));
  if (!r.filter(Boolean).length) return "";
  return `<h3>Obec v číslech a omezení území</h3>${tabInfo(r)}<p class="tlumene">Zdroj: ČSÚ, AOPK ČR, DIBAVOD (Q100). Omezení po katastrech – jen orientačně, ne po parcelách.</p>`;
}
function panelBudovy(b) {
  if (!b || !b.so_kod) return "";
  const c = [b.vyuziti, b.dokonceni && "dokončeno " + b.dokonceni, b.konstrukce, b.vytapeni, b.podlazi && b.podlazi + " podlaží",
    b.byty && b.byty !== "0" && b.byty + " bytů", b.zastavena_plocha && cislo(b.zastavena_plocha) + " m² zastavěno",
    b.obestaveny_prostor && cislo(b.obestaveny_prostor) + " m³", b.vytah === "1" && "výtah", b.plyn === "1" && "plyn"].filter(Boolean);
  return esc(c.join(", "));
}
function panelInsolvence(ico) {
  const i = D.kontext.insolvence[ico];
  if (!i) return "";
  return `<p class="varovani-text"><b>Insolvenční rejstřík:</b> ${esc(i.spisova_znacka)} · ${esc(i.stav)}${i.zahajeni ? " · od " + datum(i.zahajeni) : ""} · <a href="https://isir.justice.cz/isir/common/index.do" target="_blank" rel="noopener">ISIR</a></p>`;
}
function panelKonkurenta(ico) {
  const k = KONK.get(ico);
  const nab = D.nabidky_zak.filter((n) => n.i === ico);
  if (!k && !nab.length) return "";
  const soupeři = new Map();
  for (const n of nab) for (const m of NAB_ZAK.get(n.k) || []) if (m.i && m.i !== ico) {
    if (!soupeři.has(m.i)) soupeři.set(m.i, { n: m.n, c: 0, w: 0 });
    const s = soupeři.get(m.i); s.c++; if (m.v) s.w++;
  }
  const top = [...soupeři].sort((a, b) => b[1].c - a[1].c).slice(0, 8);
  return `<h3>Profil konkurenta (zakázky z profilů zadavatelů)</h3>` + (k ? tabInfo([
    radekInfo("Nabídek / výher", `${cislo(k.nabidek)} / ${cislo(k.vyher)} (${esc(k.uspesnost_pct)} %)`),
    radekInfo("Medián náskoku při výhře", k.median_nahskok_pct ? esc(String(k.median_nahskok_pct).replace(".", ",")) + " % pod druhou nabídkou" : ""),
    radekInfo("Medián ztráty při prohře", k.median_ztrata_pct ? esc(String(k.median_ztrata_pct).replace(".", ",")) + " % nad vítězem" : ""),
    radekInfo("Vyhráno celkem", k.vyhry_kc ? kcKratce(+k.vyhry_kc) : ""), radekInfo("Kategorie", esc(k.kategorie)),
    radekInfo("Kraje", esc(k.kraje)), radekInfo("Poslední nabídka", datum(k.posledni))]) : "") +
    (top.length ? `<p class="tlumene">Nejčastější soupeři: ${top.map(([i, s]) => `<a href="#" data-firma="${esc(i)}">${esc(s.n)}</a> (${s.c}×, vyhrál ${s.w}×)`).join(", ")}</p>` : "") +
    (nab.length ? nab.slice(0, 15).map((n) => { const z = ZAK_PODLE_KLICE.get(n.k) || {}; return `<div class="pp">${n.v ? "✓ " : ""}<a href="#" data-zakazka="${esc(n.k)}">${esc(z.n || n.k)}</a>${n.c ? " · " + kcKratce(n.c) : ""}<span class="tlumene"> · ${esc(z.zd || "")}</span></div>`; }).join("") : "");
}

/* ------------------------------------------------------------------ detail nabídky / dražby */
const PREDMET_SL = ["typ", "k.ú.", "parcela", "LV", "výměra m²", "druh pozemku", "využití", "č. p.", "stavba", "jednotka", "podíl"];
function detailNabidky(klic) {
  const r = NAB_PODLE_KLICE.get(klic);
  if (!r) return;
  const pr = D.predmety[klic] || [];
  const zm = D.zmeny.filter((x) => x.klic === klic);
  const obec = obecZMista(r.m);
  const sig = D.signaly.filter((x) => x.k === klic);
  const pouzite = PREDMET_SL.map((_, i) => pr.some((p) => p[i] !== "" && p[i] != null));
  otevriPanel(`<h2>${esc(r.n)}</h2><p class="tlumene">${odkazObce(obec, r.ku || nazevObce(obec) || "obec")} · ${esc(r.ok)} · ${odkaz(r.u, "zdroj →")}</p>
    ${stitkyNabidky(r)}
    ${tabInfo([radekInfo("Zdroj / druh", `${esc(pop("zdroj", r.z))} · ${esc(pop("druh", r.dr))}`), radekInfo("Stav", esc(pop("stav", r.s))),
      radekInfo("Prodávající", `${esc(r.p)}${r.pi ? ` <a href="#" data-firma="${esc(r.pi)}">IČO ${esc(r.pi)}</a>` : ""}`),
      radekInfo("Výměra", r.v ? cislo(r.v) + " m²" : ""), radekInfo("Vyvolávací cena", kc(r.cv)), radekInfo("Odhad", kc(r.co)),
      radekInfo("Dosažená cena", kc(r.cd)), radekInfo("Kč/m²", cislo(r.cm)), radekInfo("Jistota", kc(r.j)),
      radekInfo("Konání", datum(r.da)), radekInfo("Předchozí dražby", esc(r.pr)), radekInfo("Kulturní památka", r.pm ? "ano" : ""),
      radekInfo("Zachyceno / naposledy viděno", `${datum(r.pz)}${r.nv ? " / " + datum(r.nv) : ""}`), radekInfo("Poslední změna", datum(r.oz)),
      radekInfo("Navazující činnosti", esc(r.nc))])}
    ${signalyHtml(sig, "Signály")}
    <h3>Předměty (${pr.length})</h3>${pr.length ? `<div class="tabulka-obal"><table class="info"><tr>${PREDMET_SL.filter((_, i) => pouzite[i]).map((t) => `<th>${esc(t)}</th>`).join("")}</tr>${pr.map((p) => `<tr>${p.filter((_, i) => pouzite[i]).map((v) => `<td>${esc(v)}</td>`).join("")}</tr>`).join("")}</table></div>` : '<p class="tlumene">Rozpis předmětů zdroj neuvádí.</p>'}
    ${zm.length ? `<h3>Historie změn</h3>${zm.map((x) => `<div class="pp">${datum(x.datum)} · ${esc(x.pole)}: ${esc(x.stara)} → <b>${esc(x.nova)}</b></div>`).join("")}` : ""}`);
}

/* ------------------------------------------------------------------ prodeje obcí (záložka Dražby a nabídky) */
const stavP = { razeni: "d", smer: -1 };
function filtrProdeje() {
  const h = $("#p-hledat").value, dr = $("#p-druh").value, k = $("#p-kraj").value;
  return D.prodeje.filter((x) => (!dr || x.dr === dr) && (!k || x.kr === k) && hledej(h, x.pr, x.ku, x.par, x.ds, x.ok));
}
const SL_PRO = [
  { k: "d", t: "Dokument", f: (r) => datum(r.d) },
  { k: "pr", t: "Prodávající", f: (r) => `${odkazObce(obecZMista(r.m), r.pr)}<div class="tlumene">${esc(r.ok)}</div>` },
  { k: "par", t: "Parcely / k.ú.", sir: 1, f: (r) => `${odkaz(r.u, r.par || "(bez čísla parcely)")}<div class="tlumene">${esc(r.ku)}${r.dp ? " · " + esc(r.dp) : ""}</div>` },
  { k: "dr", t: "Druh", f: (r) => `<span class="stitek">${esc(r.dr)}</span>` },
  { k: "v", t: "Výměra m²", c: 1, f: (r) => cislo(r.v) },
  { k: "c", t: "Cena", c: 1, f: (r) => kc(r.c || r.np) + (r.oc ? `<div class="tlumene">odhad ${kcKratce(r.oc)}</div>` : "") },
  { k: "cm", t: "Kč/m²", c: 1, f: (r) => cislo(r.cm) + (r.cmd ? '<div class="tlumene">dopočteno</div>' : "") },
  { k: "lh", t: "Lhůta / dražba", f: (r) => datum(r.dd || r.lh) },
];
function kresliProdeje(zpet) {
  if (zpet === true) stavP.n = NA_STRANKU;
  stavP.prekresli = kresliProdeje;
  const r = filtrProdeje();
  $("#p-pocet").textContent = `${cislo(r.length)} parcel / položek`;
  tabulka($("#t-prodeje"), SL_PRO, r, stavP);
}
napoj(["#p-hledat", "#p-druh", "#p-kraj"], kresliProdeje);
$("#p-csv").onclick = () => stahniCsv("prodeje-obci", [
  ["datum", (r) => r.d], ["druh", (r) => r.dr], ["prodavajici", (r) => r.pr], ["deska", (r) => r.ds], ["okres", (r) => r.ok], ["kraj", (r) => r.kr],
  ["katastralni_uzemi", (r) => r.ku], ["parcely", (r) => r.par], ["druh_pozemku", (r) => r.dp], ["vymera_m2", (r) => r.v], ["cena_kc", (r) => r.c],
  ["cena_za_m2", (r) => r.cm], ["nejnizsi_podani", (r) => r.np], ["odhadni_cena", (r) => r.oc], ["datum_drazby", (r) => r.dd], ["lhuta", (r) => r.lh], ["url", (r) => r.u],
], filtrProdeje());

/* ------------------------------------------------------------------ územní studie (záložka ÚP) */
const stavUS = { razeni: "d", smer: -1 };
function filtrStudie() {
  const h = $("#us-hledat").value, t = $("#us-typ").value, k = $("#us-kraj").value, dny = +$("#us-obdobi").value, od = dny ? predDny(dny) : "";
  return D.studie.filter((x) => (!t || x.t === t || (t === "RP" && x.t === "RPP")) && (!k || x.kr === k) && (!od || x.d >= od) && hledej(h, x.n, x.zh, nazevObce(x.o)));
}
const SL_US = [
  { k: "d", t: "Poslední etapa", f: (r) => datum(r.d) },
  { k: "o", t: "Obec", h: (r) => nazevObce(r.o), f: (r) => `${odkazObce(r.o)}<div class="tlumene">${esc(r.kr)}</div>` },
  { k: "n", t: "Název", sir: 1, f: (r) => `<b>${esc(r.t)}</b> ${esc(r.n)}` },
  { k: "e", t: "Etapa", f: (r) => `<span class="stitek${/možnost využití/i.test(r.e) ? " ok" : ""}">${esc(r.e)}</span>` },
  { k: "zh", t: "Zhotovitel", f: (r) => `${esc(r.zh)}${r.zi ? `<div class="tlumene">IČO ${esc(r.zi)}</div>` : ""}` },
];
function kresliStudie(zpet) {
  if (zpet === true) stavUS.n = NA_STRANKU;
  stavUS.prekresli = kresliStudie;
  const r = filtrStudie();
  $("#us-pocet").textContent = `${cislo(r.length)} dokumentací`;
  tabulka($("#t-studie"), SL_US, r, stavUS);
}
napoj(["#us-hledat", "#us-typ", "#us-kraj", "#us-obdobi"], kresliStudie);

/* ------------------------------------------------------------------ SIGNÁLY */
const stavG = { razeni: "d", smer: -1 };
function filtrSignaly() {
  const h = $("#g-hledat").value, t = $("#g-typ").value, k = $("#g-kraj").value, nv = +$("#g-novost").value, od = nv ? predDny(nv) : "";
  return D.signaly.filter((x) => (!t || x.t === t) && (!k || x.kr === k) && (!od || x.pz >= od) && hledej(h, x.on, x.p, x.k));
}
const SL_SIG = [
  { k: "d", t: "Datum", f: (r) => datum(r.d) + (r.pz && r.pz >= predDny(7) ? '<div><span class="stitek ok">nové</span></div>' : "") },
  { k: "t", t: "Druh", f: (r) => `<span class="stitek">${esc(pop("sig", r.t))}</span>` },
  { k: "p", t: "Co se děje", sir: 1, f: (r) => `${odkaz(r.u, r.p)}<div class="tlumene">${esc(r.z)}</div>` },
  { k: "on", t: "Obec", f: (r) => `${odkazObce(r.o, r.on)}<div class="tlumene">${esc(r.kr)}</div>` },
  { k: "k", t: "Souvislosti", f: (r) => odkazSignalu(r) },
];
function odkazSignalu(r) {
  const o = [];
  if (ZAK_PODLE_KLICE.has(r.k)) o.push(`<a href="#" data-zakazka="${esc(r.k)}">zakázka</a>`);
  if (NAB_PODLE_KLICE.has(r.k)) o.push(`<a href="#" data-nabidka="${esc(r.k)}">nabídka</a>`);
  if (D.zamery.some((x) => x.k === r.k)) o.push(`<a href="#" data-zamer="${esc(r.k)}">stavba</a>`);
  if (/^\d{8}$/.test(r.k) && (r.t === "investor_vice_staveb" || r.t === "prunik_zdroju" || KONK.has(r.k) || D.investori[r.k])) o.push(`<a href="#" data-firma="${esc(r.k)}">IČO ${esc(r.k)}</a>`);
  for (const s of (r.s || "").split("; ").filter(Boolean).slice(0, 4)) {
    if (ZAK_PODLE_KLICE.has(s)) o.push(`<a href="#" data-zakazka="${esc(s)}">${esc((ZAK_PODLE_KLICE.get(s).n || "").slice(0, 40))}</a>`);
    else if (D.zmeny_up.some((x) => x.k === s)) o.push(`<a href="#" data-up="${esc(s)}">změna ÚP</a>`);
  }
  return o.join("<br>");
}
function kresliSignaly(zpet) {
  if (zpet === true) stavG.n = NA_STRANKU;
  stavG.prekresli = kresliSignaly;
  const r = filtrSignaly(), t = $("#g-typ").value;
  $("#g-pocet").textContent = `${cislo(r.length)} signálů`;
  const nap = $("#g-napoveda");
  nap.hidden = !t; nap.innerHTML = t ? `<b>${esc(pop("sig", t))}:</b> ${esc(SIG_NAPOVEDA[t] || "")}` : "";
  tabulka($("#t-signaly"), SL_SIG, r, stavG);
  const pr = D.souvislosti.pruniky.slice(0, 400);
  $("#t-pruniky").innerHTML = pr.length ? `<thead><tr><th>Poslední</th><th>Kde / kdo</th><th class="cis">Druhů událostí</th><th>Druhy</th><th>Detail</th></tr></thead><tbody>` +
    pr.map((x) => `<tr><td>${datum(x.posledni)}<div class="tlumene">od ${datum(x.prvni)}</div></td><td>${x.klic_typ === "ico" ? `<a href="#" data-firma="${esc(x.klic)}">IČO ${esc(x.klic)}</a>` : `parcela ${esc(x.klic.split(":")[1] || x.klic)}`}<div class="tlumene">${odkazObce(x.kod_obce)}</div></td><td class="cis"><b>${esc(x.pocet_zdroju)}</b></td><td>${esc(x.zdroje)}</td><td class="nazev-bunka tlumene">${esc(x.detail).slice(0, 400)}</td></tr>`).join("") + "</tbody>"
    : '<tr><td class="tlumene">Zatím žádné průniky.</td></tr>';
}
napoj(["#g-hledat", "#g-typ", "#g-kraj", "#g-novost"], kresliSignaly);
$("#g-csv").onclick = () => stahniCsv("signaly", [
  ["id", (r) => r.id], ["druh", (r) => pop("sig", r.t)], ["datum", (r) => r.d], ["prvni_zachyceni", (r) => r.pz], ["obec", (r) => r.on],
  ["kod_obce", (r) => r.o], ["kraj", (r) => r.kr], ["popis", (r) => r.p], ["zdroje", (r) => r.z], ["odkaz", (r) => r.u], ["klic", (r) => r.k], ["souvisejici", (r) => r.s],
], filtrSignaly());

/* ------------------------------------------------------------------ TRH A KONKURENCE */
function kresliTrh() {
  const S = D.souvislosti, ks = $("#r-kategorie"), kr = $("#r-kraj");
  if (ks.options.length < 2) {
    ks.innerHTML += [...new Set(S.trendy.map((x) => x.kategorie).filter((x) => x !== "vše"))].sort((a, b) => a.localeCompare(b, "cs")).map((k) => `<option>${esc(k)}</option>`).join("");
    kr.innerHTML += [...new Set(S.trh.map((x) => x.kraj).filter((x) => x !== "celá ČR"))].sort((a, b) => a.localeCompare(b, "cs")).map((k) => `<option>${esc(k)}</option>`).join("");
    const dr = $("#r-druh"); dr.innerHTML += [...new Set(S.ceny_pozemku.map((x) => x.druh_pozemku))].sort((a, b) => a.localeCompare(b, "cs")).map((k) => `<option>${esc(k)}</option>`).join("");
  }
  const kat = ks.value, kraj = kr.value;
  // souhrn trhu
  const t = S.trh.find((x) => x.kraj === kraj && x.kategorie === (kat === "vše" ? "vše" : kat)) || {};
  const nav = S.navaznosti.map((x) => +x.zpozdeni_dni).filter((x) => x > 0);
  $("#r-souhrn").innerHTML = [
    [cislo(t.zakazek) || "–", "zakázek", `${esc(kraj)} · ${esc(kat)}`],
    [t.median_nabidek ? String(t.median_nabidek).replace(".", ",") : "–", "medián počtu nabídek", t.jedna_nabidka_pct !== undefined && t.jedna_nabidka_pct !== "" ? `${esc(t.jedna_nabidka_pct)} % zakázek s jedinou nabídkou` : ""],
    [t.median_nahskok_pct ? String(t.median_nahskok_pct).replace(".", ",") + " %" : "–", "medián náskoku vítěze", "o kolik byl vítěz levnější než druhý"],
    [t.zruseno_pct !== undefined && t.zruseno_pct !== "" ? t.zruseno_pct + " %" : "–", "zrušených zakázek", t.median_cena ? "medián ceny " + kcKratce(+t.median_cena) : ""],
    [nav.length ? cislo(Math.round(median(nav))) + " dní" : "–", "PD → vypsání stavby (medián)", nav.length ? `z ${nav.length} párů u stejného zadavatele` : ""],
  ].map(([c, p, s]) => `<div class="karta"><div class="dl-cislo">${c}</div><div class="dl-popis">${p}</div><div class="dl-pod">${s}</div></div>`).join("");
  // trend: posledních 24 měsíců
  const mes = []; const d = new Date(); d.setUTCDate(1);
  for (let i = 0; i < 24; i++) { mes.unshift(d.toISOString().slice(0, 7)); d.setUTCMonth(d.getUTCMonth() - 1); }
  const tr = new Map(S.trendy.filter((x) => x.kategorie === kat).map((x) => [x.mesic, x]));
  const lab = (m) => { const [r, mm] = m.split("-"); return `${+mm}/${r.slice(2)}`; };
  grafSloupce($("#g-trend"), mes.map((m) => { const x = tr.get(m) || {}; return { l: lab(m), v: +x.vyhlaseno || 0, t: `${lab(m)}: <b>${cislo(+x.vyhlaseno || 0)}</b> vyhlášených, ${cislo(+x.s_vysledkem || 0)} s výsledkem${x.median_cena ? ", medián " + kcKratce(+x.median_cena) : ""}${x.smluv ? `<br>registr smluv: ${cislo(+x.smluv)} smluv` : ""}` }; }), "zakázek");
  grafSloupce($("#g-zruseno"), mes.map((m) => { const x = tr.get(m) || {}; return { l: lab(m), v: +x.zruseno || 0, t: `${lab(m)}: <b>${cislo(+x.zruseno || 0)}</b> zrušených` }; }), "zrušených");
  kresliKonkurenci();
  // trh podle kraje
  const trh = S.trh.filter((x) => (kraj === "celá ČR" ? true : x.kraj === kraj) && (kat === "vše" || x.kategorie === kat));
  $("#t-trh").innerHTML = `<thead><tr><th>Kraj</th><th>Kategorie</th><th class="cis">Zakázek</th><th class="cis">Medián nabídek</th><th class="cis">1 nabídka</th><th class="cis">Náskok</th><th class="cis">Medián ceny</th><th class="cis">Zrušeno</th></tr></thead><tbody>` +
    trh.slice(0, 300).map((x) => `<tr><td>${esc(x.kraj)}</td><td>${esc(x.kategorie)}</td><td class="cis">${cislo(x.zakazek)}</td><td class="cis">${esc(String(x.median_nabidek).replace(".", ","))}</td><td class="cis">${x.jedna_nabidka_pct !== "" ? esc(x.jedna_nabidka_pct) + " %" : ""}</td><td class="cis">${x.median_nahskok_pct ? esc(String(x.median_nahskok_pct).replace(".", ",")) + " %" : ""}</td><td class="cis">${x.median_cena ? kcKratce(+x.median_cena) : ""}</td><td class="cis">${x.zruseno_pct !== "" ? esc(x.zruseno_pct) + " %" : ""}</td></tr>`).join("") + "</tbody>";
  // pipeline
  const pl = S.pipeline.filter((x) => kraj === "celá ČR" || x.kraj === kraj)
    .map((x) => ({ ...x, s: +x.up_probiha + +x.stavby_zamer + +x.stavby_rizeni + +x.stavby_povoleni + +x.nabidky_aktivni + +x.zakazky_otevrene + +x.prodeje_obci_rok }))
    .sort((a, b) => b.s - a.s);
  $("#t-pipeline").innerHTML = `<thead><tr><th>Okres</th><th class="cis" title="změny ÚP v běhu">ÚP běží</th><th class="cis" title="vydané změny ÚP za rok">ÚP vydáno</th><th class="cis">Záměry</th><th class="cis">Řízení</th><th class="cis">Povoleno</th><th class="cis">Kolaudace</th><th class="cis">Nabídky</th><th class="cis">Zakázky</th><th class="cis">Prodeje obcí</th></tr></thead><tbody>` +
    pl.map((x) => `<tr><td>${esc(x.okres)}<div class="tlumene">${esc(x.kraj)}</div></td>${["up_probiha", "up_vydano_rok", "stavby_zamer", "stavby_rizeni", "stavby_povoleni", "stavby_kolaudace", "nabidky_aktivni", "zakazky_otevrene", "prodeje_obci_rok"].map((k) => `<td class="cis">${+x[k] ? cislo(x[k]) : ""}</td>`).join("")}</tr>`).join("") + "</tbody>";
  kresliCenyPozemku();
  $("#t-navaznosti").innerHTML = `<thead><tr><th>Zadavatel</th><th>PD (smlouva)</th><th>Stavba (vypsána)</th><th class="cis">Dní</th></tr></thead><tbody>` +
    [...S.navaznosti].sort((a, b) => (b.stavba_zverejneni > a.stavba_zverejneni ? 1 : -1)).slice(0, 300).map((x) => `<tr><td>${esc(x.zadavatel)}</td><td class="nazev-bunka"><a href="#" data-zakazka="${esc(x.pd_klic)}">${esc(x.pd_nazev)}</a><div class="tlumene">${datum(x.pd_smlouva)}</div></td><td class="nazev-bunka"><a href="#" data-zakazka="${esc(x.stavba_klic)}">${esc(x.stavba_nazev)}</a><div class="tlumene">${datum(x.stavba_zverejneni)}</div></td><td class="cis">${cislo(x.zpozdeni_dni)}</td></tr>`).join("") + "</tbody>";
}
function kresliKonkurenci() {
  const h = $("#r-hledat").value, kat = $("#r-kategorie").value, kraj = $("#r-kraj").value;
  const r = D.souvislosti.konkurence.filter((x) => (kat === "vše" || (x.kategorie || "").includes(kat)) && (kraj === "celá ČR" || (x.kraje || "").includes(kraj)) && hledej(h, x.nazev, x.ico));
  $("#r-pocet").textContent = `${cislo(r.length)} firem`;
  $("#t-konkurence").innerHTML = `<thead><tr><th>Firma</th><th class="cis">Nabídek</th><th class="cis">Výher</th><th class="cis">Úspěšnost</th><th class="cis">Náskok</th><th class="cis">Ztráta</th><th class="cis">Vyhráno</th><th>Kategorie / kraje</th><th>Poslední</th></tr></thead><tbody>` +
    r.slice(0, 400).map((x) => `<tr><td><a href="#" data-firma="${esc(x.ico)}">${esc(x.nazev)}</a><div class="tlumene">IČO ${esc(x.ico)}</div></td><td class="cis">${cislo(x.nabidek)}</td><td class="cis">${cislo(x.vyher)}</td><td class="cis">${esc(x.uspesnost_pct)} %</td><td class="cis">${x.median_nahskok_pct ? esc(String(x.median_nahskok_pct).replace(".", ",")) + " %" : ""}</td><td class="cis">${x.median_ztrata_pct ? esc(String(x.median_ztrata_pct).replace(".", ",")) + " %" : ""}</td><td class="cis">${x.vyhry_kc ? kcKratce(+x.vyhry_kc) : ""}</td><td class="tlumene">${esc(x.kategorie)}<br>${esc(x.kraje)}</td><td>${datum(x.posledni)}</td></tr>`).join("") + "</tbody>";
}
function kresliCenyPozemku() {
  const o = $("#r-okres").value, dr = $("#r-druh").value;
  const r = D.souvislosti.ceny_pozemku.filter((x) => (!dr || x.druh_pozemku === dr) && hledej(o, x.okres));
  $("#t-ceny-pozemku").innerHTML = `<thead><tr><th>Okres</th><th>Druh pozemku</th><th class="cis">Cen</th><th class="cis">Medián Kč/m²</th><th class="cis">Polovina mezi</th><th>Období</th></tr></thead><tbody>` +
    r.map((x) => `<tr><td>${esc(x.okres)}</td><td>${esc(x.druh_pozemku)}</td><td class="cis">${cislo(x.pocet)}</td><td class="cis"><b>${cislo(x.median_kc_m2)}</b></td><td class="cis">${cislo(x.p25_kc_m2)} – ${cislo(x.p75_kc_m2)}</td><td class="tlumene">${datum(x.od)} – ${datum(x.do)}<br>${esc(x.zdroje)}</td></tr>`).join("") + "</tbody>";
}
napoj(["#r-kategorie", "#r-kraj"], kresliTrh);
napoj(["#r-hledat"], kresliKonkurenci);
napoj(["#r-okres", "#r-druh"], kresliCenyPozemku);
