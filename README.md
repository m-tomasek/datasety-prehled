# Datasety – přehled

Interaktivní dashboard nad daty z botů v soukromém repozitáři `datasety`
(úřední desky, dražby a nabídky nemovitostí, změny územních plánů) s mapou.

**Data jsou šifrovaná.** Stránka je veřejná, ale soubor `data.enc` bez hesla nikdo nepřečte
(AES-256-GCM, klíč z hesla přes PBKDF2-SHA256, 310 000 iterací). Heslo je jen v GitHub secretu
`DASHBOARD_HESLO` v repozitáři `datasety` a v hlavě majitele.

## Jak to funguje
1. Bot v `datasety` doběhne → workflow *Přehled: export pro dashboard* data zašifruje
   a pošle sem do větve `data` (vždy jen jeden commit).
2. Workflow *Stránka* složí kód z `main` a data z `data` a zveřejní to na GitHub Pages.
3. Otevřená stránka se každé 3 minuty podívá, jestli nepřišla nová data, a sama se obnoví.

## Soubory
- `index.html`, `app.js`, `styl.css` – celá aplikace (bez sestavování, knihovny Leaflet z cdnjs)
- `.github/workflows/stranka.yml` – nasazení na Pages

Poloha na mapě = definiční bod katastrálního území (nebo obce) z RÚIAN, ne přesná parcela.
