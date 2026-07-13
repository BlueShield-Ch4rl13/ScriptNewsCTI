# 🛰️ ScriptNewsCTI

![CTI Update](https://github.com/BlueShield-Ch4rl13/ScriptNewsCTI/actions/workflows/cti-update.yml/badge.svg)

Pipeline de **Cyber Threat Intelligence** que se actualiza solo cada 6 horas mediante GitHub Actions. Recolecta IOCs de feeds públicos, los normaliza, deduplica y defanguea, y publica los resultados en este README y en `data/` (JSON + CSV).

> ⚠️ Uso exclusivamente defensivo (TLP:CLEAR). Los IOCs se muestran defangueados.

## Fuentes

| Feed | Datos | API key |
|---|---|---|
| ThreatFox (abuse.ch) | IOCs de malware (IP, dominios, URLs, hashes) | Gratuita, obligatoria |
| URLhaus (abuse.ch) | URLs de distribución de malware | Gratuita, obligatoria |
| AlienVault OTX | Indicadores de pulses suscritos | Gratuita, opcional |
| CISA KEV | CVEs explotados activamente | No requiere |

## Arquitectura

```
feeds públicos ──> collectors.py ──> normalización + dedupe + defang (utils.py)
                                          │
GitHub Actions (cron 6h) <── main.py ──> data/*.json|csv + README autogenerado
```

## Puesta en marcha

1. Crea un repo en GitHub y sube este contenido.
2. Consigue las claves gratuitas:
   - **abuse.ch**: regístrate en https://auth.abuse.ch y genera tu *Auth-Key* (sirve para ThreatFox y URLhaus).
   - **OTX** (opcional): crea cuenta en https://otx.alienvault.com y copia tu API key del perfil.
3. En el repo: *Settings → Secrets and variables → Actions → New repository secret*:
   - `ABUSECH_API_KEY`
   - `OTX_API_KEY` (opcional)
4. Pestaña **Actions** → workflow *CTI Update* → **Run workflow** para la primera ejecución manual.
5. Listo: el cron lo ejecutará cada 6 h (hora UTC) y el bot hará commit de los cambios.

### Ejecución local

```bash
pip install -r requirements.txt
export ABUSECH_API_KEY="tu_clave"
export OTX_API_KEY="tu_clave"      # opcional
python main.py
```

## Estructura

```
├── .github/workflows/cti-update.yml   # cron + auto-commit
├── main.py                            # orquestador
├── collectors.py                      # un colector por feed
├── utils.py                           # defang, dedupe, export, README
└── data/                              # iocs_latest.json / iocs_latest.csv
```

## Troubleshooting

- **El workflow no commitea**: revisa *Settings → Actions → General → Workflow permissions* y marca *Read and write permissions*.
- **ThreatFox/URLhaus devuelven 401/403**: falta o es inválida la `ABUSECH_API_KEY`.
- **El cron deja de ejecutarse**: GitHub pausa los schedules tras 60 días sin actividad; los commits del bot cuentan como actividad, así que con que funcione no se pausará.

---

## 📊 Datos en vivo

<!-- CTI:START -->
**Última actualización:** 2026-07-13 19:40 UTC · **IOCs recolectados:** 1186 · **CVEs KEV recientes:** 9

### Últimos IOCs (defangueados, máx. 25)

| IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|
| `206[.]189[.]146[.]157:12345` | ip:port | Aisuru | ThreatFox | 2026-07-13 19:30:45 UTC |
| `texjqbwa[.]site-shartbandi-bedun-filter[.]com` | domain | ClearFake | ThreatFox | 2026-07-13 19:08:37 UTC |
| `site-shartbandi-bedun-filter[.]com` | domain | ClearFake | ThreatFox | 2026-07-13 19:07:02 UTC |
| `114[.]132[.]89[.]132:45443` | ip:port | Cobalt Strike | ThreatFox | 2026-07-13 19:05:08 UTC |
| `36[.]140[.]162[.]173:7777` | ip:port | Cobalt Strike | ThreatFox | 2026-07-13 19:05:07 UTC |
| `196[.]251[.]121[.]74:2323` | ip:port | DCRat | ThreatFox | 2026-07-13 19:05:06 UTC |
| `ign0g5ax[.]site-shartbandi-khareji[.]com` | domain | ClearFake | ThreatFox | 2026-07-13 18:54:11 UTC |
| `7vq4on85[.]site-shartbandi-khareji[.]com` | domain | ClearFake | ThreatFox | 2026-07-13 18:52:24 UTC |
| `hxxp://159[.]65[.]201[.]180/hGkBCsBr/Full%20AES[.]pyw` | url | Unknown malware | ThreatFox | 2026-07-13 18:50:19 UTC |
| `authid7[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:18 UTC |
| `193[.]181[.]46[.]146:4444` | ip:port | Unknown malware | ThreatFox | 2026-07-13 18:50:18 UTC |
| `193[.]104[.]222[.]134:443` | ip:port | Unknown malware | ThreatFox | 2026-07-13 18:50:18 UTC |
| `hxxp://159[.]65[.]201[.]180/verify/request[.]vbs` | url | Unknown malware | ThreatFox | 2026-07-13 18:50:18 UTC |
| `0id1[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `0id2[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `0id3[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `0id4[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `0id5[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `0id6[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `0id7[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `0id8[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `0id9[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `authid1[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `authid2[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |
| `authid3[.]xyz` | domain | Unknown malware | ThreatFox | 2026-07-13 18:50:17 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2008-4128 | Cisco IOS | 2026-07-13 | Unknown |
| CVE-2026-56291 | Balbooa Forms | 2026-07-10 | Unknown |
| CVE-2026-48939 | iCagenda iCagenda | 2026-07-10 | Unknown |
| CVE-2026-48908 | JoomShaper SP Page Builder | 2026-07-07 | Unknown |
| CVE-2026-55255 | Langflow Langflow | 2026-07-07 | Unknown |
| CVE-2026-56290 | Joomlack Page Builder | 2026-07-07 | Unknown |
| CVE-2026-48282 | Adobe ColdFusion | 2026-07-07 | Unknown |
| CVE-2026-45659 | Microsoft SharePoint Server | 2026-07-01 | Unknown |
| CVE-2026-48558 | SimpleHelp  SimpleHelp | 2026-06-29 | Unknown |
<!-- CTI:END -->
