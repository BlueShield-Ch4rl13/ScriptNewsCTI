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
**Última actualización:** 2026-07-13 14:14 UTC · **IOCs recolectados:** 1042 · **CVEs KEV recientes:** 8

### Últimos IOCs (defangueados, máx. 25)

| IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|
| `high-priority[.]futurainternationalrealty[.]com` | domain | FAKEUPDATES | ThreatFox | 2026-07-13 14:07:42 UTC |
| `133[.]18[.]165[.]80:6606` | ip:port | AsyncRAT | ThreatFox | 2026-07-13 14:05:50 UTC |
| `133[.]18[.]165[.]80:8808` | ip:port | AsyncRAT | ThreatFox | 2026-07-13 14:05:50 UTC |
| `23[.]149[.]28[.]91:443` | ip:port | Unknown malware | ThreatFox | 2026-07-13 14:05:07 UTC |
| `23[.]149[.]28[.]91:80` | ip:port | Unknown malware | ThreatFox | 2026-07-13 14:05:07 UTC |
| `23[.]149[.]28[.]91:8080` | ip:port | Unknown malware | ThreatFox | 2026-07-13 14:05:07 UTC |
| `23[.]149[.]28[.]91:60000` | ip:port | Unknown malware | ThreatFox | 2026-07-13 14:05:06 UTC |
| `51[.]38[.]99[.]224:443` | ip:port | Unknown Stealer | ThreatFox | 2026-07-13 14:04:23 UTC |
| `outlook8web[.]com` | domain | NetSupportManager RAT | ThreatFox | 2026-07-13 14:00:52 UTC |
| `133[.]18[.]165[.]80:7707` | ip:port | AsyncRAT | ThreatFox | 2026-07-13 14:00:05 UTC |
| `hxxp://oracle[.]zzhreceive[.]top/b2f628/b[.]sh` | url | Kinsing | ThreatFox | 2026-07-13 13:59:52 UTC |
| `hxxp://s[.]na-cs[.]com/t[.]sh` | url | Kinsing | ThreatFox | 2026-07-13 13:59:50 UTC |
| `hxxp://s[.]na-cs[.]com/b2f628/b[.]sh` | url | Kinsing | ThreatFox | 2026-07-13 13:59:48 UTC |
| `162[.]243[.]3[.]92:80` | ip:port | Kinsing | ThreatFox | 2026-07-13 13:59:46 UTC |
| `oracle[.]zzhreceive[.]top` | domain | Kinsing | ThreatFox | 2026-07-13 13:59:41 UTC |
| `s[.]na-cs[.]com` | domain | Kinsing | ThreatFox | 2026-07-13 13:59:39 UTC |
| `136[.]0[.]213[.]113:8041` | ip:port | Unknown RAT | ThreatFox | 2026-07-13 13:59:29 UTC |
| `droptest[.]xyz` | domain | Unknown Loader | ThreatFox | 2026-07-13 13:53:54 UTC |
| `45[.]198[.]0[.]193:22265` | ip:port | Unknown malware | ThreatFox | 2026-07-13 13:49:55 UTC |
| `tcp[.]niceports[.]shop` | domain | Unknown malware | ThreatFox | 2026-07-13 13:49:34 UTC |
| `yxxyqkkf[.]jadoou[.]one` | domain | ClearFake | ThreatFox | 2026-07-13 13:47:40 UTC |
| `178[.]62[.]228[.]25:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 13:44:44 UTC |
| `178[.]62[.]235[.]14:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 13:44:43 UTC |
| `188[.]166[.]1[.]226:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 13:44:42 UTC |
| `188[.]166[.]105[.]148:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 13:44:41 UTC |

### CVEs explotados activamente (CISA KEV, últimos 14 días)

| CVE | Producto | Añadido | Ransomware |
|---|---|---|---|
| CVE-2026-56291 | Balbooa Forms | 2026-07-10 | Unknown |
| CVE-2026-48939 | iCagenda iCagenda | 2026-07-10 | Unknown |
| CVE-2026-48908 | JoomShaper SP Page Builder | 2026-07-07 | Unknown |
| CVE-2026-55255 | Langflow Langflow | 2026-07-07 | Unknown |
| CVE-2026-56290 | Joomlack Page Builder | 2026-07-07 | Unknown |
| CVE-2026-48282 | Adobe ColdFusion | 2026-07-07 | Unknown |
| CVE-2026-45659 | Microsoft SharePoint Server | 2026-07-01 | Unknown |
| CVE-2026-48558 | SimpleHelp  SimpleHelp | 2026-06-29 | Unknown |
<!-- CTI:END -->
