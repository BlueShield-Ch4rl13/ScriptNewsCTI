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
**Última actualización:** 2026-07-13 11:46 UTC · **IOCs recolectados:** 1014 · **CVEs KEV recientes:** 8

### Últimos IOCs (defangueados, máx. 25)

| IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|
| `genesis-cheats[.]com` | domain | Unknown malware | ThreatFox | 2026-07-13 11:42:26 UTC |
| `lqljywai[.]jadoou[.]christmas` | domain | ClearFake | ThreatFox | 2026-07-13 11:42:21 UTC |
| `ahdwvzwy[.]jadoou[.]christmas` | domain | ClearFake | ThreatFox | 2026-07-13 11:39:29 UTC |
| `mahyartunes[.]bio` | domain | ClearFake | ThreatFox | 2026-07-13 11:33:13 UTC |
| `zxx1gpmw[.]pars90[.]download` | domain | ClearFake | ThreatFox | 2026-07-13 11:16:56 UTC |
| `pars90[.]download` | domain | ClearFake | ThreatFox | 2026-07-13 11:14:45 UTC |
| `hxxps://jadeworkshop[.]top/router/handler-asset[.]js` | url | SmartApeSG | ThreatFox | 2026-07-13 11:07:19 UTC |
| `jadeworkshop[.]top` | domain | SmartApeSG | ThreatFox | 2026-07-13 11:07:18 UTC |
| `hxxps://jadeworkshop[.]top/router/verify-build` | url | SmartApeSG | ThreatFox | 2026-07-13 11:07:17 UTC |
| `154[.]88[.]99[.]59:8885` | ip:port | VShell | ThreatFox | 2026-07-13 11:05:07 UTC |
| `154[.]88[.]99[.]60:8885` | ip:port | VShell | ThreatFox | 2026-07-13 11:05:07 UTC |
| `154[.]88[.]99[.]58:8885` | ip:port | VShell | ThreatFox | 2026-07-13 11:05:06 UTC |
| `154[.]88[.]99[.]54:8885` | ip:port | VShell | ThreatFox | 2026-07-13 11:05:05 UTC |
| `ovcvaphj[.]jadoou[.]cfd` | domain | ClearFake | ThreatFox | 2026-07-13 10:48:49 UTC |
| `vnuhxmfp[.]jadoou[.]cfd` | domain | ClearFake | ThreatFox | 2026-07-13 10:44:20 UTC |
| `zxco[.]madgal[.]life` | domain | ClearFake | ThreatFox | 2026-07-13 10:37:14 UTC |
| `ukgf[.]madgal[.]life` | domain | ClearFake | ThreatFox | 2026-07-13 10:32:21 UTC |
| `64[.]225[.]73[.]161:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 10:22:32 UTC |
| `157[.]245[.]71[.]64:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 10:22:19 UTC |
| `178[.]128[.]249[.]233:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 10:22:08 UTC |
| `209[.]38[.]46[.]121:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 10:21:57 UTC |
| `142[.]93[.]231[.]53:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 10:21:45 UTC |
| `167[.]99[.]42[.]38:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 10:21:34 UTC |
| `188[.]166[.]105[.]148:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 10:21:22 UTC |
| `188[.]166[.]1[.]226:25001` | ip:port | Kimwolf | ThreatFox | 2026-07-13 10:21:09 UTC |

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
