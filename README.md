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
**Última actualización:** 2026-07-14 07:13 UTC · **IOCs recolectados:** 628 · **CVEs KEV recientes:** 8

### Últimos IOCs (defangueados, máx. 25)

| Score | Gravedad | IOC | Tipo | Amenaza | Fuente | Visto |
|---|---|---|---|---|---|---|
| — (—) | — | `45[.]88[.]186[.]125:443` | ip:port | Unknown RAT | ThreatFox | 2026-07-14 07:06:13 UTC |
| — (—) | — | `47[.]251[.]241[.]59:443` | ip:port | Havoc | ThreatFox | 2026-07-14 07:05:06 UTC |
| — (—) | — | `158[.]94[.]211[.]63:8080` | ip:port | AdaptixC2 | ThreatFox | 2026-07-14 07:05:05 UTC |
| — (—) | — | `45[.]13[.]238[.]92:443` | ip:port | Unknown RAT | ThreatFox | 2026-07-14 07:04:53 UTC |
| — (—) | — | `178[.]128[.]208[.]65:9035` | ip:port | Aisuru | ThreatFox | 2026-07-14 07:01:43 UTC |
| — (—) | — | `213[.]152[.]162[.]21:11525` | ip:port | Remcos | ThreatFox | 2026-07-14 07:01:04 UTC |
| — (—) | — | `39[.]105[.]94[.]168:80` | ip:port | Cobalt Strike | ThreatFox | 2026-07-14 06:57:56 UTC |
| — (—) | — | `17eqwy30[.]takhtenard[.]app` | domain | ClearFake | ThreatFox | 2026-07-14 06:55:12 UTC |
| — (—) | — | `takhtenard[.]app` | domain | ClearFake | ThreatFox | 2026-07-14 06:54:36 UTC |
| — (—) | — | `206[.]189[.]146[.]157:34567` | ip:port | Aisuru | ThreatFox | 2026-07-14 06:38:48 UTC |
| — (—) | — | `cwkw[.]site-shartbandi-bedun-filter[.]com` | domain | ClearFake | ThreatFox | 2026-07-14 06:24:56 UTC |
| — (—) | — | `dddododiiik[.]com` | domain | Unknown Loader | ThreatFox | 2026-07-14 06:22:42 UTC |
| — (—) | — | `extranet-partners-report[.]com` | domain | Unknown Loader | ThreatFox | 2026-07-14 06:22:42 UTC |
| — (—) | — | `imagesafedown[.]info` | domain | Unknown Loader | ThreatFox | 2026-07-14 06:22:42 UTC |
| — (—) | — | `mentopo[.]info` | domain | Unknown Loader | ThreatFox | 2026-07-14 06:22:42 UTC |
| — (—) | — | `ghyrtamr[.]plinko-1xbet[.]games` | domain | ClearFake | ThreatFox | 2026-07-14 06:19:57 UTC |
| — (—) | — | `bfpi[.]site-shartbandi-bedun-filter[.]com` | domain | ClearFake | ThreatFox | 2026-07-14 06:19:52 UTC |
| — (—) | — | `tdzfnvda[.]plinko-1xbet[.]games` | domain | ClearFake | ThreatFox | 2026-07-14 06:15:02 UTC |
| — (—) | — | `yliw[.]site-asli-bedon-filter-1xbet[.]com` | domain | ClearFake | ThreatFox | 2026-07-14 06:14:45 UTC |
| — (—) | — | `94[.]154[.]32[.]144:1912` | ip:port | RedLine Stealer | ThreatFox | 2026-07-14 06:10:07 UTC |
| — (—) | — | `13[.]53[.]169[.]83:8808` | ip:port | AsyncRAT | ThreatFox | 2026-07-14 06:05:05 UTC |
| — (—) | — | `154[.]88[.]97[.]49:8885` | ip:port | VShell | ThreatFox | 2026-07-14 06:05:04 UTC |
| — (—) | — | `ucpwcpfl[.]jadoou[.]lat` | domain | ClearFake | ThreatFox | 2026-07-14 05:54:22 UTC |
| — (—) | — | `eonjaoyi[.]jadoou[.]lat` | domain | ClearFake | ThreatFox | 2026-07-14 05:53:44 UTC |
| — (—) | — | `edge[.]kernelmonitor[.]cc` | domain | ACR Stealer | ThreatFox | 2026-07-14 05:33:38 UTC |

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
<!-- CTI:END -->
