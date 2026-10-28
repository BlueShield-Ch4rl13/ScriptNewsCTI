"""Sonda temporal: el pipeline de vulnerabilidades y avisos con datos reales, como
main.py. Deja el JSON pedido (vulns o avisos) comprimido en /tmp/sonda.b64."""
import base64, gzip, json, logging, sys, time
from datetime import datetime, timedelta, timezone
sys.path.insert(0, ".")
logging.basicConfig(level=logging.INFO)
import requests
import avisos as A
import vulnerabilidades as v

t = time.time()
kev = v.kev_catalogo()
vul = v.construir(dias=7, kev_cat=kev)
avs = A.construir(dias=7, kev_cat=kev, vulns=vul, previos=[], epss_fn=v.epss)
A.anotar(vul, avs)
obj = vul if sys.argv[1] == "vulns" else avs
extra = {}
if sys.argv[1] == "avisos":
    desde = (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%d")
    for nombre, url in {"search": f"https://euvdservices.enisa.europa.eu/api/search?exploited=true&fromDate={desde}&size=100",
                        "search_sin_fecha": "https://euvdservices.enisa.europa.eu/api/search?exploited=true&size=100"}.items():
        try:
            r = requests.get(url, headers={"User-Agent": A.UA["User-Agent"], "Accept": "application/json"}, timeout=60)
            j = r.json()
            items = j.get("items") if isinstance(j, dict) else j
            extra[nombre] = {"http": r.status_code, "total": j.get("total") if isinstance(j, dict) else None,
                             "n": len(items or []), "claves": list(j)[:6] if isinstance(j, dict) else None,
                             "explotada_desde": sorted({(i or {}).get("exploitedSince", "")[:12] for i in items or []})[-5:]}
        except Exception as e:
            extra[nombre] = {"error": repr(e)[:200]}
    obj = {**obj, "_euvd": extra}
blob = base64.b64encode(gzip.compress(json.dumps(obj, ensure_ascii=False).encode(), 9)).decode()
open("/tmp/sonda.b64", "w").write(blob)
print("::notice title=resumen::" + json.dumps({"seg": round(time.time() - t), "trozos": -(-len(blob) // 4000),
      "fuentes_vulns": vul["fuentes"], "resumen_avisos": avs["resumen"], "euvd": extra}, ensure_ascii=False)[:3900])
