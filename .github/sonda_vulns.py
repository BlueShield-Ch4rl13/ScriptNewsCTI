"""Sonda temporal: ejecuta vulnerabilidades.construir() con datos reales y deja el
JSON comprimido en /tmp/vulns.b64 para sacarlo en anotaciones de 4000 caracteres."""
import base64, gzip, json, logging, sys, time
sys.path.insert(0, ".")
logging.basicConfig(level=logging.INFO)
import vulnerabilidades as v
t = time.time()
out = v.construir(dias=7)
blob = base64.b64encode(gzip.compress(json.dumps(out, ensure_ascii=False).encode(), 9)).decode()
open("/tmp/vulns.b64", "w").write(blob)
print(f"::notice title=resumen::{json.dumps({'seg': round(time.time() - t), 'fuentes': out['fuentes'], 'trozos': -(-len(blob) // 4000)})}")
