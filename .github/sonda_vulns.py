"""Sonda temporal: ejecuta vulnerabilidades.construir() con datos reales y saca el
JSON comprimido en anotaciones (desde aquí no hay otra forma de recuperarlo)."""
import base64, gzip, json, logging, sys, time
sys.path.insert(0, ".")
logging.basicConfig(level=logging.INFO)
import vulnerabilidades as v
t = time.time()
out = v.construir(dias=7)
seg = round(time.time() - t)
blob = base64.b64encode(gzip.compress(json.dumps(out, ensure_ascii=False).encode())).decode()
print(f"::notice title=resumen::{json.dumps({'seg': seg, 'fuentes': out['fuentes'], 'resumen': out['resumen'], 'bytes_gz_b64': len(blob)})}")
for i in range(0, len(blob), 60000):
    print(f"::notice title=trozo {i // 60000:02d}::{blob[i:i + 60000]}")
