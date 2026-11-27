"""Ejecuta todos los ataques y guarda la evidencia en attacks/evidence/ (anexo E5)."""
import subprocess
import sys
from datetime import datetime
from pathlib import Path

here = Path(__file__).parent
out = here / "evidence"
out.mkdir(exist_ok=True)
failed = 0
for script in sorted(here.glob("attack_0[1-9]_*.py")):
    r = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, cwd=here.parent,
                       env={**__import__("os").environ, "PYTHONPATH": str(here.parent / "attacks")})
    log = f"{datetime.now().isoformat(timespec='seconds')}\n{r.stdout}{r.stderr}\nexit={r.returncode}\n"
    (out / f"{script.stem}.log").write_text(log, encoding="utf-8")
    print(r.stdout.rstrip()); failed += r.returncode != 0
print(f"\nResultado: {'TODAS las defensas funcionaron' if not failed else f'{failed} ataque(s) tuvieron éxito'}")
raise SystemExit(failed)
