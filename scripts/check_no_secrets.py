"""Busca secretos en el árbol de trabajo Y en todo el historial de Git (criterio C8).
Uso:  python scripts/check_no_secrets.py     (ejecutar antes de cada push)"""
import re
import subprocess
import sys
from pathlib import Path

PATTERNS = [
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    r"(?i)(password|passwd|passphrase|secret|token|api[_-]?key)\s*=\s*['\"][^'\"\s]{6,}['\"]",
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.",  # JWT
]
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv", "venv"}
SELF = Path(__file__).name


def scan_text(label: str, text: str) -> list[str]:
    return [f"{label}: coincide {p}" for p in PATTERNS if re.search(p, text)]


def main() -> int:
    hits = []
    for f in Path(".").rglob("*"):
        if f.is_file() and not (set(f.parts) & SKIP_DIRS) and f.name != SELF and f.suffix not in {".enc", ".db"}:
            try:
                hits += scan_text(str(f), f.read_text(encoding="utf-8"))
            except (UnicodeDecodeError, OSError):
                pass
    if Path(".git").exists():
        log = subprocess.run(["git", "log", "-p", "--all"], capture_output=True, text=True).stdout
        hits += scan_text("historial de git", log)
    print("\n".join(hits) if hits else "Sin secretos detectados.")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
