"""Firefox path defaults from env / .env — no machine-specific hardcodes."""
from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    path = ROOT / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, val)


_load_dotenv()


def default_firefox_src() -> str:
    return os.environ.get("FIREFOX_SRC") or str(Path.home() / "firefox")


def default_firefox_bin() -> Path | None:
    raw = os.environ.get("FIREFOX_BIN")
    if raw:
        return Path(raw).expanduser()
    src = Path(default_firefox_src()).expanduser()
    if not src.is_dir():
        return None
    for d in sorted(src.glob("obj-*")):
        for name in ("firefox", "firefox.exe"):
            cand = d / "dist" / "bin" / name
            if cand.is_file():
                return cand
    return None


def require_firefox_bin() -> Path:
    path = default_firefox_bin()
    if path is None:
        raise SystemExit(
            "Firefox binary not found. Set FIREFOX_BIN, pass --firefox, "
            "or put a build under $FIREFOX_SRC/obj-*/dist/bin/firefox"
        )
    return path
