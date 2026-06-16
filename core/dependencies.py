"""
core.dependencies — Auto dependency checker & installer for Hydra Storm v7.0
"""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Tuple

from core.colors import C, error, info, success, warn


_IMPORT_MAP: Dict[str, str] = {
    "scapy": "scapy",
    "curl_cffi": "curl_cffi",
    "paramiko": "paramiko",
    "h2": "h2",
    "websockets": "websockets",
    "beautifulsoup4": "bs4",
    "dnspython": "dns",
    "rich": "rich",
    "aiohttp": "aiohttp",
}

_OPTIONAL: set[str] = {"curl_cffi", "paramiko", "h2", "websockets"}


def _find_requirements() -> Path:
    """Locate requirements.txt relative to this file's package root."""
    here = Path(__file__).resolve().parent.parent
    return here / "requirements.txt"


def _parse_requirements(path: Path) -> List[Tuple[str, str]]:
    """Return list of (package_name, version_spec) from requirements.txt."""
    pairs: List[Tuple[str, str]] = []
    if not path.is_file():
        return pairs
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            for sep in (">=", "<=", "==", "!=", ">", "<"):
                if sep in line:
                    name, ver = line.split(sep, 1)
                    pairs.append((name.strip(), f"{sep}{ver.strip()}"))
                    break
            else:
                pairs.append((line, ""))
    return pairs


def _is_installed(package: str) -> bool:
    """Check if *package* is importable."""
    import_name = _IMPORT_MAP.get(package, package)
    try:
        importlib.import_module(import_name)
        return True
    except ImportError:
        return False


def _pip_install(packages: List[str]) -> bool:
    """Run pip install for a list of packages. Returns True on success."""
    cmd = [sys.executable, "-m", "pip", "install", "--quiet", *packages]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def check_and_install() -> Dict[str, bool]:
    """Check all dependencies and offer to install missing ones.

    Returns:
        Dict mapping package_name → availability (bool).
    """
    req_path = _find_requirements()
    packages = _parse_requirements(req_path)

    if not packages:
        warn("No requirements.txt found or it is empty.")
        return {}

    status: Dict[str, bool] = {}
    missing: List[str] = []
    missing_specs: List[str] = []

    for name, spec in packages:
        installed = _is_installed(name)
        status[name] = installed
        if installed:
            tag = f"{C.D}(optional){C.X}" if name in _OPTIONAL else ""
            success(f"{name}{spec} {tag}")
        else:
            optional_tag = " (optional)" if name in _OPTIONAL else ""
            error(f"{name}{spec} — NOT FOUND{optional_tag}")
            missing.append(name)
            missing_specs.append(f"{name}{spec}")

    if not missing:
        success("All dependencies satisfied.")
        return status

    required_missing = [m for m in missing if m not in _OPTIONAL]
    optional_missing = [m for m in missing if m in _OPTIONAL]

    if required_missing:
        info(f"Missing required: {', '.join(required_missing)}")
    if optional_missing:
        info(f"Missing optional: {', '.join(optional_missing)}")

    try:
        answer = input(
            f"\n  {C.CY}▸{C.X} Install missing packages? {C.D}[Y/n]{C.X}: {C.W}"
        ).strip().lower()
        print(C.X, end="")
    except (EOFError, KeyboardInterrupt):
        print()
        return status

    if answer in ("", "y", "yes"):
        info(f"Installing: {', '.join(missing_specs)}")
        if _pip_install(missing_specs):
            success("Installation complete.")
            for name in missing:
                status[name] = _is_installed(name)
        else:
            error("pip install failed. Try manually:")
            error(f"  {sys.executable} -m pip install {' '.join(missing_specs)}")
    else:
        warn("Skipping installation.")

    return status
