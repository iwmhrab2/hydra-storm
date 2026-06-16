# 🌊 Hydra Storm - Chaos Engineering & Network Stress-Testing Framework

Hydra Storm is an elite-grade, modular, and high-performance network security testing and traffic-simulation framework. Built using Python 3.11+, it utilizes asynchronous concurrent models, custom packet crafting, and a dynamic plugin architecture designed for systems architects and security researchers.

---

## ⚡ Key Features

- **🚀 Dynamic Plugin Architecture**: Modules are discovered and resolved at runtime via a centralized registration system (`BaseModule` & `ModuleRegistry`). No hardcoded imports.
- **🧵 High-Performance Concurrency**:
  - **Layer 7**: Built-in asynchronous engine (`aiohttp`) utilizing custom connection pooling, disabled SSL verification overhead, and Unix-optimized `uvloop` integration to bypass default Python loop limitations.
  - **Layer 4 / Amplification**: Raw socket generation, multi-threaded packet crafting, and reflection capabilities.
- **🛡️ Advanced Bypass & Proxy Rotation**:
  - TLS Handshake & JA3/JA4 fingerprint emulation utilizing `curl_cffi` to mimic standard browsers (Chrome, Firefox).
  - Dynamic, multi-threaded proxy scraper and validator with live rotators to mitigate rate-limiting.
- **🎨 Modern Terminal UI**: Real-time traffic metrics tracking, live RPS (Requests Per Second) dashboards, and category routing powered by the `rich` library.

---

## 📂 Project Architecture

```text
hydra_storm/
├── hydra.py                 # Elegant Terminal Orchestrator (CLI Entrypoint)
├── core/
│   ├── base.py              # Abstract Base Module (ABC) Interface
│   ├── registry.py          # Dynamic Runtime Module Loader
│   ├── engine_l7.py         # Asynchronous High-Throughput HTTP Engine
│   ├── proxy.py             # Multi-threaded Proxy Scraper & Validator
│   └── cf_bypass.py         # WAF & Cloudflare Anti-fingerprinting Layer
└── modules/
    ├── ddos/                # Stress-Testing Engines (L4 / L7 / Amplification)
    ├── scanner/             # Network Port & Service Fingerprinting
    ├── web/                 # Web Directory Bruteforcers & Scanners
    └── brute/               # Authentication Protocol Testing
```

---

## 🛠️ Quick Start

### One-Command Setup & Run (Recommended)

Run the appropriate one-liner for your operating system to automatically clone, install dependencies, and launch the tool.

#### 🪟 Windows (PowerShell - Auto-installs Python if missing)
```powershell
if (!(Get-Command python -ErrorAction SilentlyContinue)) { Write-Host "Python not found. Installing Python 3.12..."; winget install Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements; $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User") }; git clone https://github.com/iwmhrab2/hydra-storm.git; cd hydra-storm; python -m venv venv; .\venv\Scripts\python.exe -m pip install -r requirements.txt; .\venv\Scripts\python.exe hydra.py
```

#### 🍎 macOS (Auto-installs Python via Homebrew if missing)
```bash
command -v python3 >/dev/null 2>&1 || { echo "Python3 not found. Installing via Homebrew..."; brew install python; }; git clone https://github.com/iwmhrab2/hydra-storm.git && cd hydra-storm && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && python3 hydra.py
```

#### 🐧 Linux (Debian/Ubuntu - Auto-installs Python if missing)
```bash
command -v python3 >/dev/null 2>&1 || { echo "Python3 not found. Installing..."; sudo apt update && sudo apt install -y python3 python3-pip python3-venv; }; git clone https://github.com/iwmhrab2/hydra-storm.git && cd hydra-storm && python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt && python3 hydra.py
```

---

## 🧩 Developing Custom Modules

Hydra Storm is completely plug-and-play. To build a custom module, create a new class inside the `modules/` directory that inherits from `BaseModule`:

```python
from typing import Any
from core.base import BaseModule

class CustomStressModule(BaseModule):
    @property
    def name(self) -> str:
        return "My Custom Attack"

    @property
    def description(self) -> str:
        return "Custom packet testing module"

    @property
    def category(self) -> str:
        return "ddos" # options: scanner, web, brute, ddos

    @property
    def author(self) -> str:
        return "Developer"

    async def run(self, target: str, **kwargs: Any) -> None:
        self.log(f"Stressing target: {target}...", level="info")
        # Custom execution logic goes here
```

The tool will automatically register and expose your module under the respective category menu on the next startup.

---

## ⚠️ Disclaimer

This tool is developed for **educational, authorized security auditing, and stress-testing/chaos-engineering purposes only**. The authors accept no responsibility for unauthorized or malicious usage of this framework. Always ensure you have written consent before testing external infrastructures.
