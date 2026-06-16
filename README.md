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

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/hydra_storm.git
   cd hydra_storm
   ```

2. **Install dependencies:**
   The framework auto-detects and attempts to install missing packages on runtime. However, manual installation is recommended:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the tool:**
   ```bash
   python hydra.py
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
