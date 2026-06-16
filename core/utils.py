import sys
import os
import subprocess
from rich.progress import Progress, SpinnerColumn, TextColumn
from .colors import log_info, log_success, log_warning, log_danger

def check_dependencies():
    """Check and auto-install missing packages."""
    required_packages = [
        "scapy", "curl_cffi", "paramiko", "h2", "websockets", 
        "beautifulsoup4", "dnspython", "aiohttp", "rich", "requests"
    ]
    
    missing_packages = []
    
    # Fast check using importlib.metadata
    from importlib.metadata import distributions
    installed_packages = {dist.metadata['Name'].lower() for dist in distributions() if dist.metadata['Name']}
    
    for package in required_packages:
        # Normalize package names to match metadata style
        norm_name = package.replace("_", "-").lower()
        if norm_name not in installed_packages:
            missing_packages.append(package)

    if missing_packages:
        log_warning(f"Missing packages detected: {', '.join(missing_packages)}")
        log_info("Auto-installing missing dependencies via pip...")
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            progress.add_task(description="Installing packages...", total=None)
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_packages], 
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                log_success("All dependencies installed successfully.")
            except subprocess.CalledProcessError:
                log_danger("Failed to auto-install dependencies. Please check your internet or run: pip install -r requirements.txt")
                sys.exit(1)
    else:
        # Don't print anything if all good, keep it clean
        pass

def check_npcap():
    """Warn user if running Scapy raw sockets on Windows without Npcap."""
    if os.name == 'nt':
        npcap_path = r"C:\Windows\System32\Npcap"
        if not os.path.exists(npcap_path):
            log_warning("Npcap is NOT installed. Layer 4 DDoS methods (SYN, ACK) will FAIL.")
            log_info("Please install Npcap manually from: https://npcap.com/")
            return False
    return True

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')
