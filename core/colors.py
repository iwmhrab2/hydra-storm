import sys
import os
from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.align import Align

custom_theme = Theme({
    "info": "cyan",
    "warning": "bold yellow",
    "danger": "bold red",
    "success": "bold green",
    "title": "bold magenta",
    "border": "blue",
    "menu.text": "white",
    "menu.number": "bold yellow"
})

console = Console(theme=custom_theme)

def print_banner():
    banner_text = """
    ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗     ███████╗████████╗██████╗ ██████╗ ███╗   ███╗
    ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗    ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗████╗ ████║
    ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║    ███████╗   ██║   ██║  ██║██████╔╝██╔████╔██║
    ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║    ╚════██║   ██║   ██║  ██║██╔══██╗██║╚██╔╝██║
    ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║    ███████║   ██║   ██████╔╝██║  ██║██║ ╚═╝ ██║
    ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝    ╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝
                                      v7.0 Chaos Toolkit
    """
    console.print(Align.center(Text(banner_text, style="bold red")))

def print_main_menu():
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(justify="right", style="menu.number")
    table.add_column(style="menu.text")
    
    table.add_row("[1]", "🌊 DDoS Attack (50+ vectors)")
    table.add_row("[2]", "🔍 Port Scanner (High-Speed)")
    table.add_row("[3]", "📂 Dir Bruteforce (20K+ words)")
    table.add_row("[4]", "🔑 Login Cracker (SSH/HTTP)")
    table.add_row("[5]", "💉 Vuln Scanner (SQLi/XSS)")
    table.add_row("[8]", "🛡️ WAF Detector")
    table.add_row("", "")
    table.add_row("[0]", "🚪 Exit")

    panel = Panel(
        Align.center(table),
        title="[title]MAIN MENU[/title]",
        border_style="border",
        expand=False,
        padding=(1, 4)
    )
    console.print(Align.center(panel))

def print_ddos_menu():
    table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 2))
    table.add_column("Layer 7 (HTTP/Bypass)", justify="left")
    table.add_column("Layer 4 (TCP/UDP)", justify="left")
    table.add_column("Amplification / Gaming", justify="left")
    
    # Adding rows to match the 50+ vectors (grouped)
    table.add_row("[1] HTTP-GET (Async)", "[8] TCP-SYN (Raw)", "[15] NTP-AMP")
    table.add_row("[2] HTTP-POST", "[9] TCP-ACK", "[16] DNS-AMP")
    table.add_row("[3] HTTP-HEAD", "[10] TCP-RST", "[17] MEMCACHED-AMP")
    table.add_row("[4] HTTP-NULL", "[11] TCP-FIN", "[18] SSDP-AMP")
    table.add_row("[5] HTTP-STRESS", "[12] TCP-XMAS", "[19] MINECRAFT-AUTH")
    table.add_row("[6] CFB-BYPASS", "[13] UDP-RAW", "[20] SOURCE-ENGINE")
    table.add_row("[7] SLOWLORIS", "[14] UDP-FRAGMENT", "[21] TEAMSPEAK3")
    table.add_row("", "", "[22] FIVEM")
    
    panel = Panel(
        Align.center(table),
        title="[title]GLOBAL ATTACK VECTORS[/title]",
        border_style="danger",
        expand=False,
        padding=(1, 2)
    )
    console.print(Align.center(panel))
    console.print(Align.center(Text("[0] Back to Main Menu", style="bold yellow")))

def log_info(msg):
    console.print(f"[info][*] {msg}[/info]")

def log_success(msg):
    console.print(f"[success][+] {msg}[/success]")

def log_warning(msg):
    console.print(f"[warning][!] {msg}[/warning]")

def log_danger(msg):
    console.print(f"[danger][-] {msg}[/danger]")
