import sys
import os
import time
import asyncio
from typing import Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.align import Align
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from core.colors import print_banner, log_info, log_success, log_warning, log_danger, custom_theme
from core.utils import check_dependencies, clear_screen
from core.registry import ModuleRegistry
from core.proxy import ProxyManager

console = Console(theme=custom_theme)
registry = ModuleRegistry()
registry.discover_modules()
proxy_manager = ProxyManager()

# Global dynamic stats tracker
requests_sent = 0

def update_rps(val: int):
    global requests_sent
    requests_sent += val

async def run_live_status(duration: int):
    """Shows active progress bar with real-time RPS calculations during stress tests."""
    global requests_sent
    requests_sent = 0
    start_time = time.time()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold red]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TextColumn("[bold cyan]RPS: {task.fields[rps]}"),
        TextColumn("[bold green]Total: {task.fields[total]}"),
        console=console,
        transient=True
    ) as progress:
        task = progress.add_task("Stressing Target...", total=duration, rps=0)
        
        while not progress.finished:
            await asyncio.sleep(0.5)
            elapsed = time.time() - start_time
            if elapsed >= duration:
                break
            
            # Estimate live RPS dynamically
            current_rps = int(requests_sent / elapsed) if elapsed > 0 else 0
            progress.update(
                task,
                completed=int(elapsed),
                rps=current_rps,
                total=requests_sent
            )

def render_category_menu(category: str, modules: dict) -> str:
    """Renders menu for selected category using rich panels and returns user choice."""
    clear_screen()
    print_banner()
    
    table = Table(show_header=True, header_style="bold magenta", box=None, padding=(0, 2))
    table.add_column("Index", justify="center", style="bold yellow")
    table.add_column("Module Name", justify="left")
    table.add_column("Description", justify="left")
    
    module_list = list(modules.items())
    for idx, (name, mod) in enumerate(module_list, 1):
        inst = mod()
        table.add_row(str(idx), inst.name, inst.description)
        
    panel = Panel(
        Align.center(table),
        title=f"[bold cyan]{category.upper()} MODULES[/bold cyan]",
        border_style="blue",
        expand=False,
        padding=(1, 4)
    )
    console.print(Align.center(panel))
    console.print(Align.center(Text("[0] Back to Main Menu", style="bold yellow")))
    
    choice = input("\n[root@hydra/select]~# ")
    if choice == '0' or not choice.isdigit() or int(choice) > len(module_list):
        return None
        
    selected_name = module_list[int(choice) - 1][0]
    return selected_name

def handle_module_run(module_name: str):
    """Sets up variables, handles target parameters and executes module."""
    mod_class = registry.get_module(module_name)
    if not mod_class:
        log_danger("Module not found in registry.")
        return
        
    module_instance = mod_class()
    clear_screen()
    print_banner()
    
    console.print(Panel(Align.center(f"[bold green]CONFIGURING MODULE: {module_instance.name}[/bold green]"), border_style="bold green"))
    target = input("\nEnter Target (IP/URL/Domain): ")
    if not target:
        return
        
    kwargs = {}
    if module_instance.category == "ddos":
        threads = input("Threads (Default 500): ") or "500"
        duration = input("Duration in Seconds (Default 60): ") or "60"
        kwargs["threads"] = int(threads)
        kwargs["time"] = int(duration)
        
        # Method selection if it's L7HTTP
        if module_name == "HTTP Flood":
            method = input("Method (GET/POST/HEAD) [GET]: ") or "GET"
            kwargs["method"] = method
            kwargs["rate_tracker"] = update_rps
            
        p_choice = input("Use Proxy Rotation? (y/n) [n]: ").lower()
        if p_choice == 'y':
            if not proxy_manager.proxies:
                log_warning("No proxies loaded. Scraping proxy lists now...")
                proxy_manager.scrape_proxies()
                proxy_manager.validate_proxies(max_workers=50)
            kwargs["proxies"] = proxy_manager.proxies
            
        # Asynchronous trigger with live RPS reporting
        loop = asyncio.get_event_loop()
        try:
            # Run stress test and status dashboard in parallel
            loop.run_until_complete(asyncio.gather(
                module_instance.run(target, **kwargs),
                run_live_status(int(duration))
            ))
        except KeyboardInterrupt:
            log_warning("Execution interrupted by user.")
    else:
        # Fallback runner for synchronous legacy modules
        try:
            asyncio.run(module_instance.run(target, **kwargs))
        except TypeError:
            # If the module has not been upgraded yet and doesn't accept async
            loop = asyncio.get_event_loop()
            if loop.is_running():
                log_danger("Loop is already running. Please run standalone.")
            else:
                loop.run_until_complete(module_instance.run(target, **kwargs))
        except KeyboardInterrupt:
            log_warning("Execution interrupted by user.")
            
    input("\nPress Enter to return...")

def main_menu_loop():
    while True:
        clear_screen()
        print_banner()
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column(justify="right", style="menu.number")
        table.add_column(style="menu.text")
        
        table.add_row("[1]", "🌊 DDoS Attack (L4/L7/Amp)")
        table.add_row("[2]", "🔍 Port Scanners")
        table.add_row("[3]", "📂 Dir Bruteforce & Web Scans")
        table.add_row("[4]", "🔑 Login Crackers (Brute)")
        table.add_row("", "")
        table.add_row("[0]", "🚪 Exit")
        
        panel = Panel(
            Align.center(table),
            title="[bold magenta]HYDRA STORM ORCHESTRATOR[/bold magenta]",
            border_style="blue",
            expand=False,
            padding=(1, 4)
        )
        console.print(Align.center(panel))
        
        choice = input("\n[root@hydra]~# ")
        if choice == '0':
            log_info("Shutting down. Stay safe.")
            sys.exit(0)
            
        category_map = {
            '1': 'ddos',
            '2': 'scanner',
            '3': 'web',
            '4': 'brute'
        }
        
        cat = category_map.get(choice)
        if cat:
            modules = registry.get_modules_by_category(cat)
            if not modules:
                log_warning(f"No modules registered under the '{cat}' category.")
                time.sleep(1.5)
                continue
                
            selected_mod = render_category_menu(cat, modules)
            if selected_mod:
                handle_module_run(selected_mod)
        else:
            log_warning("Invalid Selection.")
            time.sleep(1)

def main():
    clear_screen()
    check_dependencies()
    main_menu_loop()

if __name__ == "__main__":
    main()
