import os
import sys
import importlib
import pkgutil
from typing import Dict, Type
from core.base import BaseModule

class ModuleRegistry:
    """
    Registry that dynamically scans the modules directory and resolves all
    classes subclassing BaseModule at runtime.
    """
    def __init__(self, modules_dir: str = None):
        if modules_dir is None:
            # Locate modules/ directory relative to root
            self.modules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules")
        else:
            self.modules_dir = modules_dir
        self.modules: Dict[str, Type[BaseModule]] = {}

    def discover_modules(self) -> Dict[str, Type[BaseModule]]:
        """
        Dynamically traverse the modules directory, import python files,
        and register any classes subclassing BaseModule.
        """
        self.modules.clear()
        
        # Ensure root of project is in sys.path
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root_dir not in sys.path:
            sys.path.insert(0, root_dir)

        # Walk through modules package
        for root, _, files in os.walk(self.modules_dir):
            for file in files:
                if file.endswith(".py") and not file.startswith("__"):
                    # Calculate package name based on relative path
                    rel_path = os.path.relpath(os.path.join(root, file), root_dir)
                    mod_name = os.path.splitext(rel_path)[0].replace(os.sep, ".")
                    
                    try:
                        module = importlib.import_module(mod_name)
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            # Check if attribute is a subclass of BaseModule but not BaseModule itself
                            if (
                                isinstance(attr, type)
                                and issubclass(attr, BaseModule)
                                and attr is not BaseModule
                            ):
                                # Instantiate temporary to check attributes or just register class
                                inst = attr()
                                self.modules[inst.name] = attr
                    except Exception as e:
                        # Graceful warning to avoid crashing the main UI on import failures
                        from core.colors import log_warning
                        log_warning(f"Failed to dynamically import module {mod_name}: {e}")
                        
        return self.modules

    def get_module(self, name: str) -> Type[BaseModule] | None:
        """Retrieve a specific registered module class by name."""
        return self.modules.get(name)

    def get_modules_by_category(self, category: str) -> Dict[str, Type[BaseModule]]:
        """Retrieve all registered modules of a specific category."""
        return {name: mod for name, mod in self.modules.items() if mod().category == category}
