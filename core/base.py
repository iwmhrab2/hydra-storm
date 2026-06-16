import abc
import random
from typing import Dict, Any

class BaseModule(abc.ABC):
    """
    Abstract Base Class for all Hydra Storm modules.
    All modules must inherit from this and implement the run method.
    """
    def __init__(self):
        pass

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name of the module."""
        pass

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """Brief description of the module's functionality."""
        pass

    @property
    @abc.abstractmethod
    def category(self) -> str:
        """Category of the module (scanner, web, brute, ddos)."""
        pass

    @property
    @abc.abstractmethod
    def author(self) -> str:
        """Author of the module."""
        pass

    @abc.abstractmethod
    async def run(self, target: str, **kwargs: Any) -> None:
        """
        Execute the module asynchronously.
        :param target: Target IP, domain, or URL.
        :param kwargs: Additional modular configurations.
        """
        pass

    def log(self, message: str, level: str = "info") -> None:
        """Integrated logger helper."""
        from core.colors import log_info, log_success, log_warning, log_danger
        if level == "success":
            log_success(f"[{self.name}] {message}")
        elif level == "warning":
            log_warning(f"[{self.name}] {message}")
        elif level == "danger":
            log_danger(f"[{self.name}] {message}")
        else:
            log_info(f"[{self.name}] {message}")

    def get_rotated_proxy(self, proxies: list) -> Dict[str, str] | None:
        """Dynamic proxy rotation helper."""
        if not proxies:
            return None
        proxy = random.choice(proxies)
        return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
