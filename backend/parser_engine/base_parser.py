from abc import ABC, abstractmethod
from typing import Optional, Dict, Any

class BaseParser(ABC):
    SOURCE_ID: str = "unknown"
    VERSION: str = "1.0.0"
    PRIORITY: int = 50  # Lower = tried first (10-30 = specific vendors, 100 = fallback)

    @abstractmethod
    def can_parse(self, raw: str, metadata: dict) -> float:
        """Return confidence score 0.0-1.0"""
        pass

    @abstractmethod  
    def parse(self, raw: str, metadata: dict) -> dict:
        """Return dict of extracted fields"""
        pass

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "name": self.__class__.__name__,
            "source_id": self.SOURCE_ID,
            "version": getattr(self, "VERSION", "1.0.0"),
            "priority": self.PRIORITY,
            "description": self.__doc__ or f"Parser for {self.SOURCE_ID} events"
        }
