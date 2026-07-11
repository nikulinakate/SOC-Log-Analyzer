from abc import ABC, abstractmethod

from app.schemas import NormalizedEvent


class LogParseError(ValueError):
    """Raised when an input cannot be parsed as the selected source type."""


class BaseParser(ABC):
    @abstractmethod
    def parse_text(self, content: str) -> list[NormalizedEvent]:
        raise NotImplementedError

    def parse_bytes(self, content: bytes) -> list[NormalizedEvent]:
        return self.parse_text(content.decode("utf-8", errors="replace"))
