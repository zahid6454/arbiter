"""Base class for enrichment providers."""

from __future__ import annotations

from abc import ABC, abstractmethod


class EnrichmentProvider(ABC):
    """Abstract base for enrichment data providers.

    Providers supply architecture context, bug category maps, and other
    knowledge that helps AI agents reason about *why* errors happen.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider identifier (e.g. 'wiki', 'runbook-agent')."""

    def is_available(self) -> bool:
        """Whether the provider can serve data right now (cheap check)."""
        return True

    @abstractmethod
    def available_sections(self, service: str) -> list[str] | None:
        """Return section names this provider has for a service, or None if unknown."""

    @abstractmethod
    def get_service_enrichment_data(
        self,
        service: str,
        sections: list[str] | None = None,
        max_section_chars: int | None = None,
    ) -> dict | None:
        """Fetch enrichment data for a service.

        Args:
            service: Service name
            sections: Specific sections to fetch (None = all)
            max_section_chars: If set, truncate sections at this char limit

        Returns a dict with keys: source, service, sections, metadata.
        Returns None if no data is available.
        """

    def get_platform_context(self, topic: str) -> str | None:
        """Cross-service knowledge (failure modes, communication patterns, etc.)."""
        return None

    def get_hint(self, service: str) -> dict | None:
        """Lightweight hint for gather — tells the agent what's available without fetching full data."""
        if not self.is_available():
            return None
        sections = self.available_sections(service)
        if sections is None:
            return None
        return {
            "provider": self.name,
            "available": True,
            "available_sections": sections,
            "hint": f"Call get_service_enrichment_data('{service}') for full architecture context",
        }
