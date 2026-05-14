"""Enrichment provider registry — discovers and queries enrichment sources."""

from __future__ import annotations

import logging
from pathlib import Path

from arbiter.enrichment.base import EnrichmentProvider

logger = logging.getLogger(__name__)


def get_providers(workspace: Path) -> list[EnrichmentProvider]:
    """Instantiate all known enrichment providers.

    Arbiter ships with no built-in providers. Third-party providers
    can be registered via Python entry points or by implementing
    the EnrichmentProvider ABC.
    """
    providers: list[EnrichmentProvider] = []

    # Future: discover providers via entry_points
    # for ep in importlib.metadata.entry_points(group="arbiter.enrichment"):
    #     try:
    #         cls = ep.load()
    #         providers.append(cls(workspace))
    #     except Exception as e:
    #         logger.warning("Failed to load enrichment provider %s: %s", ep.name, e)

    return providers


def get_enrichment_hints(service: str, providers: list[EnrichmentProvider]) -> list[dict]:
    """Collect lightweight hints from all available providers."""
    hints: list[dict] = []
    for provider in providers:
        try:
            if provider.is_available():
                hint = provider.get_hint(service)
                if hint:
                    hints.append(hint)
        except Exception as e:
            logger.warning("Hint failed for provider %s: %s", provider.name, e)
    return hints


def collect_enrichment(
    service: str,
    providers: list[EnrichmentProvider],
    sections: list[str] | None = None,
    provider_name: str | None = None,
    max_section_chars: int | None = None,
) -> list[dict]:
    """Query providers for enrichment data. Returns list of provider results."""
    results: list[dict] = []
    for provider in providers:
        if provider_name and provider.name != provider_name:
            continue
        try:
            data = provider.get_service_enrichment_data(
                service, sections, max_section_chars=max_section_chars
            )
            if data:
                results.append(data)
        except Exception as e:
            logger.warning("Enrichment failed for provider %s: %s", provider.name, e)
    return results
