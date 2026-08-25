from __future__ import annotations

from dataclasses import dataclass, field

from context_agent.connectors import (
    BaseConnector,
    ContextIntelligenceAgent as LegacyContextIntelligenceAgent,
    DiscoveryMCPConnector,
    LocalEvidenceConnector,
    VectorDBConnector,
)


@dataclass
class ProductionContextIntelligenceAgent(LegacyContextIntelligenceAgent):
    """Production-safe context defaults.

    Static/demo connectors remain importable for explicit simulation fixtures, but
    production context collection never enables them implicitly. Missing live data
    stays missing; it is not replaced with fabricated telemetry or topology.
    """

    connectors: list[BaseConnector] = field(
        default_factory=lambda: [
            DiscoveryMCPConnector(),
            LocalEvidenceConnector(),
            VectorDBConnector(),
        ]
    )
