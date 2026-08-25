from __future__ import annotations

from common.models import Recommendation

from resolution_agent.capability_contract import CapabilityContractGate
from resolution_agent.graph import ResolutionIntelligenceAgent as LegacyResolutionIntelligenceAgent


class ResolutionIntelligenceAgent(LegacyResolutionIntelligenceAgent):
    """Default resolution agent with Wave 3 capability-contract enforcement."""

    def __init__(self, *args, capability_contract_gate: CapabilityContractGate | None = None, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.capability_contract_gate = capability_contract_gate or CapabilityContractGate()

    async def resolve(self, context) -> Recommendation:
        recommendation = await super().resolve(context)
        return self.capability_contract_gate.apply(recommendation)


__all__ = ["ResolutionIntelligenceAgent"]
