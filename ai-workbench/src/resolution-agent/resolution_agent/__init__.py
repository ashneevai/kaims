from __future__ import annotations

from common.models import Recommendation

from resolution_agent.capability_contract import CapabilityContractGate
from resolution_agent.graph import ResolutionIntelligenceAgent as LegacyResolutionIntelligenceAgent
from resolution_agent.structured_plan_bridge import StructuredPlanBridge


class ResolutionIntelligenceAgent(LegacyResolutionIntelligenceAgent):
    """Default resolution agent with Wave 2/3 governed planning enforcement."""

    def __init__(
        self,
        *args,
        capability_contract_gate: CapabilityContractGate | None = None,
        structured_plan_bridge: StructuredPlanBridge | None = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.capability_contract_gate = capability_contract_gate or CapabilityContractGate()
        self.structured_plan_bridge = structured_plan_bridge or StructuredPlanBridge(
            self.capability_contract_gate.registry
        )

    async def resolve(self, context) -> Recommendation:
        recommendation = await super().resolve(context)
        recommendation = self.capability_contract_gate.apply(recommendation)
        return self.structured_plan_bridge.apply(context=context, recommendation=recommendation)


__all__ = ["ResolutionIntelligenceAgent"]
