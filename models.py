# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Data models for the Soc Pomdp Environment.

The SOC_POMDP environment is a simple test environment that echoes back messages.
"""

import json
from typing import List, Dict, Optional, Literal
from pydantic import Field, BaseModel
from openenv.core.env_server.types import Action, Observation

class Alert(BaseModel):
    """A single Sigma rule alert triggered on a node."""
    alert_id: str
    node_id: str
    sigma_rule: str
    severity: str
    timestamp: str

class SocAction(Action):
    """The tools available to the SOC Agent."""
    action_type: Literal["query_log", "isolate_node"] = Field(
        ..., description="The type of action to take."
    )
    target_node: Optional[str] = Field(
        default=None, description="The network node to investigate or isolate."
    )
    reasoning: str = Field(
        default="", description="Your zero-shot logical reasoning for this action."
    )

class SocObservation(Observation):
    """The SIEM Dashboard the LLM sees after every tick."""
    active_alerts: List[Alert] = Field(
        default_factory=list, description="Current alerts firing across the network."
    )
    logs_returned: str = Field(
        default="", description="Raw forensic JSON logs returned from a query_log action."
    )
    isolated_nodes: List[str] = Field(
        default_factory=list, description="Nodes currently cut off from the network."
    )
    budget_remaining: int = Field(
        default=0, description="Investigation budget remaining."
    )
    current_tick: int = Field(
        default=0, description="Current time step (1 tick = 5 minutes of real time)."
    )
    system_messages: str = Field(
        default="", description="Feedback from the environment."
    )