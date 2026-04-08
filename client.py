# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""Soc Pomdp Environment Client."""

from typing import Dict
from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from models import SocAction, SocObservation

class SocState(State):
    attacker_node: str = ""
    initial_budget: int = 0

class SocEnvClient(EnvClient[SocAction, SocObservation, SocState]):
    def _step_payload(self, action: SocAction) -> Dict:
        payload = {"action_type": action.action_type, "reasoning": action.reasoning}
        if action.target_node is not None:
            payload["target_node"] = action.target_node
        return payload

    def _parse_result(self, payload: Dict) -> StepResult[SocObservation]:
        obs_data = payload.get("observation", {})
        observation = SocObservation(
            done=payload.get("done", False),
            reward=payload.get("reward", 0.0),
            active_alerts=obs_data.get("active_alerts", []),
            logs_returned=obs_data.get("logs_returned", ""),
            isolated_nodes=obs_data.get("isolated_nodes", []),
            budget_remaining=obs_data.get("budget_remaining", 0),
            current_tick=obs_data.get("current_tick", 0),
            system_messages=obs_data.get("system_messages", "")
        )
        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> SocState:
        return SocState(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
            attacker_node=payload.get("attacker_node", ""),
            initial_budget=payload.get("initial_budget", 0),
        )