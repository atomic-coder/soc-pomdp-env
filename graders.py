"""
SOC Copilot — Objective Graders
"""
from typing import List

def easy_grader(trajectory: dict = None) -> float:
    trajectory = trajectory or {}
    rewards: List[float] = trajectory.get("rewards", [])
    if not rewards:
        return 0.5
    
    total_reward = sum(rewards)
    
    # Range is roughly -1.5 to +0.5
    normalized = (total_reward + 1.0) / 1.5
    return round(min(max(normalized, 0.01), 0.99), 4)

def medium_grader(trajectory: dict = None) -> float:
    trajectory = trajectory or {}
    rewards: List[float] = trajectory.get("rewards", [])
    if not rewards:
        return 0.5
        
    total_reward = sum(rewards)
    normalized = (total_reward + 1.0) / 1.5
    return round(min(max(normalized, 0.01), 0.99), 4)

def hard_grader(trajectory: dict = None) -> float:
    trajectory = trajectory or {}
    rewards: List[float] = trajectory.get("rewards", [])
    if not rewards:
        return 0.5
        
    total_reward = sum(rewards)
    normalized = (total_reward + 1.0) / 1.5
    return round(min(max(normalized, 0.01), 0.99), 4)