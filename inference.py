"""
SOC Copilot — Inference Script

Required environment variables:
    API_BASE_URL  -- OpenAI-compatible API base URL
    MODEL_NAME    -- Model identifier
    HF_TOKEN      -- Hugging Face / API key

Optional environment variables:
    ENV_URL       -- Environment server URL (defaults to deployed HF Space)
    TASK_NAME     -- Injected by Phase 2 validator to target a specific task

STDOUT FORMAT:
    [START] task=<task_name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...,rn>
"""

import argparse
import asyncio
import json
import os
import sys
import textwrap
from typing import List, Optional

from openai import OpenAI
from client import SocEnvClient
from models import SocAction
from graders import easy_grader, medium_grader, hard_grader

ENV_URL      = os.environ.get("ENV_URL", "https://atomic-coder-soc-pomdp-env.hf.space")
API_KEY      = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
API_BASE_URL = os.environ.get("API_BASE_URL", "https://router.huggingface.co/v1")
MODEL_NAME   = os.environ.get("MODEL_NAME", "Qwen/Qwen2.5-72B-Instruct")
BENCHMARK    = "soc-pomdp-env"

MAX_STEPS             = 25
TEMPERATURE           = 0.2
MAX_TOKENS            = 512
SUCCESS_SCORE_THRESHOLD = 0.5

TASKS   = ["easy", "medium", "hard"]
GRADERS = {"easy": easy_grader, "medium": medium_grader, "hard": hard_grader}

SYSTEM_PROMPT = textwrap.dedent("""
    You are an Autonomous SOC Analyst Copilot.
    Your mission: Locate and isolate the attacker before Data Exfiltration.

    Actions:
    1. query_log: Inspect a node. Returns forensic logs to verify True Positives vs False Positives.
    2. isolate_node: Cuts a node from the network.

    Respond ONLY with valid JSON:
    {
      "reasoning": "...",
      "action_type": "query_log",
      "target_node": "wks-user-01"
    }
""").strip()


# ── Mandatory logging helpers ─────────────────────────────────────────────────

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)

def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val  = str(done).lower()
    print(f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}", flush=True)

def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(f"[END] success={str(success).lower()} steps={steps} score={score:.3f} rewards={rewards_str}", flush=True)


# ── Prompt builder ────────────────────────────────────────────────────────────

def build_user_prompt(obs: dict, history: List[str]) -> str:
    history_block = "\n".join(history[-4:]) if history else "None"
    return textwrap.dedent(f"""
        Tick: {obs.get('current_tick', 0)} | Budget: {obs.get('budget_remaining', 0)}
        System Msg: {obs.get('system_messages', '')}
        Alerts: {json.dumps(obs.get('active_alerts', []), indent=2)}
        Logs: {obs.get('logs_returned', '')}
        History:
        {history_block}
        Next Action (JSON):
    """).strip()


# ── LLM call ──────────────────────────────────────────────────────────────────

def call_llm(client: OpenAI, messages: list, fallback_node: Optional[str] = None) -> dict:
    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME, messages=messages,
            temperature=TEMPERATURE, max_tokens=MAX_TOKENS
        )
        text = (completion.choices[0].message.content or "").strip()
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]
        raw = json.loads(text.strip())
    except Exception as exc:
        print(f"[DEBUG] LLM Error: {exc}", file=sys.stderr, flush=True)
        return {
            "action_type": "query_log",
            "target_node": fallback_node,
            "reasoning": "LLM error — defaulting to query_log."
        }

    if not raw.get("target_node") and fallback_node:
        raw["target_node"] = fallback_node
        print(f"[DEBUG] target_node missing, using fallback: {fallback_node}", file=sys.stderr, flush=True)

    if raw.get("action_type") not in ("query_log", "isolate_node"):
        print(f"[DEBUG] Invalid action_type '{raw.get('action_type')}', defaulting to query_log.", file=sys.stderr, flush=True)
        raw["action_type"] = "query_log"

    return raw


# ── Episode runner ────────────────────────────────────────────────────────────

async def run_episode(task: str, llm_client: OpenAI) -> None:
    env = await SocEnvClient(base_url=ENV_URL)

    rewards: List[float] = []
    history: List[str]   = []
    steps_taken = 0
    success     = False
    score       = 0.0
    obs_dict    = {}

    log_start(task=task, env=BENCHMARK, model=MODEL_NAME)

    try:
        result   = await env.reset(difficulty=task)
        obs_dict = result.observation.model_dump()

        def _fallback_node(obs: dict) -> Optional[str]:
            alerts = obs.get("active_alerts", [])
            if alerts:
                return alerts[0].get("node_id")
            return None

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": build_user_prompt(obs_dict, history)},
        ]

        for step in range(1, MAX_STEPS + 1):
            if result.done:
                break

            raw    = call_llm(llm_client, messages, fallback_node=_fallback_node(obs_dict))
            action = SocAction(**raw)

            reasoning_text = raw.get("reasoning", "No reasoning provided.")
            print(f"\n[REASONING] Step {step}:\n{reasoning_text}\n", file=sys.stderr, flush=True)

            action_str = (
                f"{action.action_type}('{action.target_node}')"
                if action.target_node else f"{action.action_type}()"
            )

            error: Optional[str] = None
            try:
                result   = await env.step(action)
                obs_dict = result.observation.model_dump()
                reward   = result.reward or 0.0
                done     = result.done
            except Exception as e:
                reward = 0.0
                done   = True
                error  = str(e)
                print(f"[DEBUG] env.step() error: {e}", file=sys.stderr, flush=True)
                rewards.append(reward)
                log_step(step=step, action=action_str, reward=reward, done=done, error=error)
                steps_taken = step
                break

            rewards.append(reward)
            steps_taken = step

            log_step(step=step, action=action_str, reward=reward, done=done, error=error)

            history.append(f"Step {step}: {action_str} -> reward {reward:+.2f}")
            messages.append({"role": "assistant", "content": json.dumps(raw)})
            messages.append({"role": "user",      "content": build_user_prompt(obs_dict, history)})

            if done:
                break

        score   = GRADERS[task]({"rewards": rewards})
        success = score >= SUCCESS_SCORE_THRESHOLD

    except Exception as outer_exc:
        print(f"[DEBUG] Episode error: {outer_exc}", file=sys.stderr, flush=True)

    finally:
        try:
            await env.close()
        except Exception as e:
            print(f"[DEBUG] env.close() error: {e}", file=sys.stderr, flush=True)

        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)


# ── Entry point ───────────────────────────────────────────────────────────────

async def main(difficulties: List[str]) -> None:
    llm_client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
    for task in difficulties:
        await run_episode(task, llm_client)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--difficulty",
        type=str,
        default="all",
        choices=["easy", "medium", "hard", "all"],
    )
    args = parser.parse_args()

    target_task = os.getenv("TASK_NAME", "")
    if target_task:
        if "easy"   in target_task: args.difficulty = "easy"
        elif "medium" in target_task: args.difficulty = "medium"
        elif "hard"   in target_task: args.difficulty = "hard"

    difficulties = TASKS if args.difficulty == "all" else [args.difficulty]

    asyncio.run(main(difficulties))