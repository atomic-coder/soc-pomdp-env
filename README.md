---
title: SOC POMDP Environment
emoji: 🛡️
colorFrom: red
colorTo: pink
sdk: docker
pinned: false
app_port: 8000
base_path: /web
tags:
  - openenv
---

# SOC_POMDP — Autonomous SOC Analyst Environment

A cybersecurity threat-hunting environment where an LLM agent plays the role of a Tier 3 SOC Analyst. The agent must identify and isolate an attacker moving laterally through a procedurally generated corporate network — before the attacker reaches sensitive data or the investigation budget runs out.

This is a **Partially Observable Markov Decision Process (POMDP)**: the agent never directly sees where the attacker is. It must reason from noisy SIEM alerts and forensic logs, distinguishing true positives from false positives, to locate and isolate the threat.

---

## Environment Overview

### Motivation

Real SOC analysts face exactly this problem daily: a SIEM fires dozens of alerts across a network, most of which are legitimate IT activity. The analyst must triage, investigate, and act under time and resource pressure. This environment models that task faithfully using real MITRE ATT&CK-aligned Sigma rules, realistic TP/FP log pairs, and a dynamic attacker that moves through the network if not stopped.

### How It Works

At each tick (representing ~5 minutes of real time):

1. The **attacker** may move to a connected node (every 4 ticks)
2. **Alerts fire** across the network — some are real (attacker), most are IT noise (false positives)
3. The **agent** receives the SIEM dashboard and chooses an action
4. If the attacker reaches a `db-sql` or `aws-*` node, data is exfiltrated and the episode ends in failure

The agent wins by isolating the correct node before this happens.

---

## Action Space

**`SocAction`** — two available actions:

| Field | Type | Description |
|---|---|---|
| `action_type` | `"query_log"` \| `"isolate_node"` | The action to take |
| `target_node` | `str` | The network node to act on (e.g. `"wks-user-03"`) |
| `reasoning` | `str` | The agent's zero-shot reasoning for this action |

**`query_log`** — costs 1 budget. Returns the forensic logs buffered for that node since the last query. Logs contain either TP evidence (attacker artifacts) or FP evidence (legitimate IT activity). The buffer is cleared after reading.

**`isolate_node`** — costs 5 budget. Cuts the node from the network permanently. If it's the attacker's current node: **CRITICAL SUCCESS**, episode ends with positive reward. If wrong: network disruption penalty.

---

## Observation Space

**`SocObservation`** — the SIEM dashboard the agent sees each tick:

| Field | Type | Description |
|---|---|---|
| `active_alerts` | `List[Alert]` | Sigma rule alerts firing across all non-isolated nodes |
| `logs_returned` | `str` | Forensic JSON logs from the most recent `query_log` |
| `isolated_nodes` | `List[str]` | Nodes currently cut off from the network |
| `budget_remaining` | `int` | Remaining investigation budget |
| `current_tick` | `int` | Current time step |
| `system_messages` | `str` | Environment feedback (errors, success/failure messages) |

Each **`Alert`** contains: `alert_id`, `node_id`, `sigma_rule`, `severity`, `timestamp`.

---

## Reward Function

Rewards are designed to provide a meaningful signal across the full trajectory, not just at episode end:

| Event | Reward |
|---|---|
| Correct isolation (attacker found) | `+0.5` |
| Wrong isolation (innocent node) | `-0.25` |
| Budget exhausted | `-0.5` |
| Data exfiltration (attacker reached db/cloud) | `-1.0` |
| `query_log` action | `0.0` (no direct reward — gather information) |

Per-step rewards are intentionally small so the grader's mean-based scoring reflects the quality of the full investigation strategy rather than single actions.

---

## Tasks

Three difficulty levels, each procedurally generating a different network size and attacker behaviour:

### Easy — Ransomware Script Kiddies
- **Network**: 6 nodes across DMZ, Internal, and Secure zones
- **Attacker stealth**: 1.0 (fires almost every applicable Sigma rule — easy to spot)
- **Noise**: 0.5× base FP rate
- **Budget**: 20
- **Expected score**: A capable agent should achieve 0.65–0.85

### Medium — Corporate Breach (Living off the Land)
- **Network**: 16 nodes across 4 zones
- **Attacker stealth**: 0.6 (blends in more — uses legitimate-looking tools)
- **Noise**: 0.8× base FP rate
- **Budget**: 15
- **Expected score**: 0.45–0.70

### Hard — Advanced Persistent Threat (APT)
- **Network**: 31 nodes across 5 zones including Cloud infrastructure
- **Attacker stealth**: 0.2 (ghost-like — rarely triggers alarms)
- **Noise**: 1.0× base FP rate (maximum noise)
- **Budget**: 10 (very tight — 2 wrong isolations = failure)
- **Expected score**: 0.25–0.50 for frontier models

---

## Network Topology

The procedural graph follows a realistic corporate network structure:

```
DMZ (ext-vpn, ext-web, ext-mail)
  ↓
Internal Basic (wks-user workstations)
  ↓
Internal Admin (srv-ad, srv-jumpbox, srv-sccm)
  ↓
Secure Zone (db-sql, app-pay)       ← exfiltration triggers here
  ↓
Cloud Infra (aws-s3, aws-iam)       ← exfiltration triggers here (hard only)
```

The attacker always starts in the DMZ and moves toward cloud/secure nodes. SCCM has lateral reach to everything.

---

## Sigma Rules

10 MITRE ATT&CK-aligned detection rules fire across the network each tick:

| Rule | Tactic | Severity | Base FP Rate |
|---|---|---|---|
| Suspicious Office Child Process | Initial Access | High | 5% |
| PowerShell Execution Policy Bypass | Execution | Medium | 60% |
| Scheduled Task Creation as SYSTEM | Persistence | Medium | 40% |
| Local Service Exploitation | Privilege Escalation | Critical | 2% |
| Windows Security Event Log Cleared | Defense Evasion | Critical | 1% |
| LSASS Memory Dump | Credential Access | Critical | 2% |
| Active Directory Enumeration (BloodHound) | Discovery | Medium | 30% |
| Remote WMI Command Execution | Lateral Movement | High | 50% |
| RDP Login from Unusual Internal Source | Lateral Movement | Medium | 40% |
| Massive Outbound Data Transfer via CLI | Exfiltration | Critical | 20% |

Each rule has a distinct TP log and FP log. When the agent calls `query_log`, they receive the actual buffered logs — a skilled agent can distinguish `SharpHound.exe` from `Azure AD Connect` in an AD enumeration alert.

---

## Grading

Scores are computed by `easy_grader`, `medium_grader`, and `hard_grader` in `graders.py`. Each receives a trajectory dict `{"rewards": [...]}` and returns a float in `(0.01, 0.99)`.

All three graders use the same formula: `(total_reward + 1.0) / 1.5`, normalizing from the practical reward range of `[-1.0, +0.5]` to `[0, 1]`. A score above `0.5` indicates the agent successfully isolated the attacker or at minimum avoided catastrophic failures.

---

## Quick Start

```python
from client import SocEnvClient
from models import SocAction

# Connect to a running environment
env = SocEnvClient(base_url="http://localhost:8000")

# Reset with a difficulty
result = env.reset(difficulty="easy")
obs = result.observation

print(f"Network size: nodes visible in alerts")
print(f"Budget: {obs.budget_remaining}")
print(f"Active alerts: {len(obs.active_alerts)}")

# Investigate a node
action = SocAction(
    action_type="query_log",
    target_node="ext-vpn-01",
    reasoning="High-severity alert on DMZ node, starting investigation here."
)
result = env.step(action)
print(result.observation.logs_returned)
```

---

## Running Locally

```bash
# Build the Docker image
docker build -t soc-pomdp:latest -f server/Dockerfile .

# Run the server
docker run -p 8000:8000 soc-pomdp:latest

# Or run directly with uvicorn (from project root)
uvicorn server.app:app --reload --host 0.0.0.0 --port 8000
```

The web interface is available at `http://localhost:8000/web` once running.

---

## Running the Baseline Inference Script

```bash
# Set required environment variables
export HF_TOKEN=hf_your_token_here
export API_BASE_URL=https://router.huggingface.co/v1
export MODEL_NAME=Qwen/Qwen2.5-72B-Instruct
export LOCAL_IMAGE_NAME=soc-pomdp:latest

# Run all three difficulties
python inference.py

# Run a specific difficulty
python inference.py --difficulty easy
```

The script emits structured logs consumed by the judge:
```
[START] task=easy env=Soc_POMDP model=Qwen/Qwen2.5-72B-Instruct
[STEP] step=1 action=query_log('ext-vpn-01') reward=0.00 done=false error=null
[STEP] step=2 action=isolate_node('ext-vpn-01') reward=0.50 done=true error=null
[END] success=true steps=2 score=0.999 rewards=0.00,0.50
```

---

## Deploying to Hugging Face Spaces

```bash
# From the project root
openenv push

# Push to a specific repo
openenv push --repo-id your-username/soc-pomdp

# Push as private
openenv push --private
```

---

## Project Structure

```
SOC_POMDP/
├── README.md                        # This file
├── openenv.yaml                     # OpenEnv manifest and task registration
├── models.py                        # SocAction, SocObservation, Alert models
├── client.py                        # SocEnvClient for connecting to the server
├── graders.py                       # easy_grader, medium_grader, hard_grader
├── inference.py                     # Baseline LLM agent inference script
└── server/
    ├── __init__.py
    ├── SOC_POMDP_environment.py     # Core environment logic
    ├── app.py                       # FastAPI application
    └── Dockerfile                   # Container image definition
```