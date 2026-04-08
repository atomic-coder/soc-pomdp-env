# Copyright (c) Meta Platforms, Inc. and affiliates.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

"""
Soc Pomdp Environment Implementation.

A Partially Observable Markov Decision Process (POMDP) simulating a Tier 3 Security 
Operations Center (SOC). The agent acts as an autonomous SOC Copilot tasked with 
hunting and neutralizing an adversary within a procedurally generated enterprise network.

Game Dynamics:
    - The attacker spawns in the DMZ and moves laterally across the network graph every 4 ticks.
    - The environment generates synthetic SIEM alerts based on 10 MITRE Kill Chain Sigma rules.
    - Alerts are a mix of True Positives (attacker actions governed by a stealth multiplier) 
      and False Positives (benign IT noise governed by a noise multiplier).
    - The agent must query forensic logs to differentiate between FPs and TPs before 
      spending heavy budget to isolate nodes.

Action Space (SocAction):
    - `query_log(target_node)`: Queries memory/disk artifacts on a node. 
        Cost: 1 Budget. Returns exact triggered logs (if any).
    - `isolate_node(target_node)`: Severs a node from the network. 
        Cost: 5 Budget. 

Observation Space (SocObservation):
    - `active_alerts`: List of firing Sigma rule alerts across the network.
    - `logs_returned`: Raw JSON forensic logs from the last queried node.
    - `isolated_nodes`: List of nodes currently taken offline.
    - `budget_remaining`: Investigation budget left before failure.
    - `current_tick`: Time step counter (1 tick = 5 minutes).
    - `system_messages`: Feedback on actions, errors, or mitigations.

Reward Function & Terminal Conditions:
    - Win Condition: Agent successfully isolates the attacker node. (Reward: +0.5)
    - Penalty: Agent isolates a benign/incorrect node. (Reward: -0.25)
    - Loss Condition (Exfiltration): Attacker reaches a secure zone (aws-* or db-*). (Reward: -1.0)
    - Loss Condition (Time/Budget): Agent exhausts all investigation budget. (Reward: -0.5)

Difficulty Levels:
    - `easy`: Small network, high budget (20). Attacker is noisy and highly visible.
    - `medium`: Medium network, standard budget (15). Attacker uses Living-off-the-Land tactics.
    - `hard`: Large network (includes Cloud/Admin zones), low budget (10). Attacker is an APT, highly stealthy.
"""

import random
import uuid
from typing import Dict, List, Optional

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State
from models import SocAction, SocObservation, Alert

class SocState(State):
    attacker_node: str = ""

# ── Dynamic Difficulty & Procedural Templates ───────────────────────────────
TASK_CONFIGS = {
    "easy": {
        "description": "Ransomware Script Kiddies. High noise, high visibility.",
        "noise_multiplier": 0.5,
        "stealth_multiplier": 1.0, # Triggers almost all alarms
        "budget": 20,
        "allowed_zones": ["DMZ", "Internal_Basic", "Secure"],
        "node_counts": {
            "DMZ": {"ext-vpn": 1, "ext-web": 1},
            "Internal_Basic": {"wks-user": 3},
            "Secure": {"db-sql": 1}
        }
    },
    "medium": {
        "description": "Corporate Breach. 'Living off the Land' tactics.",
        "noise_multiplier": 0.8,
        "stealth_multiplier": 0.6,
        "budget": 15,
        "allowed_zones": ["DMZ", "Internal_Basic", "Internal_Admin", "Secure"],
        "node_counts": {
            "DMZ": {"ext-vpn": 1, "ext-web": 2, "ext-mail": 1},
            "Internal_Basic": {"wks-user": 8},
            "Internal_Admin": {"srv-ad": 1, "srv-jumpbox": 1},
            "Secure": {"db-sql": 2, "app-pay": 1}
        }
    },
    "hard": {
        "description": "Advanced Persistent Threat (APT). High noise, ghost-like stealth.",
        "noise_multiplier": 1.0,
        "stealth_multiplier": 0.2, # Very rarely triggers alarms
        "budget": 10,
        "allowed_zones": ["DMZ", "Internal_Basic", "Internal_Admin", "Secure", "Cloud_Infra"],
        "node_counts": {
            "DMZ": {"ext-vpn": 2, "ext-web": 3, "ext-mail": 1},
            "Internal_Basic": {"wks-user": 15},
            "Internal_Admin": {"srv-ad": 2, "srv-jumpbox": 1, "srv-sccm": 1},
            "Secure": {"db-sql": 3, "app-pay": 2},
            "Cloud_Infra": {"aws-s3": 2, "aws-iam": 1}
        }
    }
}

# ── 10-Rule MITRE Kill Chain (Sigma Rules) ──────────────────────────────────
SIGMA_RULES = [
    # Initial Access
    {"id": "SIG_001", "rule": "Suspicious Office Child Process", "severity": "High", "base_fp_prob": 0.05, "is_attacker_behavior": True,
     "fp_log": '{"process": "excel.exe -> splwow64.exe", "user": "DOMAIN\\\\user", "cmd": "printing"}',
     "tp_log": '{"process": "winword.exe -> cmd.exe -> powershell.exe", "user": "DOMAIN\\\\user", "cmd": "powershell -W Hidden -ENCODED..."}'},
    # Execution
    {"id": "SIG_002", "rule": "PowerShell Execution Policy Bypass", "severity": "Medium", "base_fp_prob": 0.60, "is_attacker_behavior": True,
     "fp_log": '{"process": "powershell.exe -ep bypass C:\\\\IT\\\\update.ps1", "parent": "ccmexec.exe"}',
     "tp_log": '{"process": "powershell.exe -ep bypass -w hidden", "parent": "explorer.exe", "net": "TCP 443 -> 185.22.x.x"}'},
    # Persistence
    {"id": "SIG_003", "rule": "Scheduled Task Creation as SYSTEM", "severity": "Medium", "base_fp_prob": 0.40, "is_attacker_behavior": True,
     "fp_log": '{"task_name": "GoogleUpdateTaskMachineUA", "action": "C:\\\\Program Files\\\\Google\\\\...\\\\GoogleUpdate.exe"}',
     "tp_log": '{"task_name": "WinDefend_Update_Cache", "action": "C:\\\\Users\\\\Public\\\\Libraries\\\\svchost.exe"}'},
    # Privilege Escalation
    {"id": "SIG_004", "rule": "Local Service Exploitation", "severity": "Critical", "base_fp_prob": 0.02, "is_attacker_behavior": True,
     "fp_log": '{"service": "PrintSpooler", "status": "restarted by IT_Admin"}',
     "tp_log": '{"service": "PrintSpooler", "status": "crashed", "child_process": "cmd.exe running as NT AUTHORITY\\\\SYSTEM"}'},
    # Defense Evasion
    {"id": "SIG_005", "rule": "Windows Security Event Log Cleared", "severity": "Critical", "base_fp_prob": 0.01, "is_attacker_behavior": True,
     "fp_log": '{"event_id": 1102, "user": "DOMAIN\\\\IT_Admin_Dave", "desc": "Routine log rotation."}',
     "tp_log": '{"event_id": 1102, "user": "NT AUTHORITY\\\\SYSTEM", "desc": "Security log cleared via wevtutil.exe"}'},
    # Credential Access
    {"id": "SIG_006", "rule": "LSASS Memory Dump", "severity": "Critical", "base_fp_prob": 0.02, "is_attacker_behavior": True,
     "fp_log": '{"process": "taskmgr.exe -> lsass.exe", "user": "DOMAIN\\\\Admin", "desc": "Manual crash dump creation."}',
     "tp_log": '{"process": "rundll32.exe comsvcs.dll MiniDump", "user": "SYSTEM", "desc": "Suspicious memory access."}'},
    # Discovery
    {"id": "SIG_007", "rule": "Active Directory Enumeration (BloodHound)", "severity": "Medium", "base_fp_prob": 0.30, "is_attacker_behavior": True,
     "fp_log": '{"query": "LDAP://CN=Users...", "source_app": "Azure AD Connect"}',
     "tp_log": '{"query": "LDAP://CN=All...", "source_app": "SharpHound.exe", "volume": "Massive"}'},
    # Lateral Movement (WMI)
    {"id": "SIG_008", "rule": "Remote WMI Command Execution", "severity": "High", "base_fp_prob": 0.50, "is_attacker_behavior": True,
     "fp_log": '{"process": "WmiPrvSE.exe", "user": "DOMAIN\\\\svc_sccm", "command": "Select * from Win32_Product"}',
     "tp_log": '{"process": "WmiPrvSE.exe", "user": "DOMAIN\\\\Admin", "command": "process call create reverse_shell.exe"}'},
    # Lateral Movement (RDP)
    {"id": "SIG_009", "rule": "RDP Login from Unusual Internal Source", "severity": "Medium", "base_fp_prob": 0.40, "is_attacker_behavior": False, # Attacker in this env uses WMI, this is just pure noise
     "fp_log": '{"event_id": 4624, "type": 10, "user": "DOMAIN\\\\HelpDesk", "source_ip": "10.0.5.55"}',
     "tp_log": ""},
    # Exfiltration
    {"id": "SIG_010", "rule": "Massive Outbound Data Transfer via CLI", "severity": "Critical", "base_fp_prob": 0.20, "is_attacker_behavior": True,
     "fp_log": '{"process": "aws.exe s3 sync", "user": "DOMAIN\\\\svc_backup", "bytes": "500GB"}',
     "tp_log": '{"process": "rclone.exe copy", "user": "SYSTEM", "target_ip": "Mega.nz", "bytes": "45GB"}'}
]


class SocEnvironment(Environment):
    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, difficulty: str = "hard"):
        self._difficulty = difficulty if difficulty in TASK_CONFIGS else "medium"
        self._state = SocState(episode_id=str(uuid.uuid4()), step_count=0)
        self.rng = random.Random() # Will be seeded in reset
        
        self._tick = 0
        self._budget = 0
        self._global_alert_id = 0
        
        # Graph State
        self._all_nodes = []
        self._isolated_nodes = set()
        self._connections = {}
        self._attacker_node = ""
        
        # Log Memory: Maps node_id -> List of triggered logs
        self._node_logs_buffer = {}

    def _build_procedural_graph(self):
        """Dynamically generates the nodes and edges based on difficulty."""
        cfg = TASK_CONFIGS[self._difficulty]
        self._all_nodes = []
        self._connections = {}
        
        # 1. Generate Nodes
        for zone in cfg["allowed_zones"]:
            counts = cfg["node_counts"].get(zone, {})
            for prefix, count in counts.items():
                for i in range(1, count + 1):
                    node_name = f"{prefix}-{i:02d}"
                    self._all_nodes.append(node_name)
                    self._connections[node_name] = []

        # 2. Wire edges based on prefixes
        def connect(src_prefix, tgt_prefix):
            srcs = [n for n in self._all_nodes if n.startswith(src_prefix)]
            tgts = [n for n in self._all_nodes if n.startswith(tgt_prefix)]
            for s in srcs:
                for t in tgts:
                    if s != t:
                        self._connections[s].append(t)

        connect("ext-vpn", "wks-user")
        connect("ext-web", "srv-ad")
        connect("ext-mail", "wks-user")
        
        connect("wks-user", "srv-ad")
        connect("wks-user", "srv-jumpbox")
        
        connect("srv-ad", "db-sql")
        connect("srv-ad", "app-pay")
        connect("srv-ad", "srv-sccm")
        connect("srv-jumpbox", "db-sql")
        connect("srv-jumpbox", "app-pay")
        
        # SCCM pushes to everything
        connect("srv-sccm", "wks-user")
        connect("srv-sccm", "db-sql")
        connect("srv-sccm", "srv-ad")
        
        connect("db-sql", "aws-s3")
        connect("app-pay", "aws-iam")

    @property
    def state(self) -> State:
        return self._state

    def reset(self, seed: Optional[int] = None, difficulty: Optional[str] = None, **kwargs) -> SocObservation:
        if difficulty and difficulty in TASK_CONFIGS:
            self._difficulty = difficulty
        
        # 1. Seed for the OpenEnv Validator
        self.rng = random.Random(seed)
        
        cfg = TASK_CONFIGS[self._difficulty]
        self._state = SocState(episode_id=str(uuid.uuid4()), step_count=0)
        self._budget = cfg["budget"]
        self._tick = 0
        self._global_alert_id = 0
        self._isolated_nodes = set()
        self._node_logs_buffer = {}

        self._build_procedural_graph()
        
        # Drop attacker in DMZ
        dmz_nodes = [n for n in self._all_nodes if n.startswith("ext-")]
        self._attacker_node = self.rng.choice(dmz_nodes)
        self._state.attacker_node = self._attacker_node

        notes = (
            f"SYSTEM BOOT: Autonomous SOC Copilot Online. [Level: {self._difficulty.upper()}]\n"
            f"Network Size: {len(self._all_nodes)} nodes generated.\n"
            f"Mission: {cfg['description']} Isolate the attacker before budget exhaustion."
        )

        return self._generate_observation(notes, populate_logs=False)

    def _generate_observation(self, notes: str, logs: str = "", populate_logs: bool = True) -> SocObservation:
        cfg = TASK_CONFIGS[self._difficulty]
        active_alerts = []

        for node in self._all_nodes:
            if node in self._isolated_nodes:
                continue

            # Initialize log buffer for node if it doesn't exist
            if node not in self._node_logs_buffer:
                self._node_logs_buffer[node] = []

            for rule in SIGMA_RULES:
                # 1. Attacker True Positives
                if node == self._attacker_node and rule["is_attacker_behavior"]:
                    if self.rng.random() < cfg["stealth_multiplier"]:
                        self._global_alert_id += 1
                        alert_id = f"A_{self._global_alert_id}"
                        active_alerts.append(Alert(
                            alert_id=alert_id, node_id=node, sigma_rule=rule["rule"], 
                            severity=rule["severity"], timestamp=f"T+{self._tick}"
                        ))
                        # Store specific TP log silently
                        if populate_logs:
                            self._node_logs_buffer[node].append(rule["tp_log"])

                # 2. IT Noise (False Positives)
                adjusted_fp_prob = rule["base_fp_prob"] * cfg["noise_multiplier"]
                if self.rng.random() < adjusted_fp_prob:
                    self._global_alert_id += 1
                    alert_id = f"A_{self._global_alert_id}"
                    active_alerts.append(Alert(
                        alert_id=alert_id, node_id=node, sigma_rule=rule["rule"], 
                        severity=rule["severity"], timestamp=f"T+{self._tick}"
                    ))
                    # Store specific FP log silently
                    if populate_logs:
                        self._node_logs_buffer[node].append(rule["fp_log"])

        return SocObservation(
            done=False, reward=0.0,
            active_alerts=active_alerts, logs_returned=logs,
            isolated_nodes=list(self._isolated_nodes), budget_remaining=self._budget,
            current_tick=self._tick, system_messages=notes
        )

    def step(self, action: SocAction) -> SocObservation:
        self._state.step_count += 1
        self._tick += 1
        reward = 0.0
        notes = []
        logs_returned = ""
        done = False

        # ── 1. Attacker Lateral Movement ──────────────────────────────────
        if self._tick % 4 == 0:
            neighbors = self._connections.get(self._attacker_node, [])
            valid_neighbors = [n for n in neighbors if n not in self._isolated_nodes]
            if valid_neighbors:
                self._attacker_node = self.rng.choice(valid_neighbors)
                self._state.attacker_node = self._attacker_node

        # ── 2. Action Engine ──────────────────────────────────────────────
        if action.target_node not in self._all_nodes:
            notes.append(f"ERROR: Node '{action.target_node}' does not exist.")
            
        elif action.action_type == "query_log":
            self._budget -= 1
            # Retrieve exact logs triggered on this node, no hand-holding.
            stored_logs = self._node_logs_buffer.get(action.target_node, [])
            if stored_logs:
                logs_returned = "\n".join(stored_logs)
                # Clear buffer after reading
                self._node_logs_buffer[action.target_node] = []
            else:
                logs_returned = '{"status": "No forensic artifacts recovered in memory."}'
            notes.append(f"Logs queried for {action.target_node}.")

        elif action.action_type == "isolate_node":
            self._budget -= 5
            self._isolated_nodes.add(action.target_node)
            
            if action.target_node == self._attacker_node:
                notes.append(f"CRITICAL SUCCESS. Attacker isolated on {action.target_node}.")
                reward = 0.5
                done = True
            else:
                notes.append(f"MITIGATION: {action.target_node} offline. Network disrupted.")
                reward = -0.25

        # ── 3. Loss Conditions ────────────────────────────────────────────
        if self._budget <= 0 and not done:
            done = True
            reward = -0.5
            notes.append("FAILURE: SOC Budget exhausted.")
            
        # Cloud/Secure nodes exfiltration check
        loss_nodes = [n for n in self._all_nodes if n.startswith("aws-") or n.startswith("db-")]
        if self._attacker_node in loss_nodes and not done:
            done = True
            reward = -1.0
            notes.append(f"CRITICAL FAILURE: Attacker reached {self._attacker_node}. Data Exfiltrated.")

        obs = self._generate_observation(" | ".join(notes), logs_returned)
        obs.done = done
        obs.reward = reward
        return obs