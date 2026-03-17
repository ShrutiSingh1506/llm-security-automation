"""
Attack kill-chain reconstruction from raw security logs.

Classifies log lines into MITRE ATT&CK stages, builds an ordered
timeline of AttackEvent objects, and produces both terminal output
and embeddable HTML for the dashboard.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class AttackEvent:
    timestamp: str
    raw_timestamp: Optional[datetime]
    kill_chain_stage: str
    mitre_technique: str
    mitre_name: str
    description: str
    source_ip: Optional[str]
    dest_ip: Optional[str]
    indicators: List[str]
    severity: str
    raw_log: str


@dataclass
class AttackChain:
    chain_id: str
    log_source: str
    severity: str
    events: List[AttackEvent]
    stages_detected: List[str]
    total_stages: int
    source_ips: List[str]
    target_ips: List[str]
    recommendation: str
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_minutes: Optional[float] = None


# ── Kill-chain taxonomy ────────────────────────────────────────────────────────

KILL_CHAIN_STAGES: Dict[str, Dict] = {
    "RECONNAISSANCE":       {"emoji": "🔍", "color": "#6c757d", "order": 1},
    "WEAPONIZATION":        {"emoji": "⚙️",  "color": "#fd7e14", "order": 2},
    "INITIAL_ACCESS":       {"emoji": "🚪", "color": "#dc3545", "order": 3},
    "EXECUTION":            {"emoji": "💻", "color": "#e83e8c", "order": 4},
    "PERSISTENCE":          {"emoji": "🔒", "color": "#6f42c1", "order": 5},
    "PRIVILEGE_ESCALATION": {"emoji": "⬆️",  "color": "#fd7e14", "order": 6},
    "DEFENSE_EVASION":      {"emoji": "🎭", "color": "#20c997", "order": 7},
    "CREDENTIAL_ACCESS":    {"emoji": "🔑", "color": "#ffc107", "order": 8},
    "LATERAL_MOVEMENT":     {"emoji": "↔️",  "color": "#17a2b8", "order": 9},
    "COLLECTION":           {"emoji": "📦", "color": "#007bff", "order": 10},
    "EXFILTRATION":         {"emoji": "📤", "color": "#dc3545", "order": 11},
    "COMMAND_CONTROL":      {"emoji": "📡", "color": "#6c757d", "order": 12},
    "IMPACT":               {"emoji": "💥", "color": "#343a40", "order": 13},
}

# (regex, stage, mitre_id, mitre_name)
_PATTERN_RULES: List[Tuple[str, str, str, str]] = [
    (r"port\s*scan|nmap|masscan|nessus|shodan|enumerat",
     "RECONNAISSANCE", "T1595", "Active Scanning"),
    (r"whois|dns\s*lookup|subdomain|osint",
     "RECONNAISSANCE", "T1590", "Gather Victim Network Info"),
    (r"brute\s*force|password\s*spray|failed\s*login|invalid\s*password|authentication\s*fail",
     "INITIAL_ACCESS", "T1110", "Brute Force"),
    (r"phishing|spear.?phish|malicious\s*email|malicious\s*attachment",
     "INITIAL_ACCESS", "T1566", "Phishing"),
    (r"vpn.*compromised|compromised\s*credentials|stolen\s*cred|valid\s*account",
     "INITIAL_ACCESS", "T1078", "Valid Accounts"),
    (r"\$\{jndi:|jndi:ldap|log4shell|cve-2021-44228",
     "INITIAL_ACCESS", "T1190", "Exploit Public-Facing Application (Log4Shell)"),
    (r"sql\s*injection|xss|rce|remote\s*code\s*exec|exploit.*vulnerability",
     "INITIAL_ACCESS", "T1190", "Exploit Public-Facing Application"),
    (r"powershell|cmd\.exe|bash\s+-c|wget.*malware|curl.*payload|python.*exec",
     "EXECUTION", "T1059", "Command and Scripting Interpreter"),
    (r"ldap://.*exploit|jndi.*class|remote\s*class\s*load",
     "EXECUTION", "T1203", "Exploitation for Client Execution"),
    (r"mshta|wscript|cscript|regsvr32|rundll32",
     "EXECUTION", "T1218", "System Binary Proxy Execution"),
    (r"scheduled\s*task|cron\s*job|at\.exe|schtask",
     "PERSISTENCE", "T1053", "Scheduled Task/Job"),
    (r"registry.*run|hklm.*currentversion.*run|startup\s*folder",
     "PERSISTENCE", "T1547", "Boot or Logon Autostart Execution"),
    (r"new\s*service|service.*install|sc\s*create",
     "PERSISTENCE", "T1543", "Create or Modify System Process"),
    (r"persistence\s*added|persistence\s*mechanism",
     "PERSISTENCE", "T1547", "Boot or Logon Autostart Execution"),
    (r"privilege\s*escal|sudo.*success|root\s*access\s*gained|whoami.*root|uid=0",
     "PRIVILEGE_ESCALATION", "T1068", "Exploitation for Privilege Escalation"),
    (r"token\s*imperson|runas|mimikatz|pass.?the.?hash",
     "PRIVILEGE_ESCALATION", "T1134", "Access Token Manipulation"),
    (r"vssadmin.*delete|shadow\s*cop|bcdedit.*recover",
     "DEFENSE_EVASION", "T1490", "Inhibit System Recovery"),
    (r"log.*clear|event.*clear|wevtutil.*cl|auditpol",
     "DEFENSE_EVASION", "T1070", "Indicator Removal"),
    (r"obfuscat|base64.*encod|encode.*payload|pack.*upx",
     "DEFENSE_EVASION", "T1027", "Obfuscated Files or Information"),
    (r"credential|lsass|ntds\.dit|sam\s*database|secretsdump|hashdump",
     "CREDENTIAL_ACCESS", "T1003", "OS Credential Dumping"),
    (r"keylog|keyboard\s*capture",
     "CREDENTIAL_ACCESS", "T1056", "Input Capture"),
    (r"smb.*connect|lateral.*movement|psexec|wmi.*remote|rdp.*lateral",
     "LATERAL_MOVEMENT", "T1021", "Remote Services"),
    (r"pass.*ticket|golden\s*ticket|kerberoast",
     "LATERAL_MOVEMENT", "T1550", "Use Alternate Authentication Material"),
    (r"file.*collect|data.*stage|compress.*archive|zip.*sensitive|7z.*data",
     "COLLECTION", "T1560", "Archive Collected Data"),
    (r"screenshot|screen\s*capture|keylog.*collect",
     "COLLECTION", "T1113", "Screen Capture"),
    (r"c2|command.and.control|beacon|c&c|botnet|callback.*server",
     "COMMAND_CONTROL", "T1071", "Application Layer Protocol"),
    (r"dns.*tunnel|icmp.*tunnel|covert.*channel",
     "COMMAND_CONTROL", "T1572", "Protocol Tunneling"),
    (r"avsvmcloud|freescanonline|deftsecurity",
     "COMMAND_CONTROL", "T1071", "Application Layer Protocol (SolarWinds C2)"),
    (r"exfiltrat|data.*transfer.*\d+\s*[gm]b|large.*upload|upload.*\d+\s*[gm]b",
     "EXFILTRATION", "T1041", "Exfiltration Over C2 Channel"),
    (r"ftp.*upload|sftp.*put|scp.*transfer|http.*post.*\d+kb",
     "EXFILTRATION", "T1048", "Exfiltration Over Alternative Protocol"),
    (r"ransom|encrypt.*files|mass.*file.*encrypt|README.*DECRYPT|your.*files.*encrypted",
     "IMPACT", "T1486", "Data Encrypted for Impact"),
    (r"dos|ddos|denial.of.service|flood.*traffic|syn.*flood",
     "IMPACT", "T1498", "Network Denial of Service"),
    (r"data.*wipe|disk.*wipe|format.*drive|delete.*backup",
     "IMPACT", "T1485", "Data Destruction"),
]

_SEVERITY_MAP: Dict[str, str] = {
    "RECONNAISSANCE":       "LOW",
    "WEAPONIZATION":        "MEDIUM",
    "INITIAL_ACCESS":       "HIGH",
    "EXECUTION":            "HIGH",
    "PERSISTENCE":          "HIGH",
    "PRIVILEGE_ESCALATION": "CRITICAL",
    "DEFENSE_EVASION":      "HIGH",
    "CREDENTIAL_ACCESS":    "CRITICAL",
    "LATERAL_MOVEMENT":     "CRITICAL",
    "COLLECTION":           "HIGH",
    "EXFILTRATION":         "CRITICAL",
    "COMMAND_CONTROL":      "HIGH",
    "IMPACT":               "CRITICAL",
}

_RECOMMENDATIONS: Dict[str, str] = {
    "IMPACT":
        "🚨 ISOLATE IMMEDIATELY — Ransomware/impact activity detected. Disconnect affected systems.",
    "EXFILTRATION":
        "🚨 BLOCK EGRESS — Data exfiltration in progress. Block outbound connections.",
    "LATERAL_MOVEMENT":
        "⚠️  CONTAIN — Isolate compromised segment. Reset credentials and audit east-west traffic.",
    "CREDENTIAL_ACCESS":
        "⚠️  ROTATE CREDENTIALS — Force password reset for compromised accounts. Enable MFA.",
    "PRIVILEGE_ESCALATION":
        "⚠️  REVOKE PRIVILEGES — Review and revoke excessive permissions. Patch vulnerable binaries.",
    "PERSISTENCE":
        "🔍 REMEDIATE — Remove scheduled tasks, registry keys, and attacker-created services.",
    "EXECUTION":
        "🔍 KILL PROCESSES — Terminate malicious processes and quarantine downloaded payloads.",
    "INITIAL_ACCESS":
        "🔍 BLOCK & PATCH — Block source IPs. Patch exploited vulnerability. Review access logs.",
    "RECONNAISSANCE":
        "📋 MONITOR — Increase logging verbosity. Block scanning IPs at perimeter.",
}

_DEFAULT_RECOMMENDATION = (
    "🔍 INVESTIGATE — Review affected systems and apply standard incident response procedures."
)

_TIMESTAMP_FORMATS: List[Tuple[str, str]] = [
    (r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})",  "%Y-%m-%d %H:%M:%S"),
    (r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})",     "%d/%b/%Y:%H:%M:%S"),
    (r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",     "%b %d %H:%M:%S"),
    (r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})",     "%Y-%m-%dT%H:%M:%S"),
]

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_FILE_RE = re.compile(r"\b\w+\.(exe|dll|ps1|sh|py|bat|vbs|jar)\b", re.IGNORECASE)
_MAX_EVENTS_PER_STAGE = 2
_SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ── Reconstructor ──────────────────────────────────────────────────────────────

class AttackChainReconstructor:
    """Parses security logs and reconstructs MITRE ATT&CK kill chains."""

    # ── Public API ─────────────────────────────────────────────────────────────

    def reconstruct(self, log_content: str, log_source: str = "unknown") -> AttackChain:
        """Parse *log_content* and return a reconstructed :class:`AttackChain`."""
        raw_events = self._parse_events(log_content)
        events = self._sort_and_deduplicate(raw_events)

        stages_detected = list(dict.fromkeys(e.kill_chain_stage for e in events))
        source_ips = list(dict.fromkeys(e.source_ip for e in events if e.source_ip))
        all_ips = list({ip for e in events for ip in _extract_ips(e.raw_log)})
        target_ips = [ip for ip in all_ips if ip not in source_ips]

        timed = [e for e in events if e.raw_timestamp]
        start_time = timed[0].raw_timestamp if timed else None
        end_time = timed[-1].raw_timestamp if timed else None
        duration = (
            (end_time - start_time).total_seconds() / 60
            if start_time and end_time
            else None
        )

        severity = (
            max((e.severity for e in events), key=lambda s: _SEVERITY_ORDER.index(s))
            if events
            else "UNKNOWN"
        )

        recommendation = _DEFAULT_RECOMMENDATION
        for stage in _RECOMMENDATIONS:
            if stage in stages_detected:
                recommendation = _RECOMMENDATIONS[stage]
                break

        return AttackChain(
            chain_id=f"CHAIN-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            log_source=log_source,
            severity=severity,
            events=events,
            stages_detected=stages_detected,
            total_stages=len(stages_detected),
            source_ips=source_ips,
            target_ips=target_ips,
            recommendation=recommendation,
            start_time=start_time,
            end_time=end_time,
            duration_minutes=duration,
        )

    def print_chain(self, chain: AttackChain) -> None:
        """Print a formatted ASCII timeline for *chain*."""
        sep = "=" * 70
        print(f"\n{sep}")
        print(f"  ATTACK CHAIN — {chain.log_source.upper()}")
        print(sep)

        if chain.start_time and chain.end_time:
            dur = f"  ({chain.duration_minutes:.0f} min)" if chain.duration_minutes else ""
            print(
                f"  Timeline : {chain.start_time.strftime('%H:%M:%S')}"
                f" → {chain.end_time.strftime('%H:%M:%S')}{dur}"
            )
        print(f"  Severity : {chain.severity}")
        print(f"  Stages   : {chain.total_stages}/{len(KILL_CHAIN_STAGES)}")
        print(f"  Sources  : {', '.join(chain.source_ips[:3]) or 'Unknown'}")
        print(sep)

        prev_time: Optional[datetime] = None
        for event in chain.events:
            if prev_time and event.raw_timestamp and event.raw_timestamp != prev_time:
                gap = (event.raw_timestamp - prev_time).total_seconds() / 60
                if gap > 0:
                    print(f"  │  ↓ {gap:.0f} min")

            emoji = KILL_CHAIN_STAGES.get(event.kill_chain_stage, {}).get("emoji", "?")
            label = event.kill_chain_stage.replace("_", " ")
            ts = event.timestamp or "??:??:??"
            print(f"\n  {ts}  {emoji} [{label}]")
            print(f"  │  {event.mitre_technique} — {event.mitre_name}")
            print(f"  │  {event.description}")
            if event.indicators:
                print(f"  │  IOCs: {', '.join(event.indicators[:3])}")

            prev_time = event.raw_timestamp

        print("\n" + "-" * 70)
        print(f"\n  Recommendation: {chain.recommendation}")
        print(sep + "\n")

    # ── Private helpers ────────────────────────────────────────────────────────

    def _parse_events(self, log_content: str) -> List[AttackEvent]:
        events: List[AttackEvent] = []
        for line in log_content.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            result = _classify_line(line)
            if result is None:
                continue
            stage, mitre_id, mitre_name = result
            ts_str, ts_dt = _extract_timestamp(line)
            ips = _extract_ips(line)
            events.append(AttackEvent(
                timestamp=ts_str,
                raw_timestamp=ts_dt,
                kill_chain_stage=stage,
                mitre_technique=mitre_id,
                mitre_name=mitre_name,
                description=_build_description(line, stage),
                source_ip=ips[0] if ips else None,
                dest_ip=ips[1] if len(ips) > 1 else None,
                indicators=_extract_indicators(line),
                severity=_SEVERITY_MAP.get(stage, "MEDIUM"),
                raw_log=line[:200],
            ))
        return events

    @staticmethod
    def _sort_and_deduplicate(events: List[AttackEvent]) -> List[AttackEvent]:
        timed = sorted(
            [e for e in events if e.raw_timestamp],
            key=lambda e: e.raw_timestamp,  # type: ignore[arg-type]
        )
        untimed = [e for e in events if not e.raw_timestamp]
        ordered = timed + untimed

        stage_count: Dict[str, int] = {}
        result: List[AttackEvent] = []
        for event in ordered:
            count = stage_count.get(event.kill_chain_stage, 0)
            if count < _MAX_EVENTS_PER_STAGE:
                result.append(event)
                stage_count[event.kill_chain_stage] = count + 1
        return result


# ── Module-level helpers (pure functions) ──────────────────────────────────────

def _extract_timestamp(line: str) -> Tuple[str, Optional[datetime]]:
    for pattern, fmt in _TIMESTAMP_FORMATS:
        match = re.search(pattern, line)
        if match:
            ts_str = match.group(1)
            try:
                return ts_str, datetime.strptime(ts_str, fmt)
            except ValueError:
                return ts_str, None
    return "", None


def _extract_ips(text: str) -> List[str]:
    return list(dict.fromkeys(_IP_RE.findall(text)))


def _extract_indicators(line: str) -> List[str]:
    indicators: List[str] = []
    indicators.extend(_extract_ips(line))
    domains = [d for d in _DOMAIN_RE.findall(line) if not d[0].isdigit()]
    indicators.extend(domains[:3])
    indicators.extend(m[0] if isinstance(m, tuple) else m for m in _FILE_RE.findall(line))
    return list(dict.fromkeys(indicators))[:5]


def _classify_line(line: str) -> Optional[Tuple[str, str, str]]:
    line_lower = line.lower()
    for pattern, stage, mitre_id, mitre_name in _PATTERN_RULES:
        if re.search(pattern, line_lower, re.IGNORECASE):
            return stage, mitre_id, mitre_name
    return None


def _build_description(line: str, stage: str) -> str:
    ll = line.lower()
    descriptions: Dict[str, List[Tuple[str, str]]] = {
        "INITIAL_ACCESS": [
            ("brute|failed login",          "Brute force authentication attack detected"),
            ("jndi|log4shell",              "Log4Shell (CVE-2021-44228) exploitation attempt"),
            ("vpn|compromised",             "Compromised credentials used for access"),
        ],
        "EXECUTION": [
            ("powershell",                  "Malicious PowerShell execution detected"),
            ("ldap.*class|class.*ldap",     "Remote class loading via LDAP (RCE)"),
        ],
        "PERSISTENCE": [
            ("schtask|scheduled",           "Malicious scheduled task created"),
            ("registry|run",                "Registry-based persistence established"),
        ],
        "EXFILTRATION": [],
        "IMPACT": [
            ("ransom|encrypt",              "Ransomware: mass file encryption detected"),
            ("vssadmin|shadow",             "Shadow copies deleted (anti-recovery)"),
        ],
    }
    defaults: Dict[str, str] = {
        "LATERAL_MOVEMENT":     "Lateral movement to internal hosts detected",
        "COMMAND_CONTROL":      "Command & control beacon / callback detected",
        "PRIVILEGE_ESCALATION": "Privilege escalation attempt detected",
        "DEFENSE_EVASION":      "Defense evasion technique detected",
        "CREDENTIAL_ACCESS":    "Credential theft / dumping activity",
    }

    if stage == "EXFILTRATION":
        size_match = re.search(r"(\d+\.?\d*\s*[gGmM][bB])", line)
        suffix = f" ({size_match.group(1)})" if size_match else ""
        return f"Data exfiltration to external server{suffix}"

    for keyword, description in descriptions.get(stage, []):
        if re.search(keyword, ll):
            return description

    return defaults.get(stage, line[:80])


def chains_to_json(chains: List[AttackChain]) -> List[Dict]:
    result = []
    for c in chains:
        result.append({
            "chain_id":        c.chain_id,
            "log_source":      c.log_source,
            "severity":        c.severity,
            "duration_minutes": c.duration_minutes,
            "start_time":      c.start_time.isoformat() if c.start_time else None,
            "end_time":        c.end_time.isoformat() if c.end_time else None,
            "total_stages":    c.total_stages,
            "stages_detected": c.stages_detected,
            "source_ips":      c.source_ips,
            "target_ips":      c.target_ips,
            "recommendation":  c.recommendation,
            "events": [
                {
                    "timestamp":        e.timestamp,
                    "kill_chain_stage": e.kill_chain_stage,
                    "mitre_technique":  e.mitre_technique,
                    "mitre_name":       e.mitre_name,
                    "description":      e.description,
                    "severity":         e.severity,
                    "indicators":       e.indicators,
                }
                for e in c.events
            ],
        })
    return result