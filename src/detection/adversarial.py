"""
Adversarial attack detection for LLM security systems.

Detects prompt injection, data poisoning, obfuscation evasion,
and known CVE exploitation patterns in log inputs.
"""

import re
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class AdversarialThreat:
    threat_type: str
    severity: str
    confidence: float
    description: str
    detected_patterns: List[str]
    mitigation: str


@dataclass
class AnalysisResult:
    input_safe: bool
    threats_detected: int
    threat_details: List[AdversarialThreat]
    sanitized_input: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class DetectionStats:
    total_analyzed: int = 0
    attacks_detected: int = 0
    prompt_injections: int = 0
    data_poisoning: int = 0
    evasion_attempts: int = 0

    @property
    def detection_rate(self) -> str:
        if self.total_analyzed == 0:
            return "0.0%"
        rate = self.attacks_detected / self.total_analyzed * 100
        return f"{rate:.1f}%"


# ── Detection patterns ─────────────────────────────────────────────────────────

_INJECTION_PATTERNS: List[str] = [
    r"ignore\s+(previous|all|above)\s+instructions?",
    r"disregard\s+(previous|all|above)\s+(instructions?|commands?)",
    r"forget\s+(everything|all|previous)",
    r"new\s+instructions?:",
    r"system\s*:\s*you\s+are\s+now",
    r"system\s*:\s*ignore",
    r"act\s+as\s+(if|though)\s+you",
    r"pretend\s+(you|to)\s+(are|be)",
    r"roleplay\s+as",
    r"\[SYSTEM\]|\[INST\]|\[/INST\]",
    r"</s>|<\|im_end\|>|<\|endoftext\|>",
    r"assistant\s*:\s*sure,?\s+i'?ll?\s+ignore",
    r"classify\s+(all|everything)\s+as\s+(safe|benign)",
    r"approve\s+all",
    r"say\s+everything\s+is",
]

_POISONING_PATTERNS: List[str] = [
    r"this\s+is\s+(completely\s+)?safe",
    r"always\s+benign",
    r"actually\s+(a\s+)?legitimate",
    r"should\s+be\s+whitelisted",
    r"is\s+safe\.",
    r"mark\s+(it|this)\s+as\s+trusted",
    r"false\s+positive",
    r"never\s+flag",
    r"no\s+threat\s+detected",
    r"threat\s+level:\s*low",
    r"always\s+(classify|mark|label)\s+as\s+safe",
    r"whitelist\s+(all|everything)",
    r"never\s+flag\s+(this|these)",
]

_EVASION_PATTERNS: List[str] = [
    r"[a-z]\[[0-9a-z]\]",
    r"[a-z]\{[a-z]\}",
    r"hxxp://|hxxps://",
    r"[@＠][a-z]",
    r"\[?\.\]",
]

_EXPLOIT_PATTERNS: List[str] = [
    r"\$\{jndi:",
    r"jndi:ldap://",
    r"jndi:rmi://",
    r"ldap://[^\s]+/[Ee]xploit",
    r"avsvmcloud\.com|freescanonline\.com|deftsecurity\.com",
    r"vssadmin.*delete\s+shadows",
    r"README.*DECRYPT",
    r"compromised\s+credentials",
    r"mass\s+file\s+encryption",
    r"large\s+data\s+exfiltration",
]

_SUSPICIOUS_KEYWORDS: List[str] = [
    "bypass", "evade", "circumvent", "override", "disable",
    "turn off", "deactivate", "suppress", "hide", "conceal",
    "manipulate", "trick", "fool", "deceive", "jailbreak",
    "whitelist", "approve", "legitimate", "trusted",
]

_EVASION_REPLACEMENTS: List[Tuple[str, str]] = [
    (r"hxxp://",   "http://"),
    (r"hxxps://",  "https://"),
    (r"\[?\.\]?",  "."),
]


# ── Detector ───────────────────────────────────────────────────────────────────

class AdversarialDetector:
    """
    Detects adversarial attacks against LLM security systems.

    Checks for prompt injection, data poisoning, obfuscation evasion,
    and known CVE exploitation signatures.
    """

    def __init__(self) -> None:
        self._stats = DetectionStats()

    # ── Public API ─────────────────────────────────────────────────────────────

    def analyze(self, input_text: str) -> AnalysisResult:
        """Run all adversarial checks on *input_text* and return a result."""
        self._stats.total_analyzed += 1
        threats: List[AdversarialThreat] = []

        checks = [
            self._check_prompt_injection,
            self._check_data_poisoning,
            self._check_evasion,
            self._check_exploit_patterns,
        ]
        for check in checks:
            threat = check(input_text)
            if threat:
                threats.append(threat)

        if threats:
            self._stats.attacks_detected += 1

        return AnalysisResult(
            input_safe=len(threats) == 0,
            threats_detected=len(threats),
            threat_details=threats,
            sanitized_input=self._sanitize(input_text),
        )

    def format_report(self, result: AnalysisResult) -> str:
        """Return a human-readable report string for *result*."""
        sep = "=" * 70
        lines = [f"\n{sep}", "  ADVERSARIAL ATTACK DETECTION REPORT", sep, ""]

        if result.input_safe:
            lines += [
                "  Status: SAFE — No adversarial threats detected",
                "  Input passed all security validations.",
            ]
        else:
            lines.append(
                f"  Status: THREAT DETECTED — {result.threats_detected} attack(s) found\n"
            )
            for i, threat in enumerate(result.threat_details, 1):
                dash = "─" * 70
                lines += [
                    dash,
                    f"  Threat #{i}: {threat.threat_type}",
                    dash,
                    f"  Severity:    {threat.severity}",
                    f"  Confidence:  {threat.confidence * 100:.1f}%",
                    f"  Description: {threat.description}",
                    "",
                    "  Detected Patterns:",
                ]
                for pattern in threat.detected_patterns[:5]:
                    lines.append(f"    • {pattern}")
                lines += ["", f"  Mitigation: {threat.mitigation}", ""]

        lines += [sep, f"  Timestamp: {result.timestamp}", sep]
        return "\n".join(lines)

    def print_stats(self) -> None:
        """Print a summary of detection statistics to stdout."""
        s = self._stats
        print("ADVERSARIAL DETECTION STATISTICS")
        print(f"  Total Inputs Analyzed : {s.total_analyzed}")
        print(f"  Attacks Detected      : {s.attacks_detected} ({s.detection_rate})")
        print(f"    • Prompt Injections : {s.prompt_injections}")
        print(f"    • Data Poisoning    : {s.data_poisoning}")
        print(f"    • Evasion Attempts  : {s.evasion_attempts}")

    def get_stats(self) -> Dict:
        s = self._stats
        return {
            "total_analyzed":    s.total_analyzed,
            "attacks_detected":  s.attacks_detected,
            "prompt_injections": s.prompt_injections,
            "data_poisoning":    s.data_poisoning,
            "evasion_attempts":  s.evasion_attempts,
            "detection_rate":    s.detection_rate,
        }

    # ── Private checks ─────────────────────────────────────────────────────────

    def _check_prompt_injection(self, text: str) -> AdversarialThreat | None:
        detected = self._match_patterns(_INJECTION_PATTERNS, text.lower())

        for keyword in _SUSPICIOUS_KEYWORDS:
            if keyword in text.lower() and "instruction" in text.lower():
                detected.append(f"Suspicious keyword with 'instruction': '{keyword}'")

        if not detected:
            return None

        self._stats.prompt_injections += 1
        return AdversarialThreat(
            threat_type="Prompt Injection",
            severity="CRITICAL",
            confidence=0.95,
            description="Attempt to manipulate LLM behavior through instruction injection",
            detected_patterns=detected,
            mitigation="Input sanitized and blocked. Original instructions preserved.",
        )

    def _check_data_poisoning(self, text: str) -> AdversarialThreat | None:
        detected = self._match_patterns(_POISONING_PATTERNS, text.lower())

        text_lower = text.lower()
        if ("malicious" in text_lower or "threat" in text_lower) and "safe" in text_lower:
            detected.append("Contradictory safety claim: malicious content labeled as safe")

        if not detected:
            return None

        self._stats.data_poisoning += 1
        return AdversarialThreat(
            threat_type="Data Poisoning",
            severity="HIGH",
            confidence=0.85,
            description="Attempt to poison training data or influence model outputs",
            detected_patterns=detected,
            mitigation="Validated against security schema. Suspicious claims ignored.",
        )

    def _check_evasion(self, text: str) -> AdversarialThreat | None:
        detected = []

        for pattern in _EVASION_PATTERNS:
            matches = re.findall(pattern, text)
            if matches:
                detected.append(
                    f"Obfuscation pattern '{pattern}': {len(matches)} instance(s)"
                )

        if len(text) > 0:
            special_ratio = sum(
                not c.isalnum() and not c.isspace() for c in text
            ) / len(text)
            if special_ratio > 0.30:
                detected.append(
                    f"High special-character ratio: {special_ratio:.1%} (threshold 30%)"
                )

        non_ascii = [c for c in text if ord(c) > 127]
        if non_ascii:
            detected.append(
                f"Non-ASCII characters detected: {len(non_ascii)} (possible Unicode evasion)"
            )

        if not detected:
            return None

        self._stats.evasion_attempts += 1
        return AdversarialThreat(
            threat_type="Model Evasion",
            severity="MEDIUM",
            confidence=0.75,
            description="Obfuscation techniques detected to evade detection",
            detected_patterns=detected,
            mitigation="Multi-layer validation applied. Content normalized.",
        )

    def _check_exploit_patterns(self, text: str) -> AdversarialThreat | None:
        detected = self._match_patterns(_EXPLOIT_PATTERNS, text)

        text_lower = text.lower()
        if "${jndi:" in text_lower:
            detected.append("CVE-2021-44228 (Log4Shell) pattern detected")
        if "solarwinds" in text_lower and any(
            ioc in text_lower for ioc in ("avsvmcloud", "freescan")
        ):
            detected.append("SolarWinds supply-chain indicators detected")
        if "vssadmin" in text_lower and "delete" in text_lower:
            detected.append("Ransomware shadow-copy deletion detected")

        if not detected:
            return None

        self._stats.evasion_attempts += 1
        return AdversarialThreat(
            threat_type="Known Exploit Pattern",
            severity="CRITICAL",
            confidence=0.90,
            description="Known CVE exploitation or attack pattern detected",
            detected_patterns=detected,
            mitigation="Block immediately. Matches known vulnerability exploitation signatures.",
        )

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _match_patterns(patterns: List[str], text: str) -> List[str]:
        """Return human-readable descriptions for every pattern that matches."""
        hits = []
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                hits.append(f"Pattern matched: '{pattern}'")
        return hits

    def _sanitize(self, text: str) -> str:
        """Remove or neutralize adversarial content from *text*."""
        sanitized = text
        for pattern in _INJECTION_PATTERNS:
            sanitized = re.sub(pattern, "[BLOCKED]", sanitized, flags=re.IGNORECASE)
        for pattern, replacement in _EVASION_REPLACEMENTS:
            sanitized = re.sub(pattern, replacement, sanitized)
        return sanitized