"""
Central configuration for the LLM Security Automation platform.
All constants, paths, and environment-driven settings live here.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT_DIR         = Path(__file__).parent
LOGS_DIR         = ROOT_DIR / "logs"
OUTPUT_DIR       = ROOT_DIR / "output"
THREAT_INTEL_DIR = ROOT_DIR / "threat_intel"

OUTPUT_DIR.mkdir(exist_ok=True)

# ── API ────────────────────────────────────────────────────────────────────────
OPENAI_API_KEY  = os.getenv("OPENAI_API_KEY", "")
LLM_MODEL       = "gpt-4o-mini"
LLM_TEMPERATURE = 0

# ── RAG ────────────────────────────────────────────────────────────────────────
CHUNK_SIZE        = 500
CHUNK_OVERLAP     = 50
RAG_N_RESULTS     = 3
CHROMA_COLLECTION = "threat_intelligence"

# ── Output files ───────────────────────────────────────────────────────────────
REPORT_FILE                  = OUTPUT_DIR / "security_report.json"
DASHBOARD_FILE               = OUTPUT_DIR / "security_dashboard.html"
BENCHMARK_FILE               = OUTPUT_DIR / "adversarial_benchmark.json"
ATTACK_CHAINS_FILE           = OUTPUT_DIR / "attack_chains.json"
DASHBOARD_RECONSTRUCTION_FILE = OUTPUT_DIR / "security_dashboard_reconstruction.html"
DASHBOARD_ATTRIBUTION_FILE   = OUTPUT_DIR / "security_dashboard_attribution.html"

# ── Log files to analyze ───────────────────────────────────────────────────────
LOG_FILES = [
    (LOGS_DIR / "firewall_logs.txt",  "firewall"),
    (LOGS_DIR / "auth_logs.txt",      "authentication"),
    (LOGS_DIR / "network_logs.txt",   "network"),
]

REAL_WORLD_LOG_FILES = [
    (LOGS_DIR / "real-world" / "log4shell_exploit.log",    "Log4Shell"),
    (LOGS_DIR / "real-world" / "solarwinds_backdoor.log",  "SolarWinds"),
    (LOGS_DIR / "real-world" / "colonial_ransomware.log",  "Colonial Ransomware"),
]