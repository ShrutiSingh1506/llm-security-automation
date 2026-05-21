"""
Entry point: run LLM analysis on all configured log files.
Usage: python scripts/run_analysis.py
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import DASHBOARD_FILE, LOG_FILES, REPORT_FILE, THREAT_INTEL_DIR, OUTPUT_DIR
from src.analyzer.llm_analyzer import LLMSecurityAnalyzer
from src.dashboard.generator import create_enhanced_dashboard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def build_report(analyses: list) -> dict:
    return {
        "timestamp": datetime.now().isoformat(),
        "total_logs_analyzed": len(analyses),
        "analyses": analyses,
        "summary": {
            "critical": sum(1 for a in analyses if a.get("threat_level") == "CRITICAL"),
            "high":     sum(1 for a in analyses if a.get("threat_level") == "HIGH"),
            "medium":   sum(1 for a in analyses if a.get("threat_level") == "MEDIUM"),
            "low":      sum(1 for a in analyses if a.get("threat_level") == "LOW"),
        },
    }


def main() -> None:
    print("\nLLM Security Log Analyzer\n" + "─" * 40)

    analyzer = LLMSecurityAnalyzer()
    analyzer.load_threat_intelligence(THREAT_INTEL_DIR)

    analyses = []
    for log_path, log_type in LOG_FILES:
        if not log_path.exists():
            logger.warning("Log file not found: %s", log_path)
            continue
        try:
            analysis = analyzer.analyze_log(log_path.read_text(), log_type)
            analyses.append(analysis)
            analyzer.print_analysis(analysis)
        except Exception:
            logger.exception("Failed to analyse %s", log_path)

    report = build_report(analyses)
    REPORT_FILE.write_text(json.dumps(report, indent=2))
    logger.info("Report saved to %s", REPORT_FILE)

    adv_stats = analyzer.adversarial_detector.get_stats()
    analyzer.adversarial_detector.print_stats()

    create_enhanced_dashboard(
        report_file=str(REPORT_FILE),
        output_file=str(DASHBOARD_FILE),
        adversarial_stats=adv_stats,
    )

    summary = report["summary"]
    print(
        f"\nDone — {len(analyses)} logs analysed | "
        f"Critical: {summary['critical']}  High: {summary['high']}  "
        f"Medium: {summary['medium']}  Low: {summary['low']}"
    )


if __name__ == "__main__":
    main()