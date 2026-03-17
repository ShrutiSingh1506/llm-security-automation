"""
Entry point: run attack chain reconstruction and update the dashboard.
Usage: python scripts/run_day4.py
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import (
    ATTACK_CHAINS_FILE,
    DASHBOARD_DAY4_FILE,
    DASHBOARD_FILE,
    LOG_FILES,
    OUTPUT_DIR,
    REAL_WORLD_LOG_FILES,
)
from src.chains.reconstruction import (
    KILL_CHAIN_STAGES,
    AttackChain,
    AttackChainReconstructor,
    chains_to_json,
)
from src.dashboard.generator import generate_chain_html

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def run_reconstruction() -> List[AttackChain]:
    """Reconstruct attack chains from all configured log files."""
    reconstructor = AttackChainReconstructor()
    all_log_files = list(LOG_FILES) + [
        (p, label) for p, label in REAL_WORLD_LOG_FILES if p.exists()
    ]

    print("\n" + "=" * 70)
    print("  ATTACK CHAIN RECONSTRUCTION ENGINE")
    print("=" * 70)

    chains: List[AttackChain] = []
    for log_path, label in all_log_files:
        if not log_path.exists():
            logger.warning("Skipping %s — file not found", log_path)
            continue
        content = log_path.read_text(errors="ignore")
        chain = reconstructor.reconstruct(content, label)
        if chain.events:
            chains.append(chain)
            reconstructor.print_chain(chain)
        else:
            logger.info("No attack events found in %s", label)

    print("\n" + "=" * 70)
    print(f"  SUMMARY: {len(chains)} chain(s) reconstructed")
    for c in chains:
        dur = f"{c.duration_minutes:.0f}min" if c.duration_minutes else "N/A"
        print(f"    [{c.severity}] {c.log_source} — {c.total_stages} stages, {len(c.events)} events, {dur}")
    print("=" * 70)

    return chains


def save_chains(chains: List[AttackChain]) -> None:
    OUTPUT_DIR.mkdir(exist_ok=True)
    ATTACK_CHAINS_FILE.write_text(json.dumps(chains_to_json(chains), indent=2))
    logger.info("Attack chains saved to %s", ATTACK_CHAINS_FILE)


def update_dashboard(chains: List[AttackChain]) -> None:
    """Inject attack chain HTML into the existing dashboard, matching its visual style."""
    chain_html = generate_chain_html(chains)

    section = f"""
    <!-- ── Day 4: Attack Chain Reconstruction ── -->
    <div style="
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-radius: 20px;
        padding: 30px;
        margin: 30px 0;
        border: 1px solid rgba(255,255,255,0.1);
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    ">
        <h2 style="
            font-size: 1.8rem;
            font-weight: 800;
            color: #ffffff;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 12px;
        ">
            ⚔️ Attack Chain Reconstruction
        </h2>
        <p style="color: rgba(255,255,255,0.6); font-size: 0.9rem; margin-bottom: 24px;">
            Kill chain mapping across {len(chains)} log source(s) · MITRE ATT&CK aligned · Day 4
        </p>

        <!-- Summary KPI row matching original dashboard style -->
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 16px; margin-bottom: 28px;">
            <div style="background: rgba(220,53,69,0.15); border: 1px solid rgba(220,53,69,0.4); border-radius: 16px; padding: 20px; text-align: center;">
                <div style="font-size: 2.2rem; font-weight: 800; color: #dc3545;">{sum(1 for c in chains if c.severity == 'CRITICAL')}</div>
                <div style="font-size: 0.72rem; color: rgba(255,255,255,0.6); text-transform: uppercase; letter-spacing: 1px; margin-top: 6px;">Critical Chains</div>
            </div>
            <div style="background: rgba(253,126,20,0.15); border: 1px solid rgba(253,126,20,0.4); border-radius: 16px; padding: 20px; text-align: center;">
                <div style="font-size: 2.2rem; font-weight: 800; color: #fd7e14;">{len(chains)}</div>
                <div style="font-size: 0.72rem; color: rgba(255,255,255,0.6); text-transform: uppercase; letter-spacing: 1px; margin-top: 6px;">Chains Reconstructed</div>
            </div>
            <div style="background: rgba(23,162,184,0.15); border: 1px solid rgba(23,162,184,0.4); border-radius: 16px; padding: 20px; text-align: center;">
                <div style="font-size: 2.2rem; font-weight: 800; color: #17a2b8;">{sum(len(c.events) for c in chains)}</div>
                <div style="font-size: 0.72rem; color: rgba(255,255,255,0.6); text-transform: uppercase; letter-spacing: 1px; margin-top: 6px;">Attack Events</div>
            </div>
            <div style="background: rgba(40,167,69,0.15); border: 1px solid rgba(40,167,69,0.4); border-radius: 16px; padding: 20px; text-align: center;">
                <div style="font-size: 2.2rem; font-weight: 800; color: #28a745;">{len({s for c in chains for s in c.stages_detected})}</div>
                <div style="font-size: 0.72rem; color: rgba(255,255,255,0.6); text-transform: uppercase; letter-spacing: 1px; margin-top: 6px;">Kill Chain Stages</div>
            </div>
            <div style="background: rgba(111,66,193,0.15); border: 1px solid rgba(111,66,193,0.4); border-radius: 16px; padding: 20px; text-align: center;">
                <div style="font-size: 2.2rem; font-weight: 800; color: #6f42c1;">{len(KILL_CHAIN_STAGES)}</div>
                <div style="font-size: 0.72rem; color: rgba(255,255,255,0.6); text-transform: uppercase; letter-spacing: 1px; margin-top: 6px;">Total Possible Stages</div>
            </div>
        </div>

        <!-- Attack chain cards -->
        {chain_html}
    </div>
    """

    source = Path("output/security_dashboard_enhanced.html")
    if source.exists():
        html = source.read_text()
        # Inject before the footer, matching original dashboard structure
        if '<div class="footer">' in html:
            html = html.replace('<div class="footer">', section + '\n<div class="footer">')
        elif '</body>' in html:
            html = html.replace('</body>', section + '\n</body>')
    else:
        logger.warning("Original dashboard not found — creating standalone")
        html = _standalone_html(chains, section)

    DASHBOARD_DAY4_FILE.write_text(html)
    logger.info("Dashboard saved to %s", DASHBOARD_DAY4_FILE)
    print(f"\n  Dashboard created: {DASHBOARD_DAY4_FILE}")
    print(f"  Open with: open {DASHBOARD_DAY4_FILE}")


def _standalone_html(chains: List[AttackChain], chain_html: str) -> str:
    total_events    = sum(len(c.events) for c in chains)
    critical_chains = sum(1 for c in chains if c.severity == "CRITICAL")
    all_stages      = {s for c in chains for s in c.stages_detected}
    generated       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Attack Chain Reconstruction</title>
<style>
  * {{ box-sizing:border-box; margin:0; padding:0 }}
  body {{ background:#0d0d1a; color:#e0e0e0; font-family:'Segoe UI',system-ui,sans-serif; padding:30px; line-height:1.6 }}
  .header {{ background:linear-gradient(135deg,#1a1a2e,#16213e); border-radius:16px; padding:30px; margin-bottom:30px; border:1px solid rgba(220,53,69,.3) }}
  h1 {{ font-size:1.8rem; color:#fff; margin-bottom:8px }}
  .subtitle {{ color:#888; font-size:.9rem }}
  .stats {{ display:flex; gap:16px; flex-wrap:wrap; margin-top:20px }}
  .stat {{ background:rgba(255,255,255,.05); border-radius:10px; padding:16px 24px; text-align:center; flex:1; min-width:120px; border:1px solid rgba(255,255,255,.08) }}
  .stat-value {{ font-size:2rem; font-weight:bold; color:#dc3545 }}
  .stat-label {{ font-size:.75rem; color:#888; text-transform:uppercase; letter-spacing:1px; margin-top:4px }}
  .footer {{ text-align:center; color:#555; font-size:.8rem; margin-top:40px; padding-top:20px; border-top:1px solid rgba(255,255,255,.05) }}
</style>
</head>
<body>
<div class="header">
  <h1>Attack Chain Reconstruction</h1>
  <div class="subtitle">LLM Security Analyzer &mdash; Day 4 &nbsp;|&nbsp; {generated}</div>
  <div class="stats">
    <div class="stat"><div class="stat-value">{len(chains)}</div><div class="stat-label">Chains</div></div>
    <div class="stat"><div class="stat-value" style="color:#dc3545">{critical_chains}</div><div class="stat-label">Critical</div></div>
    <div class="stat"><div class="stat-value" style="color:#fd7e14">{total_events}</div><div class="stat-label">Events</div></div>
    <div class="stat"><div class="stat-value" style="color:#ffc107">{len(all_stages)}</div><div class="stat-label">Stages Seen</div></div>
    <div class="stat"><div class="stat-value" style="color:#17a2b8">{len(KILL_CHAIN_STAGES)}</div><div class="stat-label">Total Stages</div></div>
  </div>
</div>
{chain_html}
<div class="footer">
  Attack Chain Reconstruction Engine &mdash; LLM Security Analyzer<br>
  <span style="margin-top:6px;display:block">MITRE ATT&CK Framework | Cyber Kill Chain</span>
</div>
</body>
</html>"""


def print_summary_table(chains: List[AttackChain]) -> None:
    print("\n" + "=" * 70)
    print("  ATTACK CHAIN SUMMARY TABLE")
    print("=" * 70)
    print(f"  {'Source':<22} {'Severity':<10} {'Stages':<8} {'Events':<8} {'Duration'}")
    print("  " + "-" * 60)
    for c in chains:
        dur = f"{c.duration_minutes:.0f}min" if c.duration_minutes else "N/A"
        print(f"  {c.log_source:<22} {c.severity:<10} {c.total_stages:<8} {len(c.events):<8} {dur}")
    print("=" * 70)


def main() -> None:
    print("\nDay 4 — Attack Chain Reconstruction")
    print("─" * 40)

    chains = run_reconstruction()
    if not chains:
        logger.warning("No attack chains found — check your log files in logs/")
        sys.exit(0)

    print_summary_table(chains)
    save_chains(chains)
    update_dashboard(chains)

    print("\n✅ Day 4 complete!")
    print(f"  {ATTACK_CHAINS_FILE}  — structured chain data")
    print(f"  {DASHBOARD_DAY4_FILE}  — dashboard with attack chains")
    print(f"\n  Open: open {DASHBOARD_DAY4_FILE}")


if __name__ == "__main__":
    main()
