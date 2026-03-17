"""
Day 5 — Threat Actor Attribution
Usage: python scripts/run_day5.py
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).parent.parent))

from config import ATTACK_CHAINS_FILE, OUTPUT_DIR
from src.attribution.threat_actor import APT_PROFILES, ChainAttribution, ThreatActorAttributor
from src.chains.reconstruction import KILL_CHAIN_STAGES

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

ATTRIBUTION_FILE   = OUTPUT_DIR / "threat_attributions.json"
DASHBOARD_DAY4     = OUTPUT_DIR / "security_dashboard_day4.html"
DASHBOARD_DAY5     = OUTPUT_DIR / "security_dashboard_day5.html"


# ── Dashboard HTML ─────────────────────────────────────────────────────────────

def _confidence_color(confidence: float) -> str:
    if confidence >= 0.75:
        return "#dc3545"
    if confidence >= 0.50:
        return "#fd7e14"
    if confidence >= 0.30:
        return "#ffc107"
    return "#6c757d"


def _confidence_label(confidence: float) -> str:
    if confidence >= 0.75:
        return "HIGH"
    if confidence >= 0.50:
        return "MEDIUM"
    if confidence >= 0.30:
        return "LOW"
    return "INCONCLUSIVE"


def generate_attribution_html(attributions: List[ChainAttribution]) -> str:
    """Generate embeddable HTML for attribution results."""

    # Summary counts
    high_conf   = sum(1 for a in attributions if a.confidence >= 0.75)
    med_conf    = sum(1 for a in attributions if 0.50 <= a.confidence < 0.75)
    unique_apts = list(dict.fromkeys(a.primary_apt for a in attributions))
    avg_conf    = sum(a.confidence for a in attributions) / len(attributions) if attributions else 0

    html = f"""
    <style>
      .attr-card {{
        background: rgba(255,255,255,0.05);
        border-radius: 16px; padding: 24px; margin-bottom: 20px;
        border: 1px solid rgba(255,255,255,0.08);
        box-shadow: 0 4px 20px rgba(0,0,0,0.2);
      }}
      .attr-header {{ display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:16px }}
      .attr-title  {{ font-size:1.05rem; font-weight:700; color:#fff }}
      .attr-meta   {{ font-size:.78rem; color:rgba(255,255,255,0.5); margin-top:4px }}
      .conf-badge  {{ padding:6px 16px; border-radius:20px; font-size:.75rem; font-weight:700; letter-spacing:1px; white-space:nowrap }}
      .apt-name    {{ font-size:1.6rem; font-weight:800; margin:12px 0 4px }}
      .apt-aliases {{ font-size:.75rem; color:rgba(255,255,255,0.5); margin-bottom:12px }}
      .conf-bar-bg {{ background:rgba(255,255,255,0.08); border-radius:8px; height:8px; margin:8px 0 16px }}
      .conf-bar    {{ height:8px; border-radius:8px; transition:width .3s }}
      .reasoning   {{ font-size:.83rem; color:rgba(255,255,255,0.75); line-height:1.6;
                      background:rgba(255,255,255,0.03); border-radius:10px; padding:14px 16px;
                      border-left:3px solid rgba(255,255,255,0.15); margin:12px 0 }}
      .ttp-grid    {{ display:flex; flex-wrap:wrap; gap:6px; margin:10px 0 }}
      .ttp-pill    {{ background:rgba(111,66,193,0.2); border:1px solid rgba(111,66,193,0.3);
                      padding:3px 10px; border-radius:6px; font-size:.72rem; color:#a78bfa; font-family:monospace }}
      .ioc-pill    {{ background:rgba(23,162,184,0.15); border:1px solid rgba(23,162,184,0.3);
                      padding:3px 10px; border-radius:6px; font-size:.72rem; color:#67e8f9; font-family:monospace }}
      .action-list {{ margin:10px 0; padding:0 }}
      .action-item {{ font-size:.82rem; color:rgba(255,255,255,0.8); padding:6px 0;
                      border-bottom:1px solid rgba(255,255,255,0.05); display:flex; gap:10px }}
      .alt-section {{ background:rgba(255,255,255,0.03); border-radius:10px; padding:12px 16px;
                      margin-top:14px; border:1px solid rgba(255,255,255,0.06) }}
      .section-label {{ font-size:.68rem; text-transform:uppercase; letter-spacing:1.5px;
                         color:rgba(255,255,255,0.4); margin-bottom:8px }}
      .apt-profile-row {{ display:flex; gap:16px; flex-wrap:wrap; margin:10px 0 }}
      .profile-item {{ background:rgba(255,255,255,0.04); border-radius:8px; padding:8px 14px;
                        font-size:.75rem; color:rgba(255,255,255,0.6) }}
      .profile-item strong {{ color:rgba(255,255,255,0.9); display:block; margin-bottom:2px }}
    </style>

    <!-- Summary KPI strip -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:16px;margin-bottom:28px">
      <div style="background:rgba(220,53,69,0.15);border:1px solid rgba(220,53,69,0.4);border-radius:16px;padding:20px;text-align:center">
        <div style="font-size:2.2rem;font-weight:800;color:#dc3545">{high_conf}</div>
        <div style="font-size:.72rem;color:rgba(255,255,255,0.6);text-transform:uppercase;letter-spacing:1px;margin-top:6px">High Confidence</div>
      </div>
      <div style="background:rgba(253,126,20,0.15);border:1px solid rgba(253,126,20,0.4);border-radius:16px;padding:20px;text-align:center">
        <div style="font-size:2.2rem;font-weight:800;color:#fd7e14">{med_conf}</div>
        <div style="font-size:.72rem;color:rgba(255,255,255,0.6);text-transform:uppercase;letter-spacing:1px;margin-top:6px">Medium Confidence</div>
      </div>
      <div style="background:rgba(23,162,184,0.15);border:1px solid rgba(23,162,184,0.4);border-radius:16px;padding:20px;text-align:center">
        <div style="font-size:2.2rem;font-weight:800;color:#17a2b8">{len(unique_apts)}</div>
        <div style="font-size:.72rem;color:rgba(255,255,255,0.6);text-transform:uppercase;letter-spacing:1px;margin-top:6px">Unique APT Groups</div>
      </div>
      <div style="background:rgba(111,66,193,0.15);border:1px solid rgba(111,66,193,0.4);border-radius:16px;padding:20px;text-align:center">
        <div style="font-size:2.2rem;font-weight:800;color:#6f42c1">{avg_conf*100:.0f}%</div>
        <div style="font-size:.72rem;color:rgba(255,255,255,0.6);text-transform:uppercase;letter-spacing:1px;margin-top:6px">Avg Confidence</div>
      </div>
    </div>
    """

    for a in attributions:
        color       = _confidence_color(a.confidence)
        label       = _confidence_label(a.confidence)
        profile     = a.apt_profile or {}
        aliases_str = ", ".join(profile.get("aliases", [])[:3])
        bar_width   = int(a.confidence * 100)

        # TTP pills
        ttp_pills = "".join(
            f'<span class="ttp-pill">{t}</span>' for t in a.matching_ttps[:8]
        )
        # IOC pills
        ioc_pills = "".join(
            f'<span class="ioc-pill">{i}</span>' for i in a.matching_iocs[:6]
        )
        # Action items
        action_items = "".join(
            f'<li class="action-item"><span style="color:{color}">→</span> {action}</li>'
            for action in a.recommended_actions[:4]
        )

        html += f"""
        <div class="attr-card" style="border-left:4px solid {color}">
          <div class="attr-header">
            <div>
              <div class="attr-title">🎯 Attribution — {a.log_source}</div>
              <div class="attr-meta">{a.chain_id} &nbsp;|&nbsp; Campaign: {a.campaign_name}</div>
            </div>
            <span class="conf-badge" style="background:{color}20;color:{color};border:1px solid {color}40">
              {label} CONFIDENCE
            </span>
          </div>

          <div class="apt-name" style="color:{color}">{a.primary_apt}</div>
          <div class="apt-aliases">{aliases_str}</div>

          <!-- Confidence bar -->
          <div class="section-label">Confidence Score</div>
          <div style="display:flex;align-items:center;gap:12px">
            <div class="conf-bar-bg" style="flex:1">
              <div class="conf-bar" style="width:{bar_width}%;background:{color}"></div>
            </div>
            <span style="font-size:1.1rem;font-weight:700;color:{color}">{a.confidence*100:.0f}%</span>
          </div>

          <!-- APT Profile -->
          {"" if not profile else f'''
          <div class="apt-profile-row">
            <div class="profile-item"><strong>Origin</strong>{profile.get("origin","")}</div>
            <div class="profile-item"><strong>Sponsor</strong>{profile.get("sponsor","")}</div>
            <div class="profile-item"><strong>Motivation</strong>{profile.get("motivation","")}</div>
            <div class="profile-item"><strong>Active</strong>{profile.get("active","")}</div>
          </div>
          <div style="font-size:.8rem;color:rgba(255,255,255,0.5);margin-bottom:12px">{profile.get("description","")}</div>
          '''}

          <!-- Reasoning -->
          <div class="section-label" style="margin-top:12px">LLM Reasoning</div>
          <div class="reasoning">{a.reasoning}</div>

          <!-- Matching TTPs -->
          {"" if not a.matching_ttps else f'''
          <div class="section-label">Matching MITRE ATT&CK Techniques</div>
          <div class="ttp-grid">{ttp_pills}</div>
          '''}

          <!-- Matching IOCs -->
          {"" if not a.matching_iocs else f'''
          <div class="section-label">Matching IOCs / Signatures</div>
          <div class="ttp-grid">{ioc_pills}</div>
          '''}

          <!-- Recommended Actions -->
          {"" if not a.recommended_actions else f'''
          <div class="section-label" style="margin-top:14px">Recommended Actions</div>
          <ul class="action-list">{action_items}</ul>
          '''}

          <!-- Alternative Attribution -->
          <div class="alt-section">
            <div class="section-label">Alternative Attribution</div>
            <span style="color:rgba(255,255,255,0.7);font-size:.85rem;font-weight:600">{a.alternative_apt}</span>
            <span style="color:rgba(255,255,255,0.4);font-size:.8rem;margin-left:10px">
              {a.alt_confidence*100:.0f}% confidence
            </span>
          </div>
        </div>
        """

    return html


def inject_into_dashboard(
    attributions: List[ChainAttribution],
    source: Path,
    output: Path,
) -> None:
    """Inject attribution section into existing dashboard."""
    attribution_html = generate_attribution_html(attributions)
    unique_apts = list(dict.fromkeys(a.primary_apt for a in attributions))

    section = f"""
    <div style="
        background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
        border-radius: 20px; padding: 30px; margin: 30px 0;
        border: 1px solid rgba(255,255,255,0.1);
        box-shadow: 0 8px 32px rgba(0,0,0,0.3);
    ">
        <h2 style="font-size:1.8rem;font-weight:800;color:#fff;margin-bottom:8px">
            🎯 Threat Actor Attribution
        </h2>
        <p style="color:rgba(255,255,255,0.6);font-size:.9rem;margin-bottom:24px">
            LLM-powered APT attribution across {len(attributions)} chain(s)
            &nbsp;·&nbsp; Identified: {', '.join(unique_apts)}
            &nbsp;·&nbsp; Day 5
        </p>
        {attribution_html}
    </div>
    """

    if source.exists():
        html = source.read_text()
        anchor = '<div class="footer">' if '<div class="footer">' in html else "</body>"
        html = html.replace(anchor, section + "\n" + anchor)
    else:
        logger.warning("Source dashboard not found — writing standalone")
        html = section

    output.write_text(html)
    print(f"\n  Dashboard created : {output}")
    print(f"  Open with        : open {output}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    print("\nDay 5 — Threat Actor Attribution")
    print("─" * 40)

    attributor = ThreatActorAttributor()

    # Load chains from Day 4 output
    chains = attributor.load_chains(ATTACK_CHAINS_FILE)
    if not chains:
        print("\n⚠️  No attack chains found.")
        print(f"   Run scripts/run_day4.py first to generate {ATTACK_CHAINS_FILE}")
        sys.exit(0)

    print(f"\n  Loaded {len(chains)} attack chains — running LLM attribution...\n")

    # Run attribution
    attributions = attributor.attribute_all(chains)

    if not attributions:
        print("\n⚠️  No attributions produced — check your OpenAI API key.")
        sys.exit(0)

    # Save JSON
    attributor.save(attributions, ATTRIBUTION_FILE)

    # Summary table
    print("\n" + "=" * 70)
    print("  ATTRIBUTION SUMMARY")
    print("=" * 70)
    print(f"  {'Source':<22} {'APT Group':<20} {'Confidence':<12} {'Campaign'}")
    print("  " + "-" * 66)
    for a in attributions:
        print(
            f"  {a.log_source:<22} {a.primary_apt:<20} "
            f"{a.confidence*100:.0f}%{'':<9} {a.campaign_name}"
        )
    print("=" * 70)

    # Inject into dashboard
    inject_into_dashboard(attributions, DASHBOARD_DAY4, DASHBOARD_DAY5)

    print("\n✅ Day 5 complete!")
    print(f"  {ATTRIBUTION_FILE}   — structured attribution data")
    print(f"  {DASHBOARD_DAY5}  — dashboard with attribution")
    print(f"\n  Open: open {DASHBOARD_DAY5}")


if __name__ == "__main__":
    main()