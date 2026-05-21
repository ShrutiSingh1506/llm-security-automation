"""
Security Analysis Dashboard Generator
"""

import json
import os
from collections import Counter
from datetime import datetime

import plotly.graph_objects as go
from plotly.subplots import make_subplots

from src.chains.reconstruction import KILL_CHAIN_STAGES, AttackChain


# ── Shared helpers ─────────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH":     "#fd7e14",
    "MEDIUM":   "#ffc107",
    "LOW":      "#28a745",
    "UNKNOWN":  "#6c757d",
}

_CONFIDENCE_COLOR = lambda c: (
    "#dc3545" if c >= 0.75 else
    "#fd7e14" if c >= 0.50 else
    "#ffc107" if c >= 0.30 else
    "#6c757d"
)

_CONFIDENCE_LABEL = lambda c: (
    "HIGH" if c >= 0.75 else
    "MEDIUM" if c >= 0.50 else
    "LOW" if c >= 0.30 else
    "INCONCLUSIVE"
)

_BASE_CSS = """
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0d0d1a;
    color: #e0e0e0;
    line-height: 1.6;
}
.page { max-width: 1400px; margin: 0 auto; padding: 32px 24px; }
.section {
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    border-radius: 16px;
    padding: 28px;
    margin-bottom: 28px;
    border: 1px solid rgba(255,255,255,0.08);
    box-shadow: 0 4px 24px rgba(0,0,0,0.3);
}
.section-title {
    font-size: 1.4rem;
    font-weight: 700;
    color: #fff;
    margin-bottom: 20px;
    padding-bottom: 12px;
    border-bottom: 1px solid rgba(255,255,255,0.1);
}
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
}
.kpi {
    border-radius: 12px;
    padding: 20px;
    text-align: center;
    border: 1px solid rgba(255,255,255,0.08);
}
.kpi-value { font-size: 2rem; font-weight: 800; margin-bottom: 6px; }
.kpi-label { font-size: .72rem; color: rgba(255,255,255,0.55); text-transform: uppercase; letter-spacing: 1px; }
.finding-card {
    background: rgba(255,255,255,0.03);
    border-radius: 12px;
    padding: 20px;
    margin-bottom: 16px;
    border-left: 4px solid #444;
    border: 1px solid rgba(255,255,255,0.06);
}
.badge {
    display: inline-block;
    padding: 4px 14px;
    border-radius: 20px;
    font-size: .72rem;
    font-weight: 700;
    letter-spacing: 1px;
}
.ioc-box {
    background: rgba(0,0,0,0.3);
    border-radius: 8px;
    padding: 14px;
    margin-top: 12px;
    font-family: monospace;
    font-size: .78rem;
    color: #a5d6a7;
    line-height: 1.8;
    border: 1px solid rgba(255,255,255,0.06);
}
.chain-card {
    background: rgba(255,255,255,0.03);
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 18px;
    border: 1px solid rgba(255,255,255,0.07);
}
.chain-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; }
.chain-title  { font-size: 1rem; font-weight: 700; color: #fff; }
.chain-meta   { font-size: .75rem; color: rgba(255,255,255,0.4); margin-top: 4px; font-family: monospace; }
.stat-pill {
    display: inline-block;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 20px;
    padding: 3px 12px;
    font-size: .72rem;
    color: rgba(255,255,255,0.55);
    margin: 0 4px 6px 0;
}
.stage-bar { display: flex; flex-wrap: wrap; gap: 4px; margin: 10px 0 16px; }
.stage-dot {
    padding: 3px 9px;
    border-radius: 5px;
    font-size: .62rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .5px;
}
.timeline { position: relative; padding-left: 28px; }
.timeline::before {
    content: '';
    position: absolute;
    left: 8px; top: 0; bottom: 0;
    width: 2px;
    background: linear-gradient(to bottom, rgba(220,53,69,0.7), rgba(108,117,125,0.15));
    border-radius: 2px;
}
.tl-event {
    position: relative;
    margin-bottom: 14px;
    padding: 12px 14px;
    background: rgba(255,255,255,0.03);
    border-radius: 10px;
    border: 1px solid rgba(255,255,255,0.05);
    border-left: 3px solid #444;
}
.tl-event::before {
    content: '';
    position: absolute;
    left: -23px; top: 14px;
    width: 10px; height: 10px;
    border-radius: 50%;
    background: #dc3545;
    border: 2px solid #0d0d1a;
    box-shadow: 0 0 8px rgba(220,53,69,0.4);
}
.ev-stage  { font-size: .66rem; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; }
.ev-time   { font-size: .7rem; color: rgba(255,255,255,0.35); font-family: monospace; }
.ev-desc   { font-size: .83rem; color: rgba(255,255,255,0.82); margin: 5px 0; }
.ev-mitre  {
    display: inline-block;
    background: rgba(111,66,193,0.18);
    border: 1px solid rgba(111,66,193,0.3);
    padding: 2px 10px; border-radius: 6px;
    font-size: .68rem; color: #a78bfa; font-family: monospace;
}
.ev-iocs   { font-size: .7rem; color: rgba(255,255,255,0.35); margin-top: 5px; }
.time-gap  { text-align: center; color: rgba(255,255,255,0.2); font-size: .7rem; padding: 4px 0; font-style: italic; }
.chain-rec {
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 10px;
    padding: 12px 16px;
    margin-top: 14px;
    font-size: .82rem;
    color: rgba(255,255,255,0.75);
}
.attr-card {
    background: rgba(255,255,255,0.03);
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 18px;
    border: 1px solid rgba(255,255,255,0.07);
}
.attr-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 14px; }
.attr-title  { font-size: 1rem; font-weight: 700; color: #fff; }
.attr-meta   { font-size: .75rem; color: rgba(255,255,255,0.4); margin-top: 4px; }
.apt-name    { font-size: 1.5rem; font-weight: 800; margin: 10px 0 4px; }
.apt-aliases { font-size: .72rem; color: rgba(255,255,255,0.4); margin-bottom: 10px; }
.conf-bar-bg { background: rgba(255,255,255,0.07); border-radius: 6px; height: 7px; margin: 6px 0 14px; }
.conf-bar    { height: 7px; border-radius: 6px; }
.reasoning   {
    font-size: .82rem;
    color: rgba(255,255,255,0.72);
    line-height: 1.6;
    background: rgba(255,255,255,0.03);
    border-radius: 8px;
    padding: 12px 14px;
    border-left: 3px solid rgba(255,255,255,0.12);
    margin: 10px 0;
}
.ttp-pill {
    display: inline-block;
    background: rgba(111,66,193,0.18);
    border: 1px solid rgba(111,66,193,0.28);
    padding: 2px 10px; border-radius: 5px;
    font-size: .68rem; color: #a78bfa; font-family: monospace;
    margin: 2px 3px;
}
.ioc-pill {
    display: inline-block;
    background: rgba(23,162,184,0.15);
    border: 1px solid rgba(23,162,184,0.28);
    padding: 2px 10px; border-radius: 5px;
    font-size: .68rem; color: #67e8f9; font-family: monospace;
    margin: 2px 3px;
}
.section-label {
    font-size: .65rem;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    color: rgba(255,255,255,0.35);
    margin: 12px 0 6px;
}
.alt-section {
    background: rgba(255,255,255,0.02);
    border-radius: 8px;
    padding: 10px 14px;
    margin-top: 12px;
    border: 1px solid rgba(255,255,255,0.05);
}
.profile-row { display: flex; gap: 12px; flex-wrap: wrap; margin: 8px 0; }
.profile-item {
    background: rgba(255,255,255,0.04);
    border-radius: 7px;
    padding: 7px 12px;
    font-size: .72rem;
    color: rgba(255,255,255,0.55);
}
.profile-item strong { color: rgba(255,255,255,0.85); display: block; margin-bottom: 1px; }
.footer {
    text-align: center;
    color: rgba(255,255,255,0.35);
    font-size: .78rem;
    padding: 24px;
    border-top: 1px solid rgba(255,255,255,0.06);
    margin-top: 32px;
}
</style>
"""


# ── Log analysis dashboard ─────────────────────────────────────────────────────

def create_enhanced_dashboard(
    report_file: str = "output/security_report.json",
    output_file: str = "output/security_dashboard.html",
    adversarial_stats: dict = None,
    benchmark_file: str = "output/adversarial_benchmark.json",
) -> None:
    with open(report_file) as f:
        report = json.load(f)

    analyses = report.get("analyses", [])

    threat_levels   = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    attack_types    = {}
    mitre_techniques = {}
    all_ips, all_domains, all_hashes = [], [], []

    for a in analyses:
        lvl = a.get("threat_level", "UNKNOWN")
        if lvl in threat_levels:
            threat_levels[lvl] += 1
        at = a.get("attack_type", "Unknown")
        attack_types[at] = attack_types.get(at, 0) + 1
        for t in a.get("mitre_technique", "").split(","):
            t = t.strip()
            if t and t != "Unknown":
                mitre_techniques[t] = mitre_techniques.get(t, 0) + 1
        iocs = a.get("extracted_iocs", {})
        all_ips.extend(iocs.get("ips", []))
        all_domains.extend(iocs.get("domains", []))
        all_hashes.extend(iocs.get("file_hashes", []))

    if adversarial_stats is None:
        adversarial_stats = {"total_analyzed": 0, "attacks_detected": 0,
                             "prompt_injections": 0, "data_poisoning": 0,
                             "evasion_attempts": 0, "detection_rate": "0%"}

    ip_counts     = Counter(all_ips)
    domain_counts = Counter(all_domains)
    unique_ips    = len(set(all_ips))
    unique_domains = len(set(all_domains))
    unique_hashes  = len(set(all_hashes))
    total_iocs     = unique_ips + unique_domains + unique_hashes
    top_ips        = ip_counts.most_common(8)
    top_domains    = domain_counts.most_common(8)

    # Plotly charts
    fig = make_subplots(
        rows=3, cols=2,
        subplot_titles=(
            "Threat Level Distribution",
            "Attack Type Breakdown",
            "MITRE ATT&CK Techniques",
            "Top Suspicious IPs",
            "Top Malicious Domains",
            "IOC Category Distribution",
        ),
        specs=[
            [{"type": "pie"}, {"type": "bar"}],
            [{"type": "bar"}, {"type": "bar"}],
            [{"type": "bar"}, {"type": "pie"}],
        ],
        vertical_spacing=0.12,
        horizontal_spacing=0.1,
    )

    threat_colors = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14", "MEDIUM": "#ffc107", "LOW": "#28a745"}
    fig.add_trace(go.Pie(
        labels=list(threat_levels.keys()),
        values=list(threat_levels.values()),
        marker=dict(colors=[threat_colors[k] for k in threat_levels], line=dict(color="#0d0d1a", width=2)),
        hole=0.4, textposition="inside", textinfo="label+percent",
    ), row=1, col=1)

    fig.add_trace(go.Bar(
        x=list(attack_types.keys()), y=list(attack_types.values()),
        marker=dict(color=list(attack_types.values()), colorscale="Blues", showscale=False),
        text=list(attack_types.values()), textposition="outside",
    ), row=1, col=2)

    if mitre_techniques:
        mt = dict(sorted(mitre_techniques.items(), key=lambda x: x[1], reverse=True)[:6])
        fig.add_trace(go.Bar(
            y=list(mt.keys()), x=list(mt.values()), orientation="h",
            marker=dict(color=list(mt.values()), colorscale="Purples", showscale=False),
            text=list(mt.values()), textposition="outside",
        ), row=2, col=1)

    if top_ips:
        fig.add_trace(go.Bar(
            x=[i[0] for i in top_ips], y=[i[1] for i in top_ips],
            marker=dict(color=[i[1] for i in top_ips], colorscale="Reds", showscale=False),
            text=[i[1] for i in top_ips], textposition="outside",
        ), row=2, col=2)

    if top_domains:
        dl = [d[0][:28] + "..." if len(d[0]) > 28 else d[0] for d in top_domains]
        fig.add_trace(go.Bar(
            x=dl, y=[d[1] for d in top_domains],
            marker=dict(color=[d[1] for d in top_domains], colorscale="Oranges", showscale=False),
            text=[d[1] for d in top_domains], textposition="outside",
        ), row=3, col=1)

    fig.add_trace(go.Pie(
        labels=["IP Addresses", "Domains", "File Hashes"],
        values=[unique_ips, unique_domains, unique_hashes],
        marker=dict(colors=["#1e88e5", "#43a047", "#fb8c00"], line=dict(color="#0d0d1a", width=2)),
        hole=0.3, textposition="inside", textinfo="label+value",
    ), row=3, col=2)

    fig.update_layout(
        height=1300, template="plotly_dark",
        paper_bgcolor="#16213e", plot_bgcolor="#1a1a2e",
        font=dict(family="Segoe UI, sans-serif", size=12, color="#e0e0e0"),
        showlegend=False,
        title=dict(
            text="Security Analysis - Threat Intelligence Overview",
            x=0.5, xanchor="center",
            font=dict(size=20, color="#fff"),
        ),
    )
    fig.update_xaxes(showgrid=True, gridcolor="rgba(255,255,255,0.06)")
    fig.update_yaxes(showgrid=True, gridcolor="rgba(255,255,255,0.06)")

    # KPI cards
    def kpi(color, value, label):
        return (
            f'<div class="kpi" style="background:rgba({_hex_to_rgb(color)},0.12);'
            f'border-color:rgba({_hex_to_rgb(color)},0.3)">'
            f'<div class="kpi-value" style="color:{color}">{value}</div>'
            f'<div class="kpi-label">{label}</div></div>'
        )

    kpis = "".join([
        kpi("#dc3545", report["summary"]["critical"],          "Critical Threats"),
        kpi("#fd7e14", report["summary"]["high"],              "High Threats"),
        kpi("#1e88e5", unique_ips,                             "Unique IPs"),
        kpi("#43a047", unique_domains,                         "Domains"),
        kpi("#fb8c00", unique_hashes,                          "File Hashes"),
        kpi("#ab47bc", total_iocs,                             "Total IOCs"),
        kpi("#dc3545", adversarial_stats["attacks_detected"],  "AI Attacks Blocked"),
        kpi("#43a047", adversarial_stats["detection_rate"],    "Detection Rate"),
    ])

    # Findings
    findings_html = ""
    for i, a in enumerate(analyses, 1):
        lvl   = a.get("threat_level", "UNKNOWN")
        color = _SEVERITY_COLORS.get(lvl, "#6c757d")
        iocs  = a.get("extracted_iocs", {})
        ioc_block = ""
        if iocs.get("ips") or iocs.get("domains") or iocs.get("file_hashes"):
            ioc_block = '<div class="ioc-box">'
            if iocs.get("ips"):
                ioc_block += f'<strong style="color:#81c784">IPs:</strong> {", ".join(iocs["ips"][:10])}<br>'
            if iocs.get("domains"):
                ioc_block += f'<strong style="color:#81c784">Domains:</strong> {", ".join(iocs["domains"][:10])}<br>'
            if iocs.get("file_hashes"):
                ioc_block += f'<strong style="color:#81c784">Hashes:</strong> {", ".join(iocs["file_hashes"][:5])}'
            ioc_block += "</div>"

        findings_html += f"""
        <div class="finding-card" style="border-left-color:{color}">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
            <span style="font-weight:700;color:#fff">Finding {i} - {a.get("attack_type","Unknown Attack")}</span>
            <span class="badge" style="background:rgba({_hex_to_rgb(color)},0.15);color:{color};border:1px solid rgba({_hex_to_rgb(color)},0.35)">{lvl}</span>
          </div>
          <div style="font-size:.82rem;color:rgba(255,255,255,0.6);margin-bottom:6px">
            <strong style="color:rgba(255,255,255,0.8)">MITRE ATT&CK:</strong> {a.get("mitre_technique","N/A")}
          </div>
          <div style="font-size:.85rem;color:rgba(255,255,255,0.75);margin-bottom:6px">
            <strong style="color:rgba(255,255,255,0.8)">Summary:</strong> {a.get("summary","N/A")}
          </div>
          <div style="font-size:.82rem;color:rgba(255,255,255,0.65)">
            <strong style="color:rgba(255,255,255,0.8)">Remediation:</strong> {a.get("remediation","N/A")}
          </div>
          {ioc_block}
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LLM Security Analysis Dashboard</title>
{_BASE_CSS}
</head>
<body>
<div class="page">

  <div style="text-align:center;padding:40px 0 32px">
    <div style="font-size:2rem;font-weight:900;color:#fff;letter-spacing:-0.5px">
      LLM Security Operations Platform
    </div>
    <div style="color:rgba(255,255,255,0.45);margin-top:6px;font-size:.9rem">
      Generated {datetime.now().strftime("%B %d, %Y at %I:%M %p")}
    </div>
  </div>

  <div class="section">
    <div class="section-title">Overview</div>
    <div class="kpi-grid">{kpis}</div>
    <div style="font-size:.8rem;color:rgba(255,255,255,0.35);margin-top:4px">
      Adversarial inputs blocked: {adversarial_stats["prompt_injections"]} prompt injections,
      {adversarial_stats["data_poisoning"]} data poisoning attempts,
      {adversarial_stats["evasion_attempts"]} evasion techniques
    </div>
  </div>

  <div class="section">
    <div class="section-title">Threat Intelligence Charts</div>
    <div id="charts"></div>
  </div>

  <div class="section">
    <div class="section-title">Security Findings</div>
    {findings_html}
  </div>

  <div class="footer">
    LLM Security Operations Platform - Python / OpenAI / LangChain / ChromaDB / MITRE ATT&CK
  </div>
</div>
<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
<script>
var d = {fig.to_json()};
Plotly.newPlot("charts", d.data, d.layout, {{responsive:true}});
</script>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w") as f:
        f.write(html)

    print(f"\nDashboard created: {output_file}")
    print(f"  Logs analysed : {report['total_logs_analyzed']}")
    print(f"  Critical      : {report['summary']['critical']}")
    print(f"  High          : {report['summary']['high']}")
    print(f"  IOCs          : {total_iocs}")
    print(f"  AI blocked    : {adversarial_stats['attacks_detected']}")


# ── Attack chain HTML ──────────────────────────────────────────────────────────

def generate_chain_html(chains: list) -> str:
    parts = ["<div>"]

    for chain in chains:
        color = _SEVERITY_COLORS.get(chain.severity, "#6c757d")
        dur   = f"{chain.duration_minutes:.0f} min" if chain.duration_minutes is not None else "N/A"
        start = chain.start_time.strftime("%Y-%m-%d %H:%M:%S") if chain.start_time else "Unknown"
        end   = chain.end_time.strftime("%H:%M:%S") if chain.end_time else "Unknown"
        srcs  = ", ".join(chain.source_ips[:3]) or "Unknown"

        stage_pills = []
        for stage_name, info in KILL_CHAIN_STAGES.items():
            if stage_name in chain.stages_detected:
                stage_pills.append(
                    f'<span class="stage-dot" style="background:rgba({_hex_to_rgb(info["color"])},0.18);'
                    f'color:{info["color"]};border:1px solid rgba({_hex_to_rgb(info["color"])},0.35)">'
                    f'{info["emoji"]} {stage_name.replace("_"," ")}</span>'
                )
            else:
                stage_pills.append(
                    f'<span class="stage-dot" style="background:rgba(255,255,255,0.03);color:#444">'
                    f'{stage_name.replace("_"," ")}</span>'
                )

        parts.append(f"""
        <div class="chain-card" style="border-left:4px solid {color}">
          <div class="chain-header">
            <div>
              <div class="chain-title">Attack Chain - {chain.log_source}</div>
              <div class="chain-meta">{chain.chain_id} | {start} to {end} | {dur}</div>
            </div>
            <span class="badge" style="background:rgba({_hex_to_rgb(color)},0.15);color:{color};border:1px solid rgba({_hex_to_rgb(color)},0.35)">
              {chain.severity}
            </span>
          </div>
          <div>
            <span class="stat-pill">{chain.total_stages}/{len(KILL_CHAIN_STAGES)} stages</span>
            <span class="stat-pill">Sources: {srcs}</span>
            <span class="stat-pill">{len(chain.events)} events</span>
          </div>
          <div class="stage-bar">{"".join(stage_pills)}</div>
          <div class="timeline">""")

        prev_ts = None
        for event in chain.events:
            info    = KILL_CHAIN_STAGES.get(event.kill_chain_stage, {"color": "#888", "emoji": "?"})
            color_e = info["color"]
            if prev_ts and event.raw_timestamp and event.raw_timestamp != prev_ts:
                gap = (event.raw_timestamp - prev_ts).total_seconds() / 60
                if gap > 0:
                    parts.append(f'<div class="time-gap">{gap:.0f} min</div>')
            iocs_html = (
                f'<div class="ev-iocs">IOCs: {", ".join(event.indicators[:4])}</div>'
                if event.indicators else ""
            )
            parts.append(f"""
            <div class="tl-event" style="border-left-color:{color_e}">
              <div style="display:flex;justify-content:space-between;align-items:flex-start">
                <span class="ev-stage" style="color:{color_e}">{info["emoji"]} {event.kill_chain_stage.replace("_"," ")}</span>
                <span class="ev-time">{event.timestamp}</span>
              </div>
              <div class="ev-desc">{event.description}</div>
              <span class="ev-mitre">{event.mitre_technique} - {event.mitre_name}</span>
              {iocs_html}
            </div>""")
            prev_ts = event.raw_timestamp

        parts.append(f"""
          </div>
          <div class="chain-rec">{chain.recommendation}</div>
        </div>""")

    parts.append("</div>")
    return "".join(parts)


# ── Attribution HTML ───────────────────────────────────────────────────────────

def generate_attribution_html(attributions: list) -> str:
    if not attributions:
        return '<p style="color:rgba(255,255,255,0.4)">No attributions available.</p>'

    high_conf   = sum(1 for a in attributions if a.confidence >= 0.75)
    med_conf    = sum(1 for a in attributions if 0.50 <= a.confidence < 0.75)
    unique_apts = list(dict.fromkeys(a.primary_apt for a in attributions))
    avg_conf    = sum(a.confidence for a in attributions) / len(attributions)

    def kc(color, value, label):
        return (
            f'<div class="kpi" style="background:rgba({_hex_to_rgb(color)},0.12);'
            f'border-color:rgba({_hex_to_rgb(color)},0.3)">'
            f'<div class="kpi-value" style="color:{color}">{value}</div>'
            f'<div class="kpi-label">{label}</div></div>'
        )

    kpis = "".join([
        kc("#dc3545", high_conf,            "High Confidence"),
        kc("#fd7e14", med_conf,             "Medium Confidence"),
        kc("#17a2b8", len(unique_apts),     "Unique APT Groups"),
        kc("#6f42c1", f"{avg_conf*100:.0f}%", "Avg Confidence"),
    ])

    cards = ""
    for a in attributions:
        color    = _CONFIDENCE_COLOR(a.confidence)
        label    = _CONFIDENCE_LABEL(a.confidence)
        profile  = a.apt_profile or {}
        aliases  = ", ".join(profile.get("aliases", [])[:3])
        bar_w    = int(a.confidence * 100)

        ttp_pills = "".join(f'<span class="ttp-pill">{t}</span>' for t in a.matching_ttps[:8])
        ioc_pills = "".join(f'<span class="ioc-pill">{i}</span>' for i in a.matching_iocs[:6])
        actions   = "".join(
            f'<div style="font-size:.8rem;color:rgba(255,255,255,0.75);padding:5px 0;'
            f'border-bottom:1px solid rgba(255,255,255,0.05)">'
            f'<span style="color:{color}">-</span> {act}</div>'
            for act in a.recommended_actions[:4]
        )

        profile_items = ""
        if profile:
            for key in ("origin", "sponsor", "motivation", "active"):
                if profile.get(key):
                    profile_items += (
                        f'<div class="profile-item">'
                        f'<strong>{key.capitalize()}</strong>{profile[key]}</div>'
                    )

        cards += f"""
        <div class="attr-card" style="border-left:4px solid {color}">
          <div class="attr-header">
            <div>
              <div class="attr-title">Attribution - {a.log_source}</div>
              <div class="attr-meta">{a.chain_id} | Campaign: {a.campaign_name}</div>
            </div>
            <span class="badge" style="background:rgba({_hex_to_rgb(color)},0.15);color:{color};border:1px solid rgba({_hex_to_rgb(color)},0.35)">
              {label} CONFIDENCE
            </span>
          </div>
          <div class="apt-name" style="color:{color}">{a.primary_apt}</div>
          <div class="apt-aliases">{aliases}</div>
          <div class="section-label">Confidence</div>
          <div style="display:flex;align-items:center;gap:12px">
            <div class="conf-bar-bg" style="flex:1">
              <div class="conf-bar" style="width:{bar_w}%;background:{color}"></div>
            </div>
            <span style="font-size:1rem;font-weight:700;color:{color}">{a.confidence*100:.0f}%</span>
          </div>
          {"<div class='profile-row'>" + profile_items + "</div>" if profile_items else ""}
          {"<div style='font-size:.78rem;color:rgba(255,255,255,0.4);margin-bottom:10px'>" + profile.get("description","") + "</div>" if profile.get("description") else ""}
          <div class="section-label">LLM Reasoning</div>
          <div class="reasoning">{a.reasoning}</div>
          {"<div class='section-label'>MITRE ATT&CK</div><div style='margin:6px 0'>" + ttp_pills + "</div>" if a.matching_ttps else ""}
          {"<div class='section-label'>Matching IOCs</div><div style='margin:6px 0'>" + ioc_pills + "</div>" if a.matching_iocs else ""}
          {"<div class='section-label'>Recommended Actions</div>" + actions if actions else ""}
          <div class="alt-section">
            <span style="color:rgba(255,255,255,0.65);font-size:.83rem;font-weight:600">{a.alternative_apt}</span>
            <span style="color:rgba(255,255,255,0.35);font-size:.78rem;margin-left:10px">{a.alt_confidence*100:.0f}% confidence (alternative)</span>
          </div>
        </div>"""

    return f'<div class="kpi-grid">{kpis}</div>{cards}'


# ── Consolidated pipeline dashboard ───────────────────────────────────────────

def create_pipeline_dashboard(
    report_file: str,
    adversarial_stats: dict,
    chains: list,
    attributions: list,
    output_file: str,
) -> None:
    """Single consolidated dashboard covering all 4 pipeline stages."""

    with open(report_file) as f:
        report = json.load(f)

    analyses       = report.get("analyses", [])
    all_ips, all_domains, all_hashes = [], [], []
    threat_levels  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    attack_types   = {}
    mitre_techniques = {}

    for a in analyses:
        lvl = a.get("threat_level", "UNKNOWN")
        if lvl in threat_levels:
            threat_levels[lvl] += 1
        at = a.get("attack_type", "Unknown")
        attack_types[at] = attack_types.get(at, 0) + 1
        for t in a.get("mitre_technique", "").split(","):
            t = t.strip()
            if t and t != "Unknown":
                mitre_techniques[t] = mitre_techniques.get(t, 0) + 1
        iocs = a.get("extracted_iocs", {})
        all_ips.extend(iocs.get("ips", []))
        all_domains.extend(iocs.get("domains", []))
        all_hashes.extend(iocs.get("file_hashes", []))

    unique_ips     = len(set(all_ips))
    unique_domains = len(set(all_domains))
    unique_hashes  = len(set(all_hashes))
    total_iocs     = unique_ips + unique_domains + unique_hashes

    if adversarial_stats is None:
        adversarial_stats = {"total_analyzed": 0, "attacks_detected": 0,
                             "prompt_injections": 0, "data_poisoning": 0,
                             "evasion_attempts": 0, "detection_rate": "0%"}

    def kpi(color, value, label):
        return (
            f'<div class="kpi" style="background:rgba({_hex_to_rgb(color)},0.12);'
            f'border-color:rgba({_hex_to_rgb(color)},0.3)">'
            f'<div class="kpi-value" style="color:{color}">{value}</div>'
            f'<div class="kpi-label">{label}</div></div>'
        )

    critical_chains = sum(1 for c in chains if c.severity == "CRITICAL")
    high_attr       = sum(1 for a in attributions if a.confidence >= 0.75)

    kpis = "".join([
        kpi("#dc3545", report["summary"]["critical"],          "Critical Threats"),
        kpi("#fd7e14", report["summary"]["high"],              "High Threats"),
        kpi("#1e88e5", unique_ips,                             "Unique IPs"),
        kpi("#17a2b8", unique_domains,                         "Domains"),
        kpi("#dc3545", adversarial_stats["attacks_detected"],  "AI Attacks Blocked"),
        kpi("#43a047", adversarial_stats["detection_rate"],    "Detection Rate"),
        kpi("#fd7e14", critical_chains,                        "Critical Chains"),
        kpi("#6f42c1", high_attr,                              "High-Conf Attributions"),
    ])

    # Findings
    findings_html = ""
    for i, a in enumerate(analyses, 1):
        lvl   = a.get("threat_level", "UNKNOWN")
        color = _SEVERITY_COLORS.get(lvl, "#6c757d")
        iocs  = a.get("extracted_iocs", {})
        ioc_block = ""
        if iocs.get("ips") or iocs.get("domains"):
            ioc_block = '<div class="ioc-box">'
            if iocs.get("ips"):
                ioc_block += f'<strong style="color:#81c784">IPs:</strong> {", ".join(iocs["ips"][:10])}<br>'
            if iocs.get("domains"):
                ioc_block += f'<strong style="color:#81c784">Domains:</strong> {", ".join(iocs["domains"][:10])}'
            ioc_block += "</div>"

        findings_html += f"""
        <div class="finding-card" style="border-left-color:{color}">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px">
            <span style="font-weight:700;color:#fff">Finding {i} - {a.get("attack_type","Unknown")}</span>
            <span class="badge" style="background:rgba({_hex_to_rgb(color)},0.15);color:{color};border:1px solid rgba({_hex_to_rgb(color)},0.35)">{lvl}</span>
          </div>
          <div style="font-size:.8rem;color:rgba(255,255,255,0.55);margin-bottom:4px">MITRE: {a.get("mitre_technique","N/A")}</div>
          <div style="font-size:.83rem;color:rgba(255,255,255,0.72);margin-bottom:4px">{a.get("summary","N/A")}</div>
          <div style="font-size:.8rem;color:rgba(255,255,255,0.5)">{a.get("remediation","N/A")}</div>
          {ioc_block}
        </div>"""

    chain_html       = generate_chain_html(chains)
    attribution_html = generate_attribution_html(attributions)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>LLM Security Platform - Pipeline Results</title>
{_BASE_CSS}
</head>
<body>
<div class="page">

  <div style="text-align:center;padding:40px 0 32px">
    <div style="font-size:2rem;font-weight:900;color:#fff;letter-spacing:-0.5px">
      LLM Security Operations Platform
    </div>
    <div style="color:rgba(255,255,255,0.4);margin-top:6px;font-size:.88rem">
      Full pipeline results - {datetime.now().strftime("%B %d, %Y at %I:%M %p")}
    </div>
  </div>

  <!-- Stage 1: Overview -->
  <div class="section">
    <div class="section-title">Pipeline Summary</div>
    <div class="kpi-grid">{kpis}</div>
    <div style="font-size:.78rem;color:rgba(255,255,255,0.3);margin-top:4px">
      Adversarial inputs blocked: {adversarial_stats["prompt_injections"]} prompt injections,
      {adversarial_stats["data_poisoning"]} data poisoning,
      {adversarial_stats["evasion_attempts"]} evasion techniques
    </div>
  </div>

  <!-- Stage 2: Log Analysis Findings -->
  <div class="section">
    <div class="section-title">Log Analysis Findings</div>
    {findings_html}
  </div>

  <!-- Stage 3: Attack Chain Reconstruction -->
  <div class="section">
    <div class="section-title">Attack Chain Reconstruction</div>
    <div style="color:rgba(255,255,255,0.45);font-size:.83rem;margin-bottom:20px">
      {len(chains)} chain(s) reconstructed across {len(set(c.log_source for c in chains))} log sources
    </div>
    {chain_html}
  </div>

  <!-- Stage 4: Threat Actor Attribution -->
  <div class="section">
    <div class="section-title">Threat Actor Attribution</div>
    <div style="color:rgba(255,255,255,0.45);font-size:.83rem;margin-bottom:20px">
      {len(attributions)} chain(s) attributed - {", ".join(dict.fromkeys(a.primary_apt for a in attributions))}
    </div>
    {attribution_html}
  </div>

  <div class="footer">
    LLM Security Operations Platform - Python / OpenAI / LangChain / ChromaDB / MITRE ATT&CK
  </div>
</div>
</body>
</html>"""

    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else ".", exist_ok=True)
    with open(output_file, "w") as f:
        f.write(html)

    print(f"\nConsolidated dashboard: {output_file}")


# ── Internal utility ───────────────────────────────────────────────────────────

def _hex_to_rgb(hex_color: str) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    return f"{r},{g},{b}"