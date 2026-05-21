# LLM-Powered Security Operations Platform

A security automation platform that applies LLMs, RAG architecture, and the MITRE ATT&CK framework to the parts of the analyst workflow that are mechanical but time-consuming: log analysis, adversarial input detection, kill chain reconstruction, and threat actor attribution.

Phases 1–5 of 7 are complete and functional. Phases 6–7 (false positive analysis and YARA rule generation) are in progress.

**Stack:** Python · OpenAI GPT-4o-mini · LangChain · ChromaDB · MITRE ATT&CK · Pydantic

---

## What it does

Security operations teams spend significant time on investigation steps that follow predictable patterns. This platform automates five of them:

1. **Log ingestion and analysis** — processes raw firewall, auth, and network logs through a LangChain + RAG pipeline backed by a ChromaDB threat intelligence corpus
2. **Adversarial input detection** — intercepts prompt injection attempts, data poisoning, IOC obfuscation (hxxp://, [.] defanging), and CVE exploit signatures before they reach the LLM analysis layer
3. **IOC extraction** — regex-based extraction of IPs, domains, and file hashes with MITRE ATT&CK technique mapping
4. **Kill chain reconstruction** — maps raw log events to a 13-stage Cyber Kill Chain taxonomy with chronological timeline and time-gap analysis between stages
5. **Threat actor attribution** — RAG-powered attribution over an APT knowledge base; matches observed TTPs and IOCs to actor profiles at query time using semantic retrieval and LLM reasoning

Output is a structured JSON report plus a single consolidated interactive HTML dashboard.

---

## Adversarial detection benchmark

Tested against prompt injection, data poisoning, evasion techniques, and real CVE exploit patterns including Log4Shell and SolarWinds signatures.

| Technique | Detected | False Positives |
|-----------|----------|-----------------|
| Prompt injection | Yes | 0 |
| Data poisoning | Yes | 0 |
| IOC obfuscation (defanging) | Yes | 0 |
| CVE exploit patterns (Log4Shell, SolarWinds, ransomware) | Yes | 0 |

100% detection rate across the full benchmark suite with 0 false positives.

---

## Architecture

```
Security Logs
      │
      ▼
┌─────────────────────────────────────────────┐
│           Adversarial Detection Layer        │
│  Prompt Injection · Poisoning · Evasion · CVE│
└─────────────────┬───────────────────────────┘
                  │ sanitized input
                  ▼
┌─────────────────────────────────────────────┐
│         LLM Analysis Pipeline               │
│  IOC Extractor · RAG (ChromaDB) · GPT-4o-mini│
└─────────────────┬───────────────────────────┘
                  │
          ┌───────┴────────┐
          ▼                ▼
   Security Report    Kill Chain
   MITRE ATT&CK       Reconstruction
   IOCs + Remediation  Timeline + IOCs
          │                │
          └───────┬────────┘
                  ▼
     Threat Actor Attribution
     RAG over APT Profiles
     Confidence Scoring
                  │
                  ▼
         Security Dashboard
         Single Consolidated HTML
```

---

## Threat actor attribution

The attribution engine uses RAG over a curated APT profile knowledge base. At query time, it semantically retrieves the most relevant actor profiles and passes them to the LLM with the observed TTPs and IOCs for reasoning.

Profiles currently cover: APT28, APT29, Lazarus Group, APT41, FIN7, LockBit, DarkSide

Attribution output includes primary and alternative candidates with confidence scores, MITRE technique overlap analysis, and actor-specific remediation recommendations.

---

## Project structure

```
llm-security-automation/
├── config.py
├── src/
│   ├── analyzer/llm_analyzer.py        # LLM + RAG analysis engine
│   ├── detection/adversarial.py        # Adversarial detection
│   ├── chains/reconstruction.py        # Kill chain reconstruction
│   ├── attribution/threat_actor.py     # Threat actor attribution
│   └── dashboard/generator.py         # HTML dashboard
├── scripts/
│   ├── run_pipeline.py                 # Full pipeline runner (recommended)
│   ├── run_analysis.py
│   ├── run_benchmark.py
│   ├── run_reconstruction.py
│   └── run_attribution.py
├── threat_intel/
│   ├── mitre_attack.txt
│   ├── common_threats.txt
│   └── apt_profiles.txt
└── output/                             # Generated reports (gitignored)
```

---

## Setup

```bash
git clone https://github.com/ShrutiSingh1506/llm-security-automation.git
cd llm-security-automation

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

cp .env.template .env
# Add your OpenAI API key
```

```bash
# Run the full pipeline (recommended)
python scripts/run_pipeline.py

# Or run individual stages
python scripts/run_analysis.py       # Log analysis + dashboard
python scripts/run_benchmark.py      # Adversarial detection benchmark
python scripts/run_reconstruction.py # Kill chain reconstruction
python scripts/run_attribution.py    # Threat actor attribution
```

---

## Roadmap

- [x] LLM log analysis + RAG + dashboard
- [x] Adversarial attack detection
- [x] Kill chain reconstruction
- [x] Threat actor attribution
- [ ] False positive analysis
- [ ] YARA rule generation

---

## RAG configuration

Chunk size: 500 chars · Overlap: 50 chars · Retrieval: top-3 chunks per query · LLM temperature: 0

---

Shruti Singh · [LinkedIn](https://linkedin.com/in/shruti-singh96) · [Portfolio](https://shrutisingh-portfolio.netlify.app)