# 🛡️ LLM-Powered Security Operations Platform

An enterprise-grade AI security platform that automates threat detection, adversarial defense, and attack chain reconstruction using Large Language Models, RAG architecture, and the MITRE ATT&CK framework.

> **Status:** Active Development — Days 1-4 of 7 complete  
> **Author:** Shruti Singh — MS MIS, Texas A&M University  
> **Stack:** Python · OpenAI GPT-4 · LangChain · ChromaDB · MITRE ATT&CK

---

## 🎯 What This Does

Most security teams are drowning in log data. This platform automates the analyst workflow end-to-end:

1. **Ingests** raw security logs (firewall, auth, network)
2. **Detects adversarial attacks** against the AI system itself before analysis
3. **Analyzes threats** using LLM + RAG-backed threat intelligence
4. **Reconstructs kill chains** mapped to MITRE ATT&CK stages
5. **Generates** actionable reports with IOCs and remediation steps
6. **Visualizes** everything in an interactive security dashboard

---

## ✅ Features Built (Days 1–4)

### Day 1–2: LLM Log Analysis Engine
- GPT-4o-mini powered log analysis via LangChain
- RAG architecture with ChromaDB vector database
- Semantic search over threat intelligence corpus
- Structured output parsing with Pydantic schemas
- IOC extraction — IPs, domains, file hashes
- MITRE ATT&CK technique mapping
- Interactive HTML security dashboard

### Day 3: Adversarial Attack Detection ⭐
- **Prompt injection detection** — prevents LLM manipulation
- **Data poisoning defense** — blocks false safety claims
- **Obfuscation/evasion detection** — catches defanged IOCs (`hxxp://`, `[.]`)
- **CVE exploit pattern matching** — Log4Shell, SolarWinds, ransomware signatures
- **100% detection rate, 0% false positives** on benchmark suite
- Industry comparison: exceeds advanced ML baseline (85%)

### Day 4: Attack Chain Reconstruction
- Automatic kill chain reconstruction from raw log files
- 13-stage Cyber Kill Chain taxonomy mapped to MITRE ATT&CK
- Chronological timeline with time-gap analysis between stages
- IOC extraction per event (IPs, domains, file artifacts)
- Severity scoring and prioritized incident response recommendations
- Dashboard integration with visual kill chain stage progress

---

## 📊 Benchmark Results

| System | Detection Rate | False Positive Rate |
|---|---|---|
| **Our System** | **100.0%** | **0.0%** |
| Human Analysts | ~90% | ~3% |
| Advanced ML Systems | ~85% | ~5% |
| Industry Average | ~75% | ~10% |

Tested across: Prompt Injection · Data Poisoning · Evasion Techniques · Real CVE Exploits (Log4Shell, SolarWinds, Colonial Pipeline ransomware)

---

## 🏗️ Architecture
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
│                                             │
│  ┌─────────────┐      ┌──────────────────┐  │
│  │IOC Extractor│      │   RAG System     │  │
│  │  (Regex)    │      │  (ChromaDB +     │  │
│  └──────┬──────┘      │   Embeddings)    │  │
│         │             └────────┬─────────┘  │
│         └──────────┬───────────┘            │
│                    ▼                        │
│          ┌──────────────────┐               │
│          │  GPT-4o-mini     │               │
│          │  Analysis Engine │               │
│          └────────┬─────────┘               │
└───────────────────┼─────────────────────────┘
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
┌──────────────────┐  ┌────────────────────┐
│  Security Report │  │  Attack Chain      │
│  Threat Level    │  │  Reconstruction    │
│  MITRE ATT&CK    │  │  Kill Chain Stages │
│  IOCs            │  │  Timeline + IOCs   │
│  Remediation     │  │  IR Recommendations│
└──────────────────┘  └────────────────────┘
          │                    │
          └─────────┬──────────┘
                    ▼
       ┌─────────────────────┐
       │  Security Dashboard │
       │  Interactive HTML   │
       └─────────────────────┘
```

---

## 📁 Project Structure
```
llm-security-automation/
├── config.py                     # Central config — paths, API settings, constants
│
├── src/
│   ├── analyzer/
│   │   └── llm_analyzer.py       # LLM + RAG analysis engine
│   ├── detection/
│   │   └── adversarial.py        # Adversarial attack detection
│   ├── chains/
│   │   └── reconstruction.py     # Kill chain reconstruction engine
│   └── dashboard/
│       └── generator.py          # HTML dashboard generation
│
├── scripts/
│   ├── run_analysis.py           # Run LLM log analysis
│   ├── run_benchmark.py          # Run adversarial detection benchmark
│   └── run_day4.py               # Run attack chain reconstruction
│
├── logs/                         # Security log samples
│   ├── firewall_logs.txt
│   ├── auth_logs.txt
│   ├── network_logs.txt
│   └── real-world/               # CVE-based real logs (gitignored)
│
├── threat_intel/                 # RAG knowledge base
│   ├── mitre_attack.txt
│   └── common_threats.txt
│
├── output/                       # Generated reports (gitignored)
│   ├── security_report.json
│   ├── attack_chains.json
│   ├── adversarial_benchmark.json
│   └── security_dashboard_day4.html
│
├── requirements.txt
├── setup.sh
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- OpenAI API key — [platform.openai.com/api-keys](https://platform.openai.com/api-keys)

### Setup
```bash
git clone https://github.com/YOUR_USERNAME/llm-security-automation.git
cd llm-security-automation

python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

pip install -r requirements.txt

cp .env.template .env
# Add your OpenAI API key to .env
```

### Run
```bash
# Full LLM log analysis + dashboard
python scripts/run_analysis.py

# Adversarial detection benchmark
python scripts/run_benchmark.py

# Attack chain reconstruction
python scripts/run_day4.py

# Open dashboard
open output/security_dashboard_day4.html
```

---

## 🔬 Technical Details

| Component | Technology |
|---|---|
| LLM | OpenAI GPT-4o-mini via LangChain |
| Vector DB | ChromaDB (local, in-memory) |
| Embeddings | OpenAI text-embedding-ada-002 |
| Output Parsing | Pydantic + JsonOutputParser |
| IOC Extraction | Regex (IP, domain, hash patterns) |
| Kill Chain | Cyber Kill Chain + MITRE ATT&CK |
| Dashboard | Plotly + custom HTML/CSS |
| Adversarial Defense | Pattern matching + heuristics |

### RAG Configuration
- Chunk size: 500 chars · Overlap: 50 chars
- Retrieval: top-3 semantically relevant chunks per query
- LLM temperature: 0 (deterministic output for security analysis)

---

## 🗺️ Roadmap

| Day | Feature | Status |
|---|---|---|
| 1–2 | LLM Log Analysis + RAG + Dashboard | ✅ Complete |
| 3 | Adversarial Attack Detection | ✅ Complete |
| 4 | Attack Chain Reconstruction | ✅ Complete |
| 5 | Threat Actor Attribution | 🔲 Planned |
| 6 | False Positive Analysis | 🔲 Planned |
| 7 | YARA Rule Generation + Final Polish | 🔲 Planned |

---

## 💰 Cost

Using `gpt-4o-mini`: ~$0.15/1M input tokens · ~$0.60/1M output tokens  
Estimated full project cost: **$2–5**

---

## 📄 License

Educational/Portfolio Project — free to use and modify.

---

## 👤 Author

**Shruti Singh**  
MS in Management Information Systems · Texas A&M University · GPA 4.0  
[linkedin.com/in/shruti-singh96](https://www.linkedin.com/in/shruti-singh96) · shruti.singh1506@hotmail.com