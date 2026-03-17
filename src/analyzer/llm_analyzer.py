"""
LLM-powered security log analysis with RAG-based threat intelligence.

Uses OpenAI + LangChain to classify logs, extract IOCs, map to MITRE
ATT&CK, and produce structured SecurityAnalysis objects.
"""

import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

import chromadb
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter
from pydantic import BaseModel, Field

from config import (
    CHUNK_OVERLAP,
    CHUNK_SIZE,
    CHROMA_COLLECTION,
    LLM_MODEL,
    LLM_TEMPERATURE,
    OPENAI_API_KEY,
    RAG_N_RESULTS,
)
from src.detection.adversarial import AdversarialDetector

logger = logging.getLogger(__name__)

_ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a cybersecurity analyst specialising in threat detection \
and MITRE ATT&CK mapping. Analyse the security log and provide structured output.

Threat Intelligence Context:
{context}

Output format:
{format_instructions}
"""),
    ("user", """Analyse this security log:

{log_content}

Extracted IOCs:
- IPs: {ips}
- Domains: {domains}

Provide threat analysis with MITRE ATT&CK technique mapping."""),
])

_IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
_HASH_RE   = re.compile(r"\b[a-fA-F0-9]{32,64}\b")


class SecurityAnalysis(BaseModel):
    threat_level:   str = Field(description="CRITICAL | HIGH | MEDIUM | LOW")
    attack_type:    str = Field(description="Type of attack detected")
    mitre_technique: str = Field(description="MITRE ATT&CK technique ID(s)")
    indicators:     List[str] = Field(description="IOCs found (IPs, domains, hashes)")
    summary:        str = Field(description="Brief summary of the security event")
    remediation:    str = Field(description="Recommended remediation steps")


class LLMSecurityAnalyzer:
    """
    Analyses security logs using an LLM with RAG-backed threat intelligence.

    Usage::

        analyzer = LLMSecurityAnalyzer()
        analyzer.load_threat_intelligence(Path("threat_intel"))
        result = analyzer.analyze_log(log_text, log_type="firewall")
    """

    def __init__(self) -> None:
        self._llm = ChatOpenAI(
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            api_key=OPENAI_API_KEY,
        )
        self._embeddings = OpenAIEmbeddings(api_key=OPENAI_API_KEY)
        self._parser = JsonOutputParser(pydantic_object=SecurityAnalysis)
        self._collection = self._init_chroma()
        self.adversarial_detector = AdversarialDetector()
        logger.info("LLMSecurityAnalyzer initialised")

    # ── Public API ─────────────────────────────────────────────────────────────

    def load_threat_intelligence(self, intel_dir: Path) -> None:
        """Chunk and embed all .txt files in *intel_dir* into the vector store."""
        logger.info("Loading threat intelligence from %s", intel_dir)
        splitter = RecursiveCharacterTextSplitter(
            chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
        )

        chunks: List[str] = []
        metadatas: List[Dict] = []

        for path in intel_dir.glob("*.txt"):
            for chunk in splitter.split_text(path.read_text()):
                chunks.append(chunk)
                metadatas.append({"source": path.name})

        if chunks:
            self._collection.add(
                documents=chunks,
                metadatas=metadatas,
                ids=[f"doc_{i}" for i in range(len(chunks))],
            )
            logger.info("Loaded %d threat intelligence chunks", len(chunks))

    def analyze_log(self, log_content: str, log_type: str = "security") -> Dict:
        """
        Analyse *log_content* and return a structured result dict.

        Adversarial checks are run first; if the input is tainted the
        sanitised version is forwarded to the LLM.
        """
        log_content = self._adversarial_check(log_content)
        logger.info("Analysing %s log", log_type)

        iocs = self._extract_iocs(log_content)
        logger.debug("Extracted IOCs — IPs: %d, Domains: %d", len(iocs["ips"]), len(iocs["domains"]))

        context = self._retrieve_context(log_content[:1_000])
        chain = _ANALYSIS_PROMPT | self._llm | self._parser

        try:
            result: Dict = chain.invoke({
                "context":             context[:2_000] or "No additional context available",
                "log_content":         log_content[:3_000],
                "ips":                 ", ".join(iocs["ips"][:10]) or "None",
                "domains":             ", ".join(iocs["domains"][:10]) or "None",
                "format_instructions": self._parser.get_format_instructions(),
            })
            result["extracted_iocs"] = iocs
            logger.info("Analysis complete — threat level: %s", result.get("threat_level"))
            return result
        except Exception:
            logger.exception("LLM analysis failed for %s log", log_type)
            return {"error": "Analysis failed", "threat_level": "UNKNOWN", "extracted_iocs": iocs}

    def print_analysis(self, analysis: Dict) -> None:
        """Print a human-readable summary of *analysis* to stdout."""
        print(f"THREAT LEVEL : {analysis.get('threat_level', 'UNKNOWN')}")
        print(f"ATTACK TYPE  : {analysis.get('attack_type', 'Unknown')}")
        print(f"MITRE ATT&CK : {analysis.get('mitre_technique', 'N/A')}")
        print(f"\nSUMMARY\n{analysis.get('summary', 'No summary available')}")
        print(f"\nREMEDIATION\n{analysis.get('remediation', 'No remediation provided')}")
        iocs = analysis.get("extracted_iocs", {})
        if any(iocs.values()):
            print("\nINDICATORS OF COMPROMISE")
            if iocs.get("ips"):
                print(f"  IPs     : {', '.join(iocs['ips'][:5])}")
            if iocs.get("domains"):
                print(f"  Domains : {', '.join(iocs['domains'][:5])}")

    # ── Private helpers ────────────────────────────────────────────────────────

    def _adversarial_check(self, text: str) -> str:
        result = self.adversarial_detector.analyze(text)
        if not result.input_safe:
            print(self.adversarial_detector.format_report(result))
            logger.warning("Adversarial input detected — using sanitised version")
            return result.sanitized_input
        return text

    def _retrieve_context(self, query: str) -> str:
        query_embedding = self._embeddings.embed_query(query)
        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=RAG_N_RESULTS,
        )
        docs = results.get("documents", [[]])[0]
        return "\n\n".join(docs)

    @staticmethod
    def _extract_iocs(log_text: str) -> Dict[str, List[str]]:
        ips = list(dict.fromkeys(_IP_RE.findall(log_text)))
        raw_domains = list(dict.fromkeys(_DOMAIN_RE.findall(log_text)))
        domains = [d for d in raw_domains if not _IP_RE.fullmatch(d)]
        hashes = list(dict.fromkeys(_HASH_RE.findall(log_text)))
        return {"ips": ips, "domains": domains, "urls": [], "file_hashes": hashes}

    @staticmethod
    def _init_chroma() -> chromadb.Collection:
        client = chromadb.Client()
        try:
            client.delete_collection(CHROMA_COLLECTION)
        except Exception:
            pass
        return client.create_collection(
            name=CHROMA_COLLECTION,
            metadata={"description": "Threat intelligence knowledge base"},
        )