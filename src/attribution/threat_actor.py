"""
Threat Actor Attribution Engine - Day 5
Maps attack chains to known APT groups using LLM-powered reasoning.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from pydantic import BaseModel, Field

from config import (
    LLM_MODEL, LLM_TEMPERATURE, OPENAI_API_KEY,
    THREAT_INTEL_DIR, CHUNK_SIZE, CHUNK_OVERLAP, RAG_N_RESULTS,
)
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

logger = logging.getLogger(__name__)


# ── APT Knowledge Base ─────────────────────────────────────────────────────────

APT_PROFILES: Dict[str, Dict] = {
    "APT28": {
        "aliases":     ["Fancy Bear", "Sofacy", "Pawn Storm", "STRONTIUM"],
        "origin":      "Russia",
        "sponsor":     "GRU (Russian Military Intelligence)",
        "motivation":  "Espionage, political influence",
        "active":      "2004–present",
        "description": "Russian state-sponsored group targeting government, military, and political organizations globally.",
        "mitre_techniques": [
            "T1566", "T1078", "T1110", "T1021", "T1041",
            "T1003", "T1059", "T1071", "T1547",
        ],
        "known_ioc_patterns": [
            "fancy", "sofacy", "sednit", "xagent", "x-agent",
            "chopstick", "coreshell", "gamefish",
        ],
        "target_sectors": ["Government", "Military", "Political", "Defense"],
        "kill_chain_affinity": [
            "INITIAL_ACCESS", "CREDENTIAL_ACCESS", "EXFILTRATION", "COMMAND_CONTROL"
        ],
    },
    "APT29": {
        "aliases":     ["Cozy Bear", "The Dukes", "YTTRIUM", "Midnight Blizzard"],
        "origin":      "Russia",
        "sponsor":     "SVR (Russian Foreign Intelligence)",
        "motivation":  "Espionage, long-term access",
        "active":      "2008–present",
        "description": "Sophisticated Russian APT known for stealth and long-term persistence, responsible for SolarWinds supply chain attack.",
        "mitre_techniques": [
            "T1195", "T1078", "T1071", "T1027", "T1547",
            "T1003", "T1041", "T1090", "T1021",
        ],
        "known_ioc_patterns": [
            "solarwinds", "sunburst", "teardrop", "avsvmcloud",
            "freescanonline", "deftsecurity", "cozy", "nobelium",
        ],
        "target_sectors": ["Government", "Technology", "Think Tanks", "Healthcare"],
        "kill_chain_affinity": [
            "PERSISTENCE", "DEFENSE_EVASION", "COMMAND_CONTROL", "COLLECTION"
        ],
    },
    "Lazarus Group": {
        "aliases":     ["HIDDEN COBRA", "Guardians of Peace", "ZINC", "Kimsuky"],
        "origin":      "North Korea",
        "sponsor":     "RGB (Reconnaissance General Bureau)",
        "motivation":  "Financial gain, espionage, sabotage",
        "active":      "2009–present",
        "description": "North Korean state-sponsored group known for financial theft, ransomware, and destructive attacks.",
        "mitre_techniques": [
            "T1486", "T1078", "T1059", "T1041", "T1566",
            "T1021", "T1003", "T1490", "T1547",
        ],
        "known_ioc_patterns": [
            "lazarus", "wannacry", "notpetya", "hidden cobra",
            "bluenoroff", "andarariel", "applejeus",
        ],
        "target_sectors": ["Finance", "Cryptocurrency", "Defense", "Media"],
        "kill_chain_affinity": [
            "INITIAL_ACCESS", "IMPACT", "EXFILTRATION", "DEFENSE_EVASION"
        ],
    },
    "APT41": {
        "aliases":     ["Double Dragon", "Winnti", "Barium", "Wicked Panda"],
        "origin":      "China",
        "sponsor":     "MSS (Ministry of State Security)",
        "motivation":  "Espionage + financial crime (dual mission)",
        "active":      "2012–present",
        "description": "Unique Chinese APT conducting both state-sponsored espionage and financially motivated cybercrime.",
        "mitre_techniques": [
            "T1190", "T1078", "T1059", "T1021", "T1041",
            "T1003", "T1071", "T1027", "T1053",
        ],
        "known_ioc_patterns": [
            "winnti", "shadowpad", "plugx", "crosswalk",
            "messagetap", "poisonplug",
        ],
        "target_sectors": ["Technology", "Healthcare", "Telecom", "Gaming", "Finance"],
        "kill_chain_affinity": [
            "INITIAL_ACCESS", "EXECUTION", "PERSISTENCE", "LATERAL_MOVEMENT"
        ],
    },
    "DarkSide": {
        "aliases":     ["Carbon Spider", "Sangria Tempest"],
        "origin":      "Russia/Eastern Europe",
        "sponsor":     "Cybercriminal (RaaS)",
        "motivation":  "Financial — Ransomware-as-a-Service",
        "active":      "2020–present",
        "description": "RaaS group responsible for the Colonial Pipeline attack. Known for double extortion: encrypt and exfiltrate.",
        "mitre_techniques": [
            "T1486", "T1490", "T1078", "T1041", "T1547",
            "T1021", "T1003", "T1070",
        ],
        "known_ioc_patterns": [
            "darkside", "colonial", "blackmatter", "ransomware",
            "vssadmin", "readme_decrypt", "your files have been encrypted",
        ],
        "target_sectors": ["Energy", "Critical Infrastructure", "Manufacturing"],
        "kill_chain_affinity": [
            "IMPACT", "EXFILTRATION", "DEFENSE_EVASION", "PERSISTENCE"
        ],
    },
    "FIN7": {
        "aliases":     ["Carbanak", "Navigator Group", "ITG14"],
        "origin":      "Russia/Ukraine",
        "sponsor":     "Cybercriminal",
        "motivation":  "Financial — POS malware, card theft, ransomware",
        "active":      "2013–present",
        "description": "Prolific financially motivated group targeting retail, hospitality, and financial sectors.",
        "mitre_techniques": [
            "T1566", "T1059", "T1021", "T1041", "T1003",
            "T1547", "T1027", "T1071",
        ],
        "known_ioc_patterns": [
            "fin7", "carbanak", "navigator", "griffon",
            "boostwrite", "rdfsniffer",
        ],
        "target_sectors": ["Retail", "Hospitality", "Finance", "Restaurant"],
        "kill_chain_affinity": [
            "INITIAL_ACCESS", "EXECUTION", "CREDENTIAL_ACCESS", "EXFILTRATION"
        ],
    },
}

def _build_apt_vectorstore() -> Chroma:
    """Load apt_profiles.txt into ChromaDB for semantic retrieval."""
    apt_path = THREAT_INTEL_DIR / "apt_profiles.txt"
    text = apt_path.read_text()
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE, chunk_overlap=CHUNK_OVERLAP
    )
    docs = splitter.create_documents([text])
    embeddings = OpenAIEmbeddings(
        model="text-embedding-ada-002", api_key=OPENAI_API_KEY
    )
    return Chroma.from_documents(
        docs, embeddings, collection_name="apt_profiles"
    )

# ── Data models ────────────────────────────────────────────────────────────────

class AttributionOutput(BaseModel):
    apt_group:        str   = Field(description="Name of the most likely APT group")
    confidence:       float = Field(description="Confidence score 0.0 to 1.0")
    reasoning:        str   = Field(description="Detailed explanation of attribution reasoning")
    matching_ttps:    List[str] = Field(description="MITRE techniques that match this APT's profile")
    matching_iocs:    List[str] = Field(description="IOCs or keywords that match known signatures")
    alternative_apt:  str   = Field(description="Second most likely APT group")
    alt_confidence:   float = Field(description="Confidence for alternative attribution")
    campaign_name:    str   = Field(description="Suggested campaign name based on observed TTPs")
    recommended_actions: List[str] = Field(description="Specific actions based on this attribution")


@dataclass
class ChainAttribution:
    chain_id:         str
    log_source:       str
    primary_apt:      str
    confidence:       float
    reasoning:        str
    matching_ttps:    List[str]
    matching_iocs:    List[str]
    alternative_apt:  str
    alt_confidence:   float
    campaign_name:    str
    recommended_actions: List[str]
    apt_profile:      Optional[Dict] = field(default=None)


# ── Prompt ─────────────────────────────────────────────────────────────────────

_ATTRIBUTION_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a senior threat intelligence analyst specialising in APT attribution.
You have deep knowledge of nation-state and cybercriminal threat actor TTPs, infrastructure,
and targeting patterns.

Known APT profiles for reference:
{apt_profiles}

Your task: analyse the provided attack chain data and attribute it to the most likely
threat actor. Base your reasoning on:
1. MITRE ATT&CK technique overlap
2. IOC patterns matching known actor infrastructure
3. Kill chain stage progression typical of the actor
4. Target sector and motivation alignment
5. Log keywords matching known malware/tool signatures

Output format:
{format_instructions}

Be precise. If evidence is weak, reflect that in a lower confidence score.
Never fabricate IOC matches — only cite what is present in the input data.
"""),
    ("user", """Analyse this attack chain and attribute it to a threat actor:

Log Source: {log_source}
Severity: {severity}
Kill Chain Stages: {stages}
MITRE Techniques: {techniques}
Source IPs: {source_ips}
IOCs: {iocs}
Log Keywords: {keywords}
Duration: {duration}

Provide detailed attribution with confidence scoring."""),
])


# ── Attributor ─────────────────────────────────────────────────────────────────

class ThreatActorAttributor:
    """
    Attributes attack chains to known APT groups using LLM reasoning.

    Usage::

        attributor = ThreatActorAttributor()
        chains = attributor.load_chains(Path("output/attack_chains.json"))
        attributions = attributor.attribute_all(chains)
    """

    def __init__(self) -> None:
        self._llm = ChatOpenAI(
            model=LLM_MODEL,
            temperature=LLM_TEMPERATURE,
            api_key=OPENAI_API_KEY,
        )
        self._parser = JsonOutputParser(pydantic_object=AttributionOutput)
        self._chain  = _ATTRIBUTION_PROMPT | self._llm | self._parser
        self._vectorstore = _build_apt_vectorstore()
        logger.info("ThreatActorAttributor initialised with RAG over apt_profiles.txt")

    # ── Public API ─────────────────────────────────────────────────────────────

    def load_chains(self, chains_file: Path) -> List[Dict]:
        """Load attack chains from the JSON file produced by Day 4."""
        if not chains_file.exists():
            logger.error("Attack chains file not found: %s", chains_file)
            return []
        chains = json.loads(chains_file.read_text())
        logger.info("Loaded %d attack chains from %s", len(chains), chains_file)
        return chains

    def attribute_all(self, chains: List[Dict]) -> List[ChainAttribution]:
        """Run attribution on every chain and return results."""
        attributions: List[ChainAttribution] = []
        for chain in chains:
            if not chain.get("events"):
                logger.info("Skipping empty chain: %s", chain.get("log_source"))
                continue
            attribution = self._attribute_chain(chain)
            if attribution:
                attributions.append(attribution)
                self._print_attribution(attribution)
        return attributions

    def save(self, attributions: List[ChainAttribution], output_file: Path) -> None:
        """Serialise attributions to JSON."""
        data = [self._to_dict(a) for a in attributions]
        output_file.write_text(json.dumps(data, indent=2))
        logger.info("Attributions saved to %s", output_file)

    # ── Private helpers ────────────────────────────────────────────────────────

    def _attribute_chain(self, chain: Dict) -> Optional[ChainAttribution]:
        """Run LLM attribution for a single chain dict."""
        log_source = chain.get("log_source", "unknown")
        logger.info("Attributing chain: %s", log_source)

        # Extract features from chain
        stages     = chain.get("stages_detected", [])
        techniques = list({e["mitre_technique"] for e in chain.get("events", [])})
        source_ips = chain.get("source_ips", [])
        iocs       = list({
            ioc
            for e in chain.get("events", [])
            for ioc in e.get("indicators", [])
        })
        keywords = self._extract_keywords(chain)
        # also pull mitre names — richer signal for RAG query
        keywords += [e.get("mitre_name", "").lower() for e in chain.get("events", [])]
        keywords = list(dict.fromkeys(w for w in keywords if w))[:20]
        duration   = (
            f"{chain['duration_minutes']:.0f} minutes"
            if chain.get("duration_minutes") else "unknown"
        )

        try:
            result = self._chain.invoke({
                "apt_profiles":         self._retrieve_apt_context(techniques, keywords),
                "log_source":           log_source,
                "severity":             chain.get("severity", "UNKNOWN"),
                "stages":               ", ".join(stages),
                "techniques":           ", ".join(techniques),
                "source_ips":           ", ".join(source_ips[:10]) or "unknown",
                "iocs":                 ", ".join(iocs[:15]) or "none",
                "keywords":             ", ".join(keywords[:20]) or "none",
                "duration":             duration,
                "format_instructions":  self._parser.get_format_instructions(),
            })
        except Exception:
            logger.exception("LLM attribution failed for %s", log_source)
            return None

        apt_profile = APT_PROFILES.get(result.get("apt_group", ""))

        return ChainAttribution(
            chain_id=       chain.get("chain_id", "unknown"),
            log_source=     log_source,
            primary_apt=    result.get("apt_group", "Unknown"),
            confidence=     float(result.get("confidence", 0.0)),
            reasoning=      result.get("reasoning", ""),
            matching_ttps=  result.get("matching_ttps", []),
            matching_iocs=  result.get("matching_iocs", []),
            alternative_apt=result.get("alternative_apt", "Unknown"),
            alt_confidence= float(result.get("alt_confidence", 0.0)),
            campaign_name=  result.get("campaign_name", "Unknown Campaign"),
            recommended_actions=result.get("recommended_actions", []),
            apt_profile=    apt_profile,
        )
    def _retrieve_apt_context(self, techniques: List[str], keywords: List[str]) -> str:
        """Semantic search over apt_profiles.txt for relevant actor profiles."""
        query = " ".join(techniques[:5] + keywords[:5])
        if not query.strip():
            query = "advanced persistent threat lateral movement exfiltration"
        docs = self._vectorstore.similarity_search(query, k=RAG_N_RESULTS)
        return "\n\n".join(d.page_content for d in docs)

    @staticmethod
    def _extract_keywords(chain: Dict) -> List[str]:
        """Pull significant keywords from event descriptions and raw logs."""
        keywords: List[str] = []
        for event in chain.get("events", []):
            desc = event.get("description", "").lower()
            keywords.extend(desc.split())
        # Keep only meaningful words, deduplicate
        stopwords = {
            "the", "a", "an", "to", "from", "and", "or", "in",
            "on", "at", "of", "for", "is", "was", "detected",
            "attempt", "activity",
        }
        return list(dict.fromkeys(
            w for w in keywords if len(w) > 4 and w not in stopwords
        ))[:20]


    @staticmethod
    def _print_attribution(a: ChainAttribution) -> None:
        sep = "=" * 70
        print(f"\n{sep}")
        print(f"  THREAT ACTOR ATTRIBUTION — {a.log_source.upper()}")
        print(sep)
        print(f"  Primary   : {a.primary_apt} ({a.confidence*100:.0f}% confidence)")
        print(f"  Campaign  : {a.campaign_name}")
        print(f"  Alternative: {a.alternative_apt} ({a.alt_confidence*100:.0f}% confidence)")
        print(f"\n  Reasoning:\n  {a.reasoning[:300]}...")
        if a.matching_ttps:
            print(f"\n  Matching TTPs : {', '.join(a.matching_ttps)}")
        if a.matching_iocs:
            print(f"  Matching IOCs : {', '.join(a.matching_iocs[:5])}")
        print(f"\n  Recommended Actions:")
        for action in a.recommended_actions[:3]:
            print(f"    • {action}")
        print(sep)

    @staticmethod
    def _to_dict(a: ChainAttribution) -> Dict:
        return {
            "chain_id":           a.chain_id,
            "log_source":         a.log_source,
            "primary_apt":        a.primary_apt,
            "confidence":         a.confidence,
            "reasoning":          a.reasoning,
            "matching_ttps":      a.matching_ttps,
            "matching_iocs":      a.matching_iocs,
            "alternative_apt":    a.alternative_apt,
            "alt_confidence":     a.alt_confidence,
            "campaign_name":      a.campaign_name,
            "recommended_actions": a.recommended_actions,
            "apt_profile": {
                "aliases":     a.apt_profile.get("aliases", []) if a.apt_profile else [],
                "origin":      a.apt_profile.get("origin", "") if a.apt_profile else "",
                "sponsor":     a.apt_profile.get("sponsor", "") if a.apt_profile else "",
                "motivation":  a.apt_profile.get("motivation", "") if a.apt_profile else "",
                "description": a.apt_profile.get("description", "") if a.apt_profile else "",
            } if a.apt_profile else {},
        }