"""Runner — Threat Actor Attribution"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import logging
from src.attribution.threat_actor import ThreatActorAttributor
import config

logging.basicConfig(level=logging.INFO, format="%(levelname)s — %(message)s")


def main():
    print("=" * 60)
    print("THREAT ACTOR ATTRIBUTION")
    print("=" * 60)

    attributor = ThreatActorAttributor()
    chains = attributor.load_chains(config.ATTACK_CHAINS_FILE)

    if not chains:
        print("[!] No attack chains found. Run reconstruction first.")
        return

    attributions = attributor.attribute_all(chains)

    output_path = config.OUTPUT_DIR / "attribution_report.json"
    attributor.save(attributions, output_path)
    print(f"\n[✓] Done. {len(attributions)} chain(s) attributed.")
    print(f"    Report → {output_path}")


if __name__ == "__main__":
    main()