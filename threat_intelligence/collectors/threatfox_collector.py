import requests

from config.settings import THREATFOX_FEED_URL, MAX_INDICATORS_PER_FEED
from utils.logger import setup_logger

logger = setup_logger()


def collect_threatfox():
    """
    Collect SHA256 malware hashes from ThreatFox.
    Uses ThreatFox API to fetch recent IOCs and extracts SHA256 hashes.
    """

    logger.info("ThreatFox Collector | Starting collection")

    indicators = []
    count = 0

    try:

        # ThreatFox requires POST request
        response = requests.post(
            THREATFOX_FEED_URL,
            json={
                "query": "get_iocs",
                "days": 1
            },
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        if not data or "data" not in data:
            logger.warning("ThreatFox Collector | No IOC data returned")
            return indicators

        for entry in data["data"]:

            if count >= MAX_INDICATORS_PER_FEED:
                break

            ioc_type = entry.get("ioc_type", "")
            ioc_value = entry.get("ioc")

            if not ioc_type or not ioc_value:
                continue

            # Accept any SHA256 indicator format
            if "sha256" in ioc_type.lower():

                indicators.append({
                    "indicator": ioc_value,
                    "type": "hash",
                    "source": "threatfox"
                })

                count += 1

        logger.info(
            f"ThreatFox Collector | Indicators collected: {len(indicators)}"
        )

    except Exception as e:

        logger.error(f"ThreatFox Collector | Error: {str(e)}")

    return indicators