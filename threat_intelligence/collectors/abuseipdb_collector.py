import requests

from config.api_keys import ABUSEIPDB_API_KEY
from config.settings import ABUSEIPDB_API_URL, MAX_INDICATORS_PER_FEED
from utils.logger import setup_logger

logger = setup_logger()


def collect_abuseipdb():

    logger.info("AbuseIPDB Collector | Starting collection")

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "confidenceMinimum": 75
    }

    indicators = []

    try:

        response = requests.get(
            ABUSEIPDB_API_URL,
            headers=headers,
            params=params,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        for entry in data.get("data", [])[:MAX_INDICATORS_PER_FEED]:

            indicators.append({
                "indicator": entry["ipAddress"],
                "type": "ip",
                "source": "abuseipdb"
            })

        logger.info(f"AbuseIPDB Collector | Indicators collected: {len(indicators)}")

    except Exception as e:

        logger.error(f"AbuseIPDB Collector | Error: {str(e)}")

    return indicators