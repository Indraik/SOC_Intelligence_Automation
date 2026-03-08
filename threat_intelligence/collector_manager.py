import json
import threading

from threat_intelligence.collectors.abuseipdb_collector import collect_abuseipdb
from threat_intelligence.collectors.urlhaus_collector import collect_urlhaus
from threat_intelligence.collectors.threatfox_collector import collect_threatfox

from config.settings import RAW_FEED_PATH
from utils.logger import setup_logger
from threat_intelligence.normalizer import normalize_feed


logger = setup_logger()


def run_pipeline():

    logger.info("Threat Pipeline | Starting threat intelligence collection")

    results = {
        "abuseipdb": [],
        "urlhaus": [],
        "threatfox": []
    }

    # Thread wrapper functions
    def abuseipdb_task():
        try:
            results["abuseipdb"] = collect_abuseipdb()
        except Exception as e:
            logger.error(f"AbuseIPDB Collector Failed | {str(e)}")

    def urlhaus_task():
        try:
            results["urlhaus"] = collect_urlhaus()
        except Exception as e:
            logger.error(f"URLHaus Collector Failed | {str(e)}")

    def threatfox_task():
        try:
            results["threatfox"] = collect_threatfox()
        except Exception as e:
            logger.error(f"ThreatFox Collector Failed | {str(e)}")

    # Create threads
    threads = [
        threading.Thread(target=abuseipdb_task),
        threading.Thread(target=urlhaus_task),
        threading.Thread(target=threatfox_task)
    ]

    # Start collectors
    for thread in threads:
        thread.start()

    # Wait for completion
    for thread in threads:
        thread.join()

    # Merge results
    all_indicators = (
        results["abuseipdb"]
        + results["urlhaus"]
        + results["threatfox"]
    )

    logger.info(f"Threat Pipeline | Total raw indicators collected: {len(all_indicators)}")

    # Save raw feed
    try:
        with open(RAW_FEED_PATH, "w") as f:
            json.dump(all_indicators, f, indent=4)

        logger.info("Threat Pipeline | Raw threat feed saved")

    except Exception as e:
        logger.error(f"Threat Pipeline | Failed to save raw feed | {str(e)}")

    # Run normalization
    normalize_feed()

    logger.info("Threat Pipeline | Completed successfully")