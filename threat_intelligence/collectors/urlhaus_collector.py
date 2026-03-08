import requests
import csv
import re
from urllib.parse import urlparse
from io import StringIO

from config.settings import URLHAUS_FEED_URL, MAX_INDICATORS_PER_FEED
from utils.logger import setup_logger

logger = setup_logger()


def collect_urlhaus():

    logger.info("URLHaus Collector | Starting collection")

    indicators = []

    try:

        response = requests.get(URLHAUS_FEED_URL, timeout=10)
        response.raise_for_status()

        csv_data = StringIO(response.text)

        reader = csv.reader(csv_data)

        count = 0

        ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"

        for row in reader:

            if row and not row[0].startswith("#"):

                if count >= MAX_INDICATORS_PER_FEED:
                    break

                url = row[2]

                parsed = urlparse(url)

                host = parsed.netloc

                # Remove port if present
                host = host.split(":")[0]

                if not host:
                    continue

                # Detect if host is an IP address
                if re.match(ip_pattern, host):

                    indicators.append({
                        "indicator": host,
                        "type": "ip",
                        "source": "urlhaus"
                    })

                else:

                    indicators.append({
                        "indicator": host,
                        "type": "domain",
                        "source": "urlhaus"
                    })

                count += 1

        logger.info(f"URLHaus Collector | Indicators collected: {len(indicators)}")

    except Exception as e:

        logger.error(f"URLHaus Collector | Error: {str(e)}")

    return indicators