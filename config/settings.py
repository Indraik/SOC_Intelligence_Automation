# ==============================
# Threat Intelligence Settings
# ==============================

MAX_INDICATORS_PER_FEED = 100


# ==============================
# Threat Feed URLs
# ==============================

ABUSEIPDB_API_URL = "https://api.abuseipdb.com/api/v2/blacklist"

URLHAUS_FEED_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

THREATFOX_FEED_URL = "https://threatfox.abuse.ch/export/json/recent/"


# ==============================
# File Paths
# ==============================

RAW_FEED_PATH = "data/raw_threat_feed.json"

NORMALIZED_FEED_PATH = "data/normalized_threat_feed.json"


# ==============================
# Logging
# ==============================

LOG_FILE_PATH = "logs/threat_pipeline.log"