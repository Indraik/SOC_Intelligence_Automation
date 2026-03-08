import json
import os

CACHE_FILE = "data/ioc_cache.json"


def load_cache():
    """
    Load IOC cache from disk.
    """

    if not os.path.exists(CACHE_FILE):
        return {}

    try:

        with open(CACHE_FILE, "r") as f:
            return json.load(f)

    except Exception:

        return {}


def update_cache(cache):
    """
    Save IOC cache to disk.
    """

    try:

        with open(CACHE_FILE, "w") as f:
            json.dump(cache, f, indent=4)

    except Exception:
        pass