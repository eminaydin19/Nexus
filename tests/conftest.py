import os
import tempfile

# Settings are read at import time, so configure the environment before any backend import.
_DATA_DIR = tempfile.mkdtemp(prefix="nexus-test-")
os.environ["DATA_DIR"] = _DATA_DIR
os.environ["DATABASE_URL"] = ""
os.environ["INGEST_API_KEY"] = "test-key"
os.environ["DASHBOARD_USER"] = ""
os.environ["DASHBOARD_PASSWORD"] = ""
os.environ["RATE_LIMIT_PER_MINUTE"] = "1000"
os.environ["DEFENSE_MODE"] = "dry_run"
os.environ["SLACK_WEBHOOK_URL"] = ""
