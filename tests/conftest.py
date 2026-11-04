import os
import tempfile

# Settings are read at import time, so configure the environment before any backend import.
_DATA_DIR = tempfile.mkdtemp(prefix="nexus-test-")
os.environ["DATA_DIR"] = _DATA_DIR
os.environ["DATABASE_URL"] = ""
os.environ["DASHBOARD_USER"] = "admin"
os.environ["DASHBOARD_PASSWORD"] = "test-password"
os.environ["RATE_LIMIT_PER_MINUTE"] = "1000"
os.environ["SLACK_WEBHOOK_URL"] = ""
