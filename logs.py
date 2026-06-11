"""
logs.py — Event Logger
======================
Writes structured events to logs/events.log
"""

import os, threading
from datetime import datetime

LOG_DIR  = "logs"
LOG_FILE = os.path.join(LOG_DIR, "events.log")


class Logger:
    _inst = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._inst is None:
            with cls._lock:
                if cls._inst is None:
                    cls._inst = super().__new__(cls)
                    cls._inst._fl = threading.Lock()
                    os.makedirs(LOG_DIR, exist_ok=True)
        return cls._inst

    def log(self, message: str, level: str = "INFO"):
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"[{ts}] [{level:<7}] {message}\n"
        with self._fl:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(entry)

    def read_last(self, n: int = 200) -> list:
        if not os.path.exists(LOG_FILE):
            return []
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [l.rstrip() for l in reversed(lines[-n:])]
