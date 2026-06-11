"""
database.py — SQLite Persistence
==================================
Stores only REAL detected threats (no fake/simulated data).
Tables:
  sessions  — each analysis session (file upload or live capture)
  threats   — detected threat flows (severity != NORMAL)
  flows     — all analysed flows (summary counts per session)
"""

import os, json, sqlite3, threading
from datetime import datetime

DB_FILE = "threats.db"


class Database:
    _inst = None
    _lock = threading.Lock()

    def __new__(cls):
        if cls._inst is None:
            with cls._lock:
                if cls._inst is None:
                    cls._inst = super().__new__(cls)
                    cls._inst._rl = threading.Lock()
                    cls._inst._init()
        return cls._inst

    def _conn(self):
        return sqlite3.connect(DB_FILE, check_same_thread=False)

    def _init(self):
        with self._rl:
            c = self._conn()
            c.execute("""CREATE TABLE IF NOT EXISTS sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at  TEXT,
                source      TEXT,
                source_type TEXT,
                total_flows INTEGER DEFAULT 0,
                high_count  INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count   INTEGER DEFAULT 0,
                normal_count INTEGER DEFAULT 0
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS threats (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      INTEGER,
                timestamp       TEXT,
                src_ip          TEXT,
                dst_ip          TEXT,
                src_port        TEXT,
                dst_port        TEXT,
                protocol        TEXT,
                attack          TEXT,
                severity        TEXT,
                confidence      REAL,
                anomaly_score   REAL,
                composite_score REAL,
                is_anomaly      INTEGER,
                response_action TEXT,
                rf_probas       TEXT,
                FOREIGN KEY(session_id) REFERENCES sessions(id)
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS hourly_stats (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                hour    TEXT UNIQUE,
                total   INTEGER DEFAULT 0,
                high    INTEGER DEFAULT 0,
                medium  INTEGER DEFAULT 0,
                low     INTEGER DEFAULT 0
            )""")
            c.commit(); c.close()

    # ── Sessions ──────────────────────────────────────────────────────────
    def new_session(self, source: str, source_type: str) -> int:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._rl:
            c = self._conn()
            cur = c.execute(
                "INSERT INTO sessions(started_at,source,source_type) VALUES(?,?,?)",
                (ts, source, source_type))
            sid = cur.lastrowid
            c.commit(); c.close()
        return sid

    def close_session(self, session_id: int, counts: dict):
        with self._rl:
            c = self._conn()
            c.execute("""UPDATE sessions SET
                total_flows=?,high_count=?,medium_count=?,low_count=?,normal_count=?
                WHERE id=?""",
                (counts.get("total",0), counts.get("HIGH",0),
                 counts.get("MEDIUM",0), counts.get("LOW",0),
                 counts.get("NORMAL",0), session_id))
            c.commit(); c.close()

    # ── Threats ───────────────────────────────────────────────────────────
    def insert_threat(self, session_id: int, flow: dict, action: str):
        ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hour = datetime.now().strftime("%Y-%m-%d %H:00")
        sev  = flow.get("severity","NORMAL")
        with self._rl:
            c = self._conn()
            c.execute("""INSERT INTO threats
                (session_id,timestamp,src_ip,dst_ip,src_port,dst_port,protocol,
                 attack,severity,confidence,anomaly_score,composite_score,
                 is_anomaly,response_action,rf_probas)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (session_id, ts,
                 flow.get("src_ip","?"), flow.get("dst_ip","?"),
                 str(flow.get("src_port","?")), str(flow.get("dst_port","?")),
                 str(flow.get("protocol","?")),
                 flow.get("attack","?"), sev,
                 flow.get("confidence",0), flow.get("anomaly_score",0),
                 flow.get("composite_score",0),
                 1 if flow.get("is_anomaly") else 0,
                 action, flow.get("rf_probas","{}")))
            # hourly stats
            col = sev.lower() if sev in ("HIGH","MEDIUM","LOW") else None
            c.execute("""INSERT INTO hourly_stats(hour,total) VALUES(?,1)
                ON CONFLICT(hour) DO UPDATE SET total=total+1""", (hour,))
            if col:
                c.execute(f"UPDATE hourly_stats SET {col}={col}+1 WHERE hour=?", (hour,))
            c.commit(); c.close()

    # ── Queries ───────────────────────────────────────────────────────────
    def get_stats(self) -> dict:
        with self._rl:
            c = self._conn()
            total   = c.execute("SELECT COALESCE(SUM(total_flows),0) FROM sessions").fetchone()[0]
            high    = c.execute("SELECT COUNT(*) FROM threats WHERE severity='HIGH'").fetchone()[0]
            medium  = c.execute("SELECT COUNT(*) FROM threats WHERE severity='MEDIUM'").fetchone()[0]
            low     = c.execute("SELECT COUNT(*) FROM threats WHERE severity='LOW'").fetchone()[0]
            atk     = c.execute("SELECT attack,COUNT(*) FROM threats GROUP BY attack ORDER BY 2 DESC LIMIT 8").fetchall()
            ips     = c.execute("SELECT src_ip,COUNT(*) FROM threats GROUP BY src_ip ORDER BY 2 DESC LIMIT 10").fetchall()
            hourly  = c.execute("SELECT hour,total,high,medium,low FROM hourly_stats ORDER BY hour DESC LIMIT 24").fetchall()
            sessions= c.execute("SELECT id,started_at,source,source_type,total_flows,high_count,medium_count,low_count FROM sessions ORDER BY id DESC LIMIT 10").fetchall()
            c.close()
        return {
            "total": total, "high": high, "medium": medium, "low": low,
            "normal": max(0, total-high-medium-low),
            "attack_counts": dict(atk),
            "top_ips":       dict(ips),
            "hourly": [{"hour":r[0],"total":r[1],"high":r[2],"medium":r[3],"low":r[4]}
                       for r in reversed(hourly)],
            "sessions": [{"id":r[0],"started_at":r[1],"source":r[2],
                          "source_type":r[3],"total_flows":r[4],
                          "high":r[5],"medium":r[6],"low":r[7]}
                         for r in sessions],
        }

    def get_threats(self, n: int = 200, level: str = None,
                    attack: str = None, ip: str = None,
                    session_id: int = None) -> list:
        wheres, params = [], []
        if level:      wheres.append("severity=?");        params.append(level)
        if attack:     wheres.append("attack=?");          params.append(attack)
        if ip:         wheres.append("src_ip LIKE ?");     params.append(f"%{ip}%")
        if session_id: wheres.append("session_id=?");      params.append(session_id)
        where = ("WHERE " + " AND ".join(wheres)) if wheres else ""
        with self._rl:
            c = self._conn()
            rows = c.execute(
                f"SELECT * FROM threats {where} ORDER BY id DESC LIMIT ?",
                params+[n]).fetchall()
            c.close()
        cols = ["id","session_id","timestamp","src_ip","dst_ip","src_port",
                "dst_port","protocol","attack","severity","confidence",
                "anomaly_score","composite_score","is_anomaly",
                "response_action","rf_probas"]
        return [dict(zip(cols,r)) for r in rows]

    def get_sessions(self) -> list:
        with self._rl:
            c = self._conn()
            rows = c.execute(
                "SELECT * FROM sessions ORDER BY id DESC LIMIT 20").fetchall()
            c.close()
        cols = ["id","started_at","source","source_type","total_flows",
                "high_count","medium_count","low_count","normal_count"]
        return [dict(zip(cols,r)) for r in rows]
