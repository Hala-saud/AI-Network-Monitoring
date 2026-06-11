"""
response.py — Stage 5: Automated Response
==========================================
  LOW    → Log to database + events.log
  MEDIUM → Log + alert + block IP (60 seconds)
  HIGH   → Log + alert + block IP (300 seconds) + isolate host
"""

import os, time, platform, subprocess, shutil, threading
from datetime import datetime
from logs import Logger

BLOCK_DURATION = {"HIGH": 300, "MEDIUM": 60}


class Responder:
    def __init__(self, disabled: bool = False):
        self.disabled = disabled
        self.logger   = Logger()
        self.os_type  = platform.system()
        self._blocked = {}
        self._lock    = threading.Lock()

    def respond(self, flow: dict) -> str:
        """Execute response for a scored flow. Returns action label."""
        sev    = flow.get("severity", "NORMAL")
        src_ip = str(flow.get("src_ip", "?"))
        attack = flow.get("attack", "?")
        score  = flow.get("composite_score", 0.0)
        self._expire()

        if sev == "HIGH":
            self._alert(sev, src_ip, attack, score)
            action = self._block(src_ip, BLOCK_DURATION["HIGH"])
            if attack in ("DDoS", "DoS", "BruteForce"):
                self._isolate(src_ip)
                action = "BLOCKED+ISOLATED"
            self.logger.log(f"HIGH THREAT | {attack} from {src_ip} | score={score:.2f} | {action}")
            return action

        elif sev == "MEDIUM":
            self._alert(sev, src_ip, attack, score)
            action = self._block(src_ip, BLOCK_DURATION["MEDIUM"])
            self.logger.log(f"MEDIUM THREAT | {attack} from {src_ip} | score={score:.2f} | {action}")
            return action

        elif sev == "LOW":
            self.logger.log(f"LOW THREAT | {attack} from {src_ip} | score={score:.2f} | LOGGED")
            return "LOGGED"

        return "NORMAL"

    def _alert(self, sev, ip, attack, score):
        c = {"HIGH":"\033[91m","MEDIUM":"\033[93m"}.get(sev,"")
        r = "\033[0m"
        print(f"\n{c}{'!'*60}")
        print(f"  ⚠  {sev} THREAT  |  {attack}  |  {ip}  |  score={score:.2f}")
        print(f"{'!'*60}{r}")

    def _block(self, ip: str, duration: int) -> str:
        if self.disabled:
            return "MONITOR_ONLY"
        with self._lock:
            if ip in self._blocked:
                return "ALREADY_BLOCKED"
            self._blocked[ip] = time.time() + duration
        cmd = self._cmd("-A", ip)
        if cmd:
            try:
                subprocess.run(cmd, check=True, capture_output=True, timeout=5)
                print(f"  [BLOCK] {ip} for {duration}s")
                return "BLOCKED"
            except Exception as e:
                print(f"  [!] Block failed (need root?): {e}")
                return "BLOCK_FAILED"
        return "NO_FIREWALL"

    def _isolate(self, ip: str):
        if self.disabled: return
        ipt = self._ipt()
        if not ipt: return
        for rule in [["-A","INPUT","-s",ip,"-j","DROP"],
                     ["-A","OUTPUT","-d",ip,"-j","DROP"],
                     ["-A","FORWARD","-s",ip,"-j","DROP"]]:
            try: subprocess.run([ipt]+rule, check=True,
                                capture_output=True, timeout=5)
            except: pass
        print(f"  [ISOLATE] {ip}")

    def _expire(self):
        now = time.time()
        with self._lock:
            expired = [ip for ip,t in self._blocked.items() if now>=t]
        for ip in expired:
            with self._lock: self._blocked.pop(ip, None)
            cmd = self._cmd("-D", ip)
            if cmd:
                try: subprocess.run(cmd, check=True, capture_output=True, timeout=5)
                except: pass
            print(f"  [UNBLOCK] {ip}")

    def _ipt(self):
        ipt = shutil.which("iptables") or "/usr/sbin/iptables"
        return ipt if os.path.exists(ipt) else None

    def _cmd(self, flag: str, ip: str):
        if self.disabled: return None
        if self.os_type == "Linux":
            ipt = self._ipt()
            if ipt: return [ipt, flag, "INPUT", "-s", ip, "-j", "DROP"]
        elif self.os_type == "Windows":
            name = f"AIMonitor_{ip.replace('.','_')}"
            if flag == "-A":
                return ["netsh","advfirewall","firewall","add","rule",
                        f"name={name}","dir=in","action=block",f"remoteip={ip}"]
            else:
                return ["netsh","advfirewall","firewall","delete",
                        "rule",f"name={name}"]
        return None

    def blocked_ips(self) -> dict:
        now = time.time()
        return {ip: max(0, int(t-now)) for ip,t in self._blocked.items()}
