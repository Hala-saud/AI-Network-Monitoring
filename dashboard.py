"""
dashboard.py — Stage 6: Dashboard & Logging System
====================================================
Flask web app providing:
  • Upload PCAP / CSV → AI analysis → results shown live
  • Start / stop live network capture
  • Real-time threat table (auto-refresh)
  • Attack distribution + top IPs charts
  • Hourly activity timeline
  • Session history (from SQLite)
  • Full threat database (filterable/searchable)
  • Event log viewer
  • No fake data — only real detected threats stored
"""

import os, json, time, threading, uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from flask import Flask, jsonify, render_template_string, request

import numpy as np
import pandas as pd

from detection        import Detector
from database         import Database
from logs             import Logger
from response         import Responder

UPLOAD_DIR  = "uploads"
ALLOWED_EXT = {".pcap", ".pcapng", ".csv"}
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── Shared analysis state (in-memory, reset per session) ──────────────────
_state = {
    "status": "idle",   # idle | analyzing | capturing | done | error
    "source": "",
    "source_type": "",
    "session_id": None,
    "total_flows": 0,
    "analyzed": 0,
    "live_threats": [],   # recent threats for live display (last 500)
    "sev_counts": {"HIGH":0,"MEDIUM":0,"LOW":0,"NORMAL":0},
    "atk_counts": {},
    "top_ips": {},
    "error": "",
    "stop_flag": False,
}
_lock = threading.Lock()


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 500 * 1024 * 1024

    detector  = Detector()
    db        = Database()
    logger    = Logger()
    responder = Responder()

    detector.load()

    # ── Analysis pipeline ─────────────────────────────────────────────────
    def _run_analysis(df_raw: pd.DataFrame, session_id: int):
        import feature_extraction, scoring
        CHUNK = 2000
        sev_counts = {"HIGH":0,"MEDIUM":0,"LOW":0,"NORMAL":0}
        atk_counts = {}
        top_ips    = {}

        with _lock: _state["total_flows"] = len(df_raw)

        for start in range(0, len(df_raw), CHUNK):
            with _lock:
                if _state["stop_flag"]:
                    break
            chunk = df_raw.iloc[start:start+CHUNK]
            X     = feature_extraction.extract(chunk, detector.feature_cols)
            preds = detector.predict(X)
            scored= scoring.score_flows(chunk, preds)

            new_threats = []
            for _, row in scored.iterrows():
                sev = row["severity"]
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
                atk = row["attack"]
                atk_counts[atk] = atk_counts.get(atk, 0) + 1
                ip  = row["src_ip"]
                if sev != "NORMAL":
                    top_ips[ip] = top_ips.get(ip, 0) + 1
                    action = responder.respond(row.to_dict())
                    db.insert_threat(session_id, row.to_dict(), action)
                    logger.log(f"{sev} | {atk} | {ip} → {row['dst_ip']}:{row['dst_port']} | score={row['composite_score']:.2f}")
                    r = row.to_dict()
                    r["timestamp"] = datetime.now().strftime("%H:%M:%S")
                    r["response_action"] = action
                    new_threats.append(r)

            with _lock:
                _state["analyzed"] = min(start + CHUNK, len(df_raw))
                _state["sev_counts"] = sev_counts
                _state["atk_counts"] = atk_counts
                _state["top_ips"] = dict(sorted(top_ips.items(),
                                     key=lambda x:x[1], reverse=True)[:10])
                _state["live_threats"] = (_state["live_threats"] + new_threats)[-500:]

        db.close_session(session_id, sev_counts)
        with _lock:
            _state["analyzed"] = len(df_raw)
            _state["status"]   = "done"

    def _file_thread(filepath: str, name: str):
        import capture as cap
        try:
            ext = os.path.splitext(filepath)[1].lower()
            df  = cap.load_pcap(filepath) if ext in (".pcap",".pcapng") \
                  else cap.load_csv(filepath)
            if len(df) == 0:
                with _lock: _state["status"]="error"; _state["error"]="No flows extracted."
                return
            sid = db.new_session(name, "file")
            with _lock: _state["session_id"] = sid
            _run_analysis(df, sid)
        except Exception as e:
            with _lock: _state["status"]="error"; _state["error"]=str(e)
        finally:
            try: os.remove(filepath)
            except: pass

    def _live_thread(interface: str):
        import capture as cap
        from scapy.all import sniff, IP
        sid = db.new_session(interface, "live")
        with _lock: _state["session_id"] = sid
        import feature_extraction, scoring

        sev_counts = {"HIGH":0,"MEDIUM":0,"LOW":0,"NORMAL":0}
        atk_counts = {}
        top_ips    = {}
        buf = []

        def pkt_cb(pkt):
            if pkt.haslayer(IP): buf.append(pkt)

        def flush():
            if not buf: return
            pkts = buf[:]; buf.clear()
            try:
                df = cap._packets_to_df(pkts)
                if len(df) == 0: return
                X      = feature_extraction.extract(df, detector.feature_cols)
                preds  = detector.predict(X)
                scored = scoring.score_flows(df, preds)
                new_t  = []
                for _, row in scored.iterrows():
                    sev = row["severity"]
                    atk = row["attack"]
                    ip  = row["src_ip"]
                    sev_counts[sev] = sev_counts.get(sev,0)+1
                    atk_counts[atk] = atk_counts.get(atk,0)+1
                    if sev != "NORMAL":
                        top_ips[ip] = top_ips.get(ip,0)+1
                        action = responder.respond(row.to_dict())
                        db.insert_threat(sid, row.to_dict(), action)
                        logger.log(f"LIVE {sev} | {atk} | {ip} → {row['dst_ip']}:{row['dst_port']}")
                        r = row.to_dict()
                        r["timestamp"] = datetime.now().strftime("%H:%M:%S")
                        r["response_action"] = action
                        new_t.append(r)
                with _lock:
                    _state["analyzed"] += len(df)
                    _state["total_flows"] += len(df)
                    _state["sev_counts"] = sev_counts
                    _state["atk_counts"] = atk_counts
                    _state["top_ips"] = dict(sorted(top_ips.items(),
                                         key=lambda x:x[1],reverse=True)[:10])
                    _state["live_threats"] = (_state["live_threats"]+new_t)[-500:]
            except Exception as e:
                print(f"[!] Live analysis error: {e}")

        try:
            sniffer_stop = [False]
            def run_sniff():
                sniff(iface=interface, prn=pkt_cb, store=False,
                      stop_filter=lambda p: sniffer_stop[0])
            t = threading.Thread(target=run_sniff, daemon=True)
            t.start()

            while True:
                time.sleep(5)
                with _lock:
                    if _state["stop_flag"]: break
                flush()

            sniffer_stop[0] = True
            flush()
        except Exception as e:
            with _lock: _state["status"]="error"; _state["error"]=str(e)

        db.close_session(sid, sev_counts)
        with _lock: _state["status"]="done"

    # ── Routes ────────────────────────────────────────────────────────────
    @app.route("/")
    def index():
        ifaces = _get_ifaces()
        models_ready = detector.ready
        return render_template_string(HTML,
            ifaces=ifaces, models_ready=models_ready)

    @app.route("/upload", methods=["POST"])
    def upload():
        if not detector.ready:
            return jsonify({"error":"Models not trained. Run: python model_training.py --data ./datasets/"}),400
        if "file" not in request.files:
            return jsonify({"error":"No file"}),400
        f = request.files["file"]
        ext = os.path.splitext(f.filename or "")[1].lower()
        if ext not in ALLOWED_EXT:
            return jsonify({"error":f"Unsupported: {ext}. Use .pcap .pcapng .csv"}),400

        with _lock:
            if _state["status"] in ("analyzing","capturing"):
                return jsonify({"error":"Analysis already running"}),400
            _reset_state()
            _state["status"]      = "analyzing"
            _state["source"]      = f.filename
            _state["source_type"] = "file"

        fname = secure_filename(f.filename)
        path  = os.path.join(UPLOAD_DIR, fname)
        f.save(path)
        threading.Thread(target=_file_thread, args=(path, fname), daemon=True).start()
        return jsonify({"ok": True})

    @app.route("/start_capture", methods=["POST"])
    def start_capture():
        if not detector.ready:
            return jsonify({"error":"Models not trained"}),400
        iface = (request.json or {}).get("interface","").strip()
        if not iface:
            return jsonify({"error":"No interface"}),400
        with _lock:
            if _state["status"] in ("analyzing","capturing"):
                return jsonify({"error":"Already running"}),400
            _reset_state()
            _state["status"]      = "capturing"
            _state["source"]      = iface
            _state["source_type"] = "live"
        threading.Thread(target=_live_thread, args=(iface,), daemon=True).start()
        return jsonify({"ok": True})

    @app.route("/stop_capture", methods=["POST"])
    def stop_capture():
        with _lock: _state["stop_flag"] = True
        return jsonify({"ok":True})

    @app.route("/reset", methods=["POST"])
    def reset():
        with _lock:
            _state["stop_flag"] = True
            _reset_state()
        return jsonify({"ok":True})

    @app.route("/api/state")
    def api_state():
        with _lock: s = dict(_state)
        s["threats"] = s.pop("live_threats", [])[-200:]
        return jsonify(s)

    @app.route("/api/db/stats")
    def api_db_stats():
        return jsonify(db.get_stats())

    @app.route("/api/db/threats")
    def api_db_threats():
        return jsonify(db.get_threats(
            n=int(request.args.get("n",200)),
            level=request.args.get("level") or None,
            attack=request.args.get("attack") or None,
            ip=request.args.get("ip") or None,
            session_id=int(request.args["session"]) if request.args.get("session") else None,
        ))

    @app.route("/api/db/sessions")
    def api_db_sessions():
        return jsonify(db.get_sessions())

    @app.route("/api/logs")
    def api_logs():
        return jsonify({"lines": logger.read_last(300)})

    @app.route("/api/interfaces")
    def api_interfaces():
        return jsonify(_get_ifaces())

    return app


def _reset_state():
    _state.update({
        "status":"idle","source":"","source_type":"",
        "session_id":None,"total_flows":0,"analyzed":0,
        "live_threats":[],"sev_counts":{"HIGH":0,"MEDIUM":0,"LOW":0,"NORMAL":0},
        "atk_counts":{},"top_ips":{},"error":"","stop_flag":False,
    })


def _get_ifaces() -> list:
    ifaces = []
    try:
        with open("/proc/net/dev") as f:
            for line in f.readlines()[2:]:
                name = line.split(":")[0].strip()
                if name and name != "lo": ifaces.append(name)
    except: pass
    if not ifaces:
        import socket
        try:
            import netifaces
            ifaces = [i for i in netifaces.interfaces() if i != "lo"]
        except: ifaces = ["eth0","wlan0","ens33"]
    return ifaces


# ══════════════════════════════════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI Network Monitor</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#e6edf3;font-family:'Segoe UI',monospace;font-size:13px}
header{background:#161b22;padding:12px 20px;border-bottom:2px solid #21262d;
       display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px}
header h1{font-size:1.1rem;color:#58a6ff}
.status-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sdot{width:9px;height:9px;border-radius:50%;display:inline-block;margin-right:4px}
.sdot.idle{background:#484f58}.sdot.analyzing,.sdot.capturing{background:#3fb950;animation:bl 1s infinite}
.sdot.done{background:#58a6ff}.sdot.error{background:#f85149}
@keyframes bl{0%,100%{opacity:1}50%{opacity:.2}}
nav{background:#161b22;border-bottom:1px solid #21262d;display:flex;flex-wrap:wrap;padding:0 20px}
nav button{background:none;border:none;color:#8b949e;padding:10px 16px;cursor:pointer;
           font-size:.82rem;border-bottom:2px solid transparent;transition:.15s}
nav button.active,nav button:hover{color:#58a6ff;border-bottom-color:#58a6ff}
.pg{display:none;padding:14px}.pg.active{display:block}
/* layout */
.two-col{display:grid;grid-template-columns:300px 1fr;gap:12px;height:calc(100vh - 98px)}
.sidebar{overflow-y:auto;display:flex;flex-direction:column;gap:10px}
.main-area{overflow-y:auto;display:flex;flex-direction:column;gap:10px}
/* cards */
.section{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px}
.section h3{font-size:.68rem;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-bottom:10px}
/* upload */
.dz{border:2px dashed #30363d;border-radius:8px;padding:20px;text-align:center;
    cursor:pointer;position:relative;transition:.2s}
.dz:hover,.dz.drag{border-color:#58a6ff;background:#1c2128}
.dz input{position:absolute;inset:0;opacity:0;cursor:pointer;width:100%;height:100%}
.dz-icon{font-size:1.8rem;margin-bottom:6px}.dz-text{font-size:.8rem;color:#8b949e}
.dz-hint{font-size:.68rem;color:#484f58;margin-top:3px}
progress{width:100%;height:5px;border-radius:3px;accent-color:#58a6ff;display:block;margin-top:8px}
/* selects/inputs */
select,input{background:#21262d;border:1px solid #30363d;color:#e6edf3;
             padding:6px 10px;border-radius:6px;font-size:.8rem;outline:none;width:100%}
select:focus,input:focus{border-color:#58a6ff}
/* buttons */
.btn{border:none;padding:7px 14px;border-radius:6px;cursor:pointer;font-size:.8rem;
     font-weight:600;display:inline-flex;align-items:center;gap:5px;transition:.15s}
.btn-green{background:#2ea043;color:#fff}.btn-green:hover{background:#3fb950}
.btn-red{background:#da3633;color:#fff}.btn-red:hover{background:#f85149}
.btn-blue{background:#1f6feb;color:#fff}.btn-blue:hover{background:#388bfd}
.btn-gray{background:#21262d;color:#8b949e;border:1px solid #30363d}
.btn-gray:hover{color:#e6edf3}.btn:disabled{opacity:.4;cursor:not-allowed}
.btn-full{width:100%;justify-content:center;margin-top:6px}
/* stat cards */
.cards5{display:grid;grid-template-columns:repeat(5,1fr);gap:8px}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px;text-align:center}
.card .n{font-size:1.7rem;font-weight:700;margin:4px 0}
.card .l{font-size:.62rem;color:#8b949e;text-transform:uppercase;letter-spacing:1px}
.c-t .n{color:#e6edf3}.c-n .n{color:#3fb950}.c-h .n{color:#f85149}
.c-m .n{color:#e3b341}.c-l .n{color:#58a6ff}
/* charts */
.two-pan{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.panel{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:12px}
.panel h3{font-size:.68rem;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}
.br{display:flex;align-items:center;margin-bottom:5px;font-size:.75rem}
.bl{width:120px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#8b949e}
.bw{flex:1;background:#21262d;border-radius:3px;height:13px;overflow:hidden}
.b{height:100%;border-radius:3px;min-width:20px;display:flex;align-items:center;
   padding-left:4px;font-size:.65rem;color:#e6edf3;transition:width .4s}
.b-r{background:#da3633}.b-b{background:#1f6feb}
/* timeline */
.timeline{display:flex;align-items:flex-end;gap:3px;height:70px;overflow-x:auto;padding:2px 0}
.tb-g{display:flex;flex-direction:column;align-items:center;gap:1px}
.tb{width:18px;border-radius:2px 2px 0 0}.tb:hover{opacity:.75}
.tb-l{font-size:.52rem;color:#484f58;transform:rotate(-45deg);white-space:nowrap}
/* table */
.tw{overflow:auto;max-height:380px;background:#161b22;border:1px solid #21262d;border-radius:8px}
table{width:100%;border-collapse:collapse}
th{background:#21262d;padding:7px 9px;text-align:left;font-size:.65rem;
   color:#8b949e;text-transform:uppercase;letter-spacing:.5px;position:sticky;top:0;z-index:1;white-space:nowrap}
td{padding:6px 9px;border-bottom:1px solid #21262d;font-size:.75rem;white-space:nowrap}
tr:hover td{background:#1c2128}
/* badges */
.badge{padding:2px 7px;border-radius:20px;font-size:.65rem;font-weight:700}
.b-HIGH{background:#3d1a1a;color:#f85149;border:1px solid #f85149}
.b-MEDIUM{background:#2d2000;color:#e3b341;border:1px solid #e3b341}
.b-LOW{background:#0d2040;color:#58a6ff;border:1px solid #58a6ff}
.b-NORMAL{background:#0a2820;color:#3fb950;border:1px solid #3fb950}
/* search bar */
.sbar{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.sbar input,.sbar select{width:auto;flex:1;min-width:120px}
/* progress */
.pgbar-wrap{background:#21262d;border-radius:4px;height:7px;margin:5px 0;overflow:hidden}
.pgbar{height:100%;background:#58a6ff;border-radius:4px;transition:width .3s}
/* empty */
.empty{text-align:center;padding:50px 20px;color:#484f58}
.empty .ei{font-size:2.5rem;margin-bottom:8px}
/* pre */
pre{color:#3fb950;font-size:.72rem;font-family:monospace;white-space:pre-wrap;
    background:#010409;border-radius:6px;padding:10px;max-height:420px;overflow:auto}
/* warning */
.warn{background:#3d2000;border:1px solid #e3b341;border-radius:8px;
      padding:12px;color:#e3b341;font-size:.8rem;line-height:1.6;margin-bottom:10px}
code{color:#58a6ff;font-size:.78rem}
</style>
</head>
<body>
<header>
  <h1>&#127921; AI Network Monitor — Real-Time Threat Detection</h1>
  <div class="status-row">
    <span><span class="sdot idle" id="sdot"></span><span id="stxt">Idle</span></span>
    <button class="btn btn-gray" id="btn-reset" onclick="doReset()" style="display:none">&#128260; New Analysis</button>
    <span id="live-lbl" style="display:none;color:#3fb950;font-size:.8rem">&#128250; Live Capture Active</span>
  </div>
</header>

<nav>
  <button class="active" onclick="showPg('analyze',this)">&#128202; Analyze</button>
  <button onclick="showPg('database',this)">&#128190; Database</button>
  <button onclick="showPg('sessions',this)">&#128203; Sessions</button>
  <button onclick="showPg('eventlog',this)">&#128196; Event Log</button>
</nav>

<!-- ══ ANALYZE PAGE ═══════════════════════════════════════════════════════ -->
<div id="pg-analyze" class="pg active">
<div class="two-col">

  <!-- SIDEBAR -->
  <div class="sidebar">
    {% if not models_ready %}
    <div class="warn">
      ⚠️ <b>Models not trained.</b><br>Run in terminal:<br>
      <code>python model_training.py --data ./datasets/</code><br>Then refresh.
    </div>
    {% endif %}

    <!-- Upload -->
    <div class="section">
      <h3>&#128228; Upload Traffic File</h3>
      <div class="dz" id="dz"
           ondragover="event.preventDefault();this.classList.add('drag')"
           ondragleave="this.classList.remove('drag')"
           ondrop="onDrop(event)">
        <input type="file" id="finput" accept=".pcap,.pcapng,.csv" onchange="onFileSelect(this)">
        <div class="dz-icon">&#128228;</div>
        <div class="dz-text">Drop file here or <u>click to browse</u></div>
        <div class="dz-hint">.pcap &nbsp; .pcapng &nbsp; .csv (CICFlowMeter)</div>
      </div>
      <div id="upd" style="display:none">
        <div style="font-size:.72rem;color:#8b949e;margin-top:6px">Uploading <span id="upfn"></span>...</div>
        <progress id="upbar" value="0" max="100"></progress>
      </div>
    </div>

    <!-- Live Capture -->
    <div class="section">
      <h3>&#128225; Live Network Capture</h3>
      <p style="font-size:.72rem;color:#8b949e;margin-bottom:8px;line-height:1.5">
        Analyses real traffic from your network interface every 5 seconds.<br>
        <b style="color:#e3b341">Requires root:</b> <code>sudo python main.py</code>
      </p>
      <div style="display:flex;gap:6px;margin-bottom:8px">
        <select id="iface-sel" style="flex:1">
          {% for i in ifaces %}<option>{{i}}</option>{% endfor %}
        </select>
        <button class="btn btn-gray" onclick="refreshIfaces()">&#128260;</button>
      </div>
      <button class="btn btn-green btn-full" id="btn-start" onclick="startCapture()" {% if not models_ready %}disabled{% endif %}>
        &#9654; Start Live Capture
      </button>
      <button class="btn btn-red btn-full" id="btn-stop" onclick="stopCapture()" style="display:none">
        &#9632; Stop Capture
      </button>
    </div>

    <!-- Model info -->
    <div class="section">
      <h3>&#129504; AI Models</h3>
      {% if models_ready %}
      <div style="font-size:.75rem;line-height:1.9;color:#8b949e">
        <div>&#10003; Isolation Forest (anomaly)</div>
        <div>&#10003; Random Forest (classifier)</div>
        <div>&#10003; Trained on CICIDS2017</div>
        <div style="margin-top:6px;color:#484f58">
          DoS · DDoS · PortScan · BruteForce<br>WebAttack · Botnet · Infiltration
        </div>
      </div>
      {% else %}
      <div style="color:#f85149;font-size:.75rem">&#10007; Not trained</div>
      {% endif %}
    </div>
  </div>

  <!-- MAIN AREA -->
  <div class="main-area">

    <!-- empty state -->
    <div class="empty" id="empty-st">
      <div class="ei">&#128269;</div>
      <div>Upload a .pcap or .csv file, or start live capture</div>
      <div style="font-size:.75rem;margin-top:5px;color:#484f58">All results are stored in SQLite database</div>
    </div>

    <!-- progress -->
    <div class="section" id="prog-sec" style="display:none">
      <div style="display:flex;justify-content:space-between">
        <span id="prog-lbl">Analysing...</span>
        <span id="prog-pct" style="color:#8b949e">0%</span>
      </div>
      <div class="pgbar-wrap"><div class="pgbar" id="pgbar" style="width:0%"></div></div>
      <div id="prog-det" style="font-size:.68rem;color:#484f58;margin-top:4px"></div>
    </div>

    <!-- stats -->
    <div class="cards5" id="cards-sec" style="display:none">
      <div class="card c-t"><div class="l">Flows</div><div class="n" id="c-t">0</div></div>
      <div class="card c-n"><div class="l">Normal</div><div class="n" id="c-n">0</div></div>
      <div class="card c-h"><div class="l">HIGH</div><div class="n" id="c-h">0</div></div>
      <div class="card c-m"><div class="l">MEDIUM</div><div class="n" id="c-m">0</div></div>
      <div class="card c-l"><div class="l">LOW</div><div class="n" id="c-l">0</div></div>
    </div>

    <!-- charts -->
    <div class="two-pan" id="charts-sec" style="display:none">
      <div class="panel"><h3>Attack Distribution</h3><div id="atk-ch"></div></div>
      <div class="panel"><h3>Top Source IPs</h3><div id="ip-ch"></div></div>
    </div>

    <!-- threats table -->
    <div class="tw" id="tbl-sec" style="display:none">
      <table><thead><tr>
        <th>Time</th><th>Severity</th><th>Src IP</th><th>Dst IP</th>
        <th>Port</th><th>Proto</th><th>Attack</th><th>Score</th><th>Conf</th><th>Anomaly</th><th>Action</th>
      </tr></thead>
      <tbody id="t-body"><tr><td colspan="11" style="text-align:center;padding:24px;color:#484f58">
        No threats detected yet</td></tr></tbody></table>
    </div>

  </div>
</div>
</div>

<!-- ══ DATABASE PAGE ══════════════════════════════════════════════════════ -->
<div id="pg-database" class="pg">
  <!-- DB summary cards -->
  <div class="cards5" style="margin-bottom:12px">
    <div class="card c-t"><div class="l">Total Flows</div><div class="n" id="db-t">—</div></div>
    <div class="card c-n"><div class="l">Normal</div><div class="n" id="db-n">—</div></div>
    <div class="card c-h"><div class="l">HIGH</div><div class="n" id="db-h">—</div></div>
    <div class="card c-m"><div class="l">MEDIUM</div><div class="n" id="db-m">—</div></div>
    <div class="card c-l"><div class="l">LOW</div><div class="n" id="db-l">—</div></div>
  </div>

  <!-- charts -->
  <div class="two-pan" style="margin-bottom:12px">
    <div class="panel"><h3>All-time Attack Distribution</h3><div id="db-atk-ch"></div></div>
    <div class="panel"><h3>Hourly Activity</h3>
      <div class="timeline" id="db-timeline"></div></div>
  </div>

  <!-- search + table -->
  <div class="sbar">
    <input id="s-ip" placeholder="Filter by IP...">
    <select id="s-lvl"><option value="">All Levels</option>
      <option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
    <select id="s-atk"><option value="">All Attacks</option>
      <option>DoS</option><option>DDoS</option><option>PortScan</option>
      <option>BruteForce</option><option>WebAttack</option>
      <option>Botnet</option><option>Infiltration</option></select>
    <button class="btn btn-blue" onclick="searchDB()">Search</button>
    <button class="btn btn-gray" onclick="clearSearch()">Clear</button>
  </div>
  <div class="tw">
    <table><thead><tr>
      <th>ID</th><th>Time</th><th>Session</th><th>Severity</th>
      <th>Src IP</th><th>Dst IP</th><th>Port</th><th>Attack</th>
      <th>Score</th><th>Conf</th><th>Action</th>
    </tr></thead>
    <tbody id="db-tbody"><tr><td colspan="11" style="text-align:center;padding:24px;color:#484f58">
      Loading...</td></tr></tbody></table>
  </div>
</div>

<!-- ══ SESSIONS PAGE ══════════════════════════════════════════════════════ -->
<div id="pg-sessions" class="pg">
  <div class="tw">
    <table><thead><tr>
      <th>ID</th><th>Started</th><th>Source</th><th>Type</th>
      <th>Flows</th><th>HIGH</th><th>MEDIUM</th><th>LOW</th><th>Action</th>
    </tr></thead>
    <tbody id="sess-tbody"><tr><td colspan="9" style="text-align:center;padding:24px;color:#484f58">
      Loading...</td></tr></tbody></table>
  </div>
</div>

<!-- ══ EVENT LOG PAGE ═════════════════════════════════════════════════════ -->
<div id="pg-eventlog" class="pg">
  <div class="section">
    <h3>&#128196; Event Log — logs/events.log</h3>
    <pre id="log-pre">Loading...</pre>
  </div>
</div>

<script>
let polling=null, lastTCount=0, currentPg='analyze';

function showPg(name,btn){
  document.querySelectorAll('.pg').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('nav button').forEach(b=>b.classList.remove('active'));
  document.getElementById('pg-'+name).classList.add('active');
  btn.classList.add('active');
  currentPg=name;
  if(name==='database'){loadDB();loadDBThreats();}
  if(name==='sessions') loadSessions();
  if(name==='eventlog') loadLog();
}

// ── Upload ────────────────────────────────────────────────────────────────
function onDrop(ev){ev.preventDefault();document.getElementById('dz').classList.remove('drag');const f=ev.dataTransfer.files[0];if(f)doUpload(f);}
function onFileSelect(inp){if(inp.files[0])doUpload(inp.files[0]);}
function doUpload(file){
  const ext=file.name.split('.').pop().toLowerCase();
  if(!['pcap','pcapng','csv'].includes(ext)){alert('Use .pcap .pcapng .csv');return;}
  document.getElementById('upfn').textContent=file.name;
  document.getElementById('upd').style.display='block';
  const fd=new FormData();fd.append('file',file);
  const xhr=new XMLHttpRequest();
  xhr.upload.onprogress=e=>{if(e.lengthComputable)document.getElementById('upbar').value=(e.loaded/e.total*100)|0;};
  xhr.onload=()=>{
    document.getElementById('upd').style.display='none';
    const r=JSON.parse(xhr.responseText);
    if(r.error){alert('Error: '+r.error);return;}
    startPolling();
  };
  xhr.onerror=()=>alert('Upload failed');
  xhr.open('POST','/upload');xhr.send(fd);
}

// ── Live Capture ──────────────────────────────────────────────────────────
function startCapture(){
  const iface=document.getElementById('iface-sel').value;
  if(!iface){alert('Select interface');return;}
  fetch('/start_capture',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({interface:iface})})
    .then(r=>r.json()).then(d=>{
      if(d.error){alert('Error: '+d.error);return;}
      document.getElementById('btn-start').style.display='none';
      document.getElementById('btn-stop').style.display='block';
      document.getElementById('live-lbl').style.display='inline';
      startPolling();
    });
}
function stopCapture(){
  fetch('/stop_capture',{method:'POST'}).then(()=>{
    document.getElementById('btn-start').style.display='block';
    document.getElementById('btn-stop').style.display='none';
    document.getElementById('live-lbl').style.display='none';
  });
}

// ── Reset ─────────────────────────────────────────────────────────────────
function doReset(){
  fetch('/reset',{method:'POST'}).then(()=>{
    stopPolling();lastTCount=0;
    document.getElementById('empty-st').style.display='block';
    ['prog-sec','cards-sec','charts-sec','tbl-sec'].forEach(id=>document.getElementById(id).style.display='none');
    document.getElementById('btn-reset').style.display='none';
    document.getElementById('sdot').className='sdot idle';
    document.getElementById('stxt').textContent='Idle';
    document.getElementById('btn-start').style.display='block';
    document.getElementById('btn-stop').style.display='none';
    document.getElementById('live-lbl').style.display='none';
  });
}

// ── Polling ───────────────────────────────────────────────────────────────
function startPolling(){if(polling)clearInterval(polling);polling=setInterval(fetchState,1500);fetchState();}
function stopPolling(){if(polling)clearInterval(polling);polling=null;}

async function fetchState(){
  const d=await fetch('/api/state').then(r=>r.json()).catch(()=>null);
  if(!d)return;
  const s=d.status;
  // dot
  document.getElementById('sdot').className='sdot '+s;
  document.getElementById('stxt').textContent={idle:'Idle',analyzing:'Analysing...',capturing:'Live Capture',done:'Done',error:'Error'}[s]||s;
  document.getElementById('btn-reset').style.display=(s==='done'||s==='error')?'inline-flex':'none';
  if(s==='error'){stopPolling();if(d.error)alert('Error: '+d.error);return;}
  if(s==='done'&&d.source_type==='file')stopPolling();

  const has=d.analyzed>0;
  document.getElementById('empty-st').style.display=has?'none':'block';
  document.getElementById('prog-sec').style.display=s==='analyzing'?'block':'none';
  document.getElementById('cards-sec').style.display=has?'grid':'none';
  document.getElementById('charts-sec').style.display=has?'grid':'none';
  document.getElementById('tbl-sec').style.display=has?'block':'none';

  // progress
  if(s==='analyzing'){
    const pct=d.total_flows>0?Math.round(d.analyzed/d.total_flows*100):0;
    document.getElementById('pgbar').style.width=pct+'%';
    document.getElementById('prog-pct').textContent=pct+'%';
    document.getElementById('prog-lbl').textContent='Analysing: '+d.source;
    document.getElementById('prog-det').textContent=d.analyzed.toLocaleString()+' / '+(d.total_flows||'?').toLocaleString()+' flows';
  }

  // cards
  const sc=d.sev_counts||{};
  document.getElementById('c-t').textContent=d.analyzed.toLocaleString();
  document.getElementById('c-n').textContent=(sc.NORMAL||0).toLocaleString();
  document.getElementById('c-h').textContent=(sc.HIGH||0).toLocaleString();
  document.getElementById('c-m').textContent=(sc.MEDIUM||0).toLocaleString();
  document.getElementById('c-l').textContent=(sc.LOW||0).toLocaleString();

  // atk chart
  const ac=d.atk_counts||{},mxa=Math.max(...Object.values(ac),1);
  document.getElementById('atk-ch').innerHTML=Object.keys(ac).length
    ?Object.entries(ac).sort((a,b)=>b[1]-a[1]).map(([k,v])=>
      `<div class="br"><div class="bl">${k}</div><div class="bw"><div class="b b-r" style="width:${Math.max(Math.round(v/mxa*100),4)}%">${v}</div></div></div>`).join('')
    :'<div style="color:#484f58;font-size:.75rem">No attacks</div>';

  // ip chart
  const ips=d.top_ips||{},mxi=Math.max(...Object.values(ips),1);
  document.getElementById('ip-ch').innerHTML=Object.keys(ips).length
    ?Object.entries(ips).map(([k,v])=>
      `<div class="br"><div class="bl"><code>${k}</code></div><div class="bw"><div class="b b-b" style="width:${Math.max(Math.round(v/mxi*100),4)}%">${v}</div></div></div>`).join('')
    :'<div style="color:#484f58;font-size:.75rem">No suspicious IPs</div>';

  // threat table
  const threats=d.threats||[];
  if(threats.length!==lastTCount){
    lastTCount=threats.length;
    const cl={HIGH:'#f85149',MEDIUM:'#e3b341',LOW:'#58a6ff',NORMAL:'#3fb950'};
    document.getElementById('t-body').innerHTML=threats.length
      ?[...threats].reverse().map(t=>`<tr>
          <td style="color:#8b949e">${t.timestamp||''}</td>
          <td><span class="badge b-${t.severity}">${t.severity}</span></td>
          <td><code>${t.src_ip}</code></td>
          <td><code>${t.dst_ip}</code></td>
          <td>${t.dst_port}</td><td>${t.protocol}</td>
          <td style="color:${cl[t.severity]};font-weight:600">${t.attack}</td>
          <td style="color:${cl[t.severity]}">${(t.composite_score*100).toFixed(1)}%</td>
          <td>${(t.confidence*100).toFixed(1)}%</td>
          <td>${t.is_anomaly?'⚠ Yes':'No'}</td>
          <td style="color:#8b949e;font-size:.68rem">${t.response_action||'—'}</td>
        </tr>`).join('')
      :'<tr><td colspan="11" style="text-align:center;padding:24px;color:#3fb950">&#10003; All normal — no threats</td></tr>';
  }
}

// ── Database page ──────────────────────────────────────────────────────────
async function loadDB(){
  const d=await fetch('/api/db/stats').then(r=>r.json()).catch(()=>({}));
  document.getElementById('db-t').textContent=(d.total||0).toLocaleString();
  document.getElementById('db-n').textContent=(d.normal||0).toLocaleString();
  document.getElementById('db-h').textContent=(d.high||0).toLocaleString();
  document.getElementById('db-m').textContent=(d.medium||0).toLocaleString();
  document.getElementById('db-l').textContent=(d.low||0).toLocaleString();
  // attack chart
  const ac=d.attack_counts||{},mxa=Math.max(...Object.values(ac),1);
  document.getElementById('db-atk-ch').innerHTML=Object.keys(ac).length
    ?Object.entries(ac).sort((a,b)=>b[1]-a[1]).map(([k,v])=>
      `<div class="br"><div class="bl">${k}</div><div class="bw"><div class="b b-r" style="width:${Math.max(Math.round(v/mxa*100),4)}%">${v}</div></div></div>`).join('')
    :'<div style="color:#484f58;font-size:.75rem">No data</div>';
  // timeline
  const h=d.hourly||[],mxh=Math.max(...h.map(x=>x.total),1);
  document.getElementById('db-timeline').innerHTML=h.map(x=>{
    const ht=Math.round(x.total/mxh*58);
    const lbl=x.hour?x.hour.slice(11,16):'';
    return `<div class="tb-g"><div class="tb" style="height:${ht}px;background:#1f6feb" title="${x.hour}: ${x.total}"></div><div class="tb-l">${lbl}</div></div>`;
  }).join('')||'<div style="color:#484f58;font-size:.75rem">No data</div>';
}

async function loadDBThreats(extra=''){
  const d=await fetch('/api/db/threats?n=200'+extra).then(r=>r.json()).catch(()=>[]);
  const cl={HIGH:'#f85149',MEDIUM:'#e3b341',LOW:'#58a6ff'};
  document.getElementById('db-tbody').innerHTML=d.length
    ?d.map(t=>`<tr>
        <td style="color:#484f58">#${t.id}</td>
        <td style="color:#8b949e;font-size:.68rem">${t.timestamp}</td>
        <td style="color:#484f58">${t.session_id}</td>
        <td><span class="badge b-${t.severity}">${t.severity}</span></td>
        <td><code>${t.src_ip}</code></td><td><code>${t.dst_ip}</code></td>
        <td>${t.dst_port}</td>
        <td style="color:${cl[t.severity]||'#e6edf3'};font-weight:600">${t.attack}</td>
        <td style="color:${cl[t.severity]||'#e6edf3'}">${(t.composite_score*100).toFixed(1)}%</td>
        <td>${(t.confidence*100).toFixed(1)}%</td>
        <td style="color:#8b949e;font-size:.68rem">${t.response_action||'—'}</td>
      </tr>`).join('')
    :'<tr><td colspan="11" style="text-align:center;padding:24px;color:#484f58">No threats in database</td></tr>';
}

function searchDB(){
  const ip=document.getElementById('s-ip').value;
  const lv=document.getElementById('s-lvl').value;
  const at=document.getElementById('s-atk').value;
  const p=new URLSearchParams();
  if(ip)p.append('ip',ip);if(lv)p.append('level',lv);if(at)p.append('attack',at);
  loadDBThreats(p.toString()?'&'+p:'');
}
function clearSearch(){
  ['s-ip'].forEach(id=>document.getElementById(id).value='');
  ['s-lvl','s-atk'].forEach(id=>document.getElementById(id).selectedIndex=0);
  loadDBThreats();
}

// ── Sessions ───────────────────────────────────────────────────────────────
async function loadSessions(){
  const d=await fetch('/api/db/sessions').then(r=>r.json()).catch(()=>[]);
  document.getElementById('sess-tbody').innerHTML=d.length
    ?d.map(s=>`<tr>
        <td style="color:#484f58">#${s.id}</td>
        <td style="color:#8b949e;font-size:.72rem">${s.started_at}</td>
        <td><code>${s.source}</code></td>
        <td style="color:#8b949e">${s.source_type}</td>
        <td>${(s.total_flows||0).toLocaleString()}</td>
        <td style="color:#f85149">${s.high_count||0}</td>
        <td style="color:#e3b341">${s.medium_count||0}</td>
        <td style="color:#58a6ff">${s.low_count||0}</td>
        <td><button class="btn btn-gray" style="padding:3px 8px;font-size:.68rem"
            onclick="viewSession(${s.id})">View</button></td>
      </tr>`).join('')
    :'<tr><td colspan="9" style="text-align:center;padding:24px;color:#484f58">No sessions yet</td></tr>';
}
function viewSession(sid){
  showPg('database',document.querySelector('nav button:nth-child(2)'));
  loadDB();loadDBThreats('&session='+sid);
}

// ── Event Log ──────────────────────────────────────────────────────────────
async function loadLog(){
  const d=await fetch('/api/logs').then(r=>r.json()).catch(()=>({lines:[]}));
  document.getElementById('log-pre').textContent=d.lines.length?d.lines.join('\n'):'No events logged yet.';
}

// ── Interfaces refresh ─────────────────────────────────────────────────────
async function refreshIfaces(){
  const d=await fetch('/api/interfaces').then(r=>r.json()).catch(()=>[]);
  const sel=document.getElementById('iface-sel');
  sel.innerHTML=d.map(i=>`<option>${i}</option>`).join('');
}

// ── Init ───────────────────────────────────────────────────────────────────
fetchState().then(()=>{
  const s=document.getElementById('sdot').className;
  if(s.includes('analyzing')||s.includes('capturing'))startPolling();
});
// Auto-refresh DB page when active
setInterval(()=>{
  if(currentPg==='database'){loadDB();loadDBThreats();}
  if(currentPg==='eventlog')loadLog();
}, 5000);
</script>
</body>
</html>"""
