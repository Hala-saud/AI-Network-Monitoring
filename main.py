"""
main.py — Entry Point
AI-Based Intelligent Network Monitoring & Automated Threat Response System
==========================================================================
Starts the Flask web application. All analysis is triggered from the browser:
  - Upload a PCAP or CSV file
  - Start / stop live capture from a network interface
  - Real results from CICIDS2017-trained AI models
  - No fake data, no simulated ports, no pseudo attacks

Usage:
  python main.py
  sudo python main.py          # required for live capture
  python main.py --port 8080
"""

import argparse
from dashboard import create_app

def main():
    parser = argparse.ArgumentParser(description="AI Network Monitor")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    app = create_app()

    print("""
╔══════════════════════════════════════════════════════════════╗
║   AI-Based Intelligent Network Monitoring System             ║
║   نظام ذكي لمراقبة الشبكة والاستجابة التلقائية للتهديدات    ║
╠══════════════════════════════════════════════════════════════╣
║  Stage 1 : Traffic Capture      (Upload PCAP/CSV or Live)   ║
║  Stage 2 : Feature Extraction   (CICFlowMeter format)       ║
║  Stage 3 : AI Detection         (Isolation Forest + RF)     ║
║  Stage 4 : Threat Scoring       (Low / Medium / High)       ║
║  Stage 5 : Automated Response   (Block / Alert / Log)       ║
║  Stage 6 : Dashboard & Logging  (Flask + SQLite)            ║
╚══════════════════════════════════════════════════════════════╝
""")
    print(f"  Open browser → http://localhost:{args.port}\n")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)

if __name__ == "__main__":
    main()
