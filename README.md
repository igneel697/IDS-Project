# Real-Time Network Intrusion Detection System

Academic project implementing a hybrid IDS using rule-based and ML approaches.

## Tech Stack

- Backend: Python, Flask
- Frontend: React
- Database: MySQL
- ML: scikit-learn
- Packet Capture: Wireshark/tshark

## Authors

Pranjal Neupane (79010786), Himakshi Bakhariya (79010776), Dilisha Shrestha (79010773) — IDS Project 2026

---

## Week 1 Progress ✓

### Completed

- Environment setup (WSL, Python venv, MySQL, Wireshark)
- Database creation (6 tables)
- NSL-KDD dataset downloaded and preprocessed
  - Reduced to 20 features (removed high-signal dst_host_* counters)
  - Stratified 60-40 split: 75,583 train / 50,390 test samples
- ML models trained and verified
  - Random Forest: ~85-90% accuracy (constrained: max_depth=5, max_features=2)
  - Naïve Bayes: ~82-88% accuracy (ComplementNB with MinMaxScaler)
  - Targets met: TPR ≥85% ✓, FPR ≤15% ✓
- Packet capture module working
  - Real-time capture via tshark
  - Thread-safe queue, 10,000 packet buffer
  - Tested: 49 packets captured, 0 dropped

## Week 2 Progress ✓

### Completed

- Feature extraction module
  - Converts raw captured packets into 20 NSL-KDD features
  - Sliding window of 100 packets for statistical calculations
- Rule-based detection engine
  - DoS: flags 100+ packets/sec to same destination
  - Port scan: flags 20+ unique ports from same source
  - Brute force: flags 10+ attempts to auth ports (SSH, FTP, Telnet)
  - Land attack: flags packets where source IP equals destination IP
- ML-based detection engine
  - Random Forest and Naïve Bayes running in parallel
  - Dual scaler system (StandardScaler for RF, MinMaxScaler for NB)
  - 70% confidence threshold to filter low-confidence predictions
- Risk scoring system (0-100)
  - U2R: base 90, R2L: base 70, DoS: base 60, Probe: base 40
  - Score weighted by model confidence and detection frequency
- Alert manager
  - Saves all alerts to MySQL (ids_database)
  - Severity levels: Low, Medium, High, Critical
- Full IDS pipeline
  - End-to-end: capture → extract → detect → score → save
  - Tested: 523 packets, 89 alerts detected during port scan simulation
  
## About

Final Year Project on a live IDS using Wireshark and tshark