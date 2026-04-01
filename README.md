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


## About

Final Year Project on a live IDS using Wireshark and tshark