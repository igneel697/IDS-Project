# Real-Time Network Intrusion Detection System

Academic project implementing hybrid IDS using rule-based and ML approaches.

## Tech Stack
- Backend: Python, Flask
- Frontend: React
- Database: MySQL
- ML: scikit-learn
- Packet Capture: Wireshark/tshark

## Author
Pranjal Neupane, Himakshi Bakhariya, Dilisha Shrestha - IDS Project 2026
## Week 1 Progress ✓

### Completed:
* Environment setup (WSL, Python, MySQL, Wireshark)
* Database creation (6 tables)
* NSL-KDD dataset downloaded and preprocessed
  + Reduced to 20 features (removed high-signal dst_host_* counters)
  + 60-40 stratified split: 75,583 train / 50,390 test samples
* ML models trained
  + Random Forest: ~85-90% accuracy (constrained depth/features)
  + Naïve Bayes: ~82-88% accuracy (ComplementNB with MinMaxScaler)
* Targets met: TPR ≥85% ✓, FPR ≤15% ✓

### Next Steps (Week 2):
- [ ] Implement rule-based detection
- [ ] Implement hybrid decision logic
- [ ] Implement risk scoring algorithm
- [ ] Create alert manager
