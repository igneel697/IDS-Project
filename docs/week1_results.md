# Week 1 Results - ML Model Training

## Date: March 20, 2026

## Dataset
- **Source:** NSL-KDD
- **Training samples:** 100,778
- **Test samples:** 25,195
- **Features:** 41
- **Classes:** 5 (dos, normal, probe, r2l, u2r)

## Model Performance

### Decision Tree (Random Forest)
- **Accuracy:** 99.58% ✓
- **True Positive Rate (Recall):** 99.58% ✓ (Target: ≥85%)
- **False Positive Rate:** 0.11% ✓ (Target: ≤15%)
- **Precision:** 99.67%
- **F1-Score:** 99.62%

**Per-Class Performance:**
| Class | Precision | Recall | F1-Score | Support |
|-------|-----------|--------|----------|---------|
| DoS | 99.97% | 99.95% | 99.96% | 9,186 |
| Normal | 99.80% | 99.45% | 99.62% | 13,469 |
| Probe | 99.06% | 99.06% | 99.06% | 2,331 |
| R2L | 87.84% | 97.99% | 92.64% | 199 |
| U2R | 27.78% | 100.00% | 43.48% | 10 |

### Naïve Bayes
- **Accuracy:** 44.36%
- **True Positive Rate (Recall):** 44.36% (Below expected)
- **False Positive Rate:** 15.22%
- **Note:** Used as backup classifier in hybrid system

## Configuration
- **Random Forest Trees:** 100
- **Max Depth:** 25
- **Min Samples Split:** 50
- **Min Samples Leaf:** 20
- **Class Weight:** Balanced
- **Train-Test Split:** 80-20 stratified

## Conclusion
✅ **Decision Tree model meets all project targets**
✅ **Ready for integration into detection engine**
✅ **Week 1 objectives achieved**

## Files Generated
- decision_tree.pkl (3.9 MB)
- naive_bayes.pkl (3.9 KB)
- label_encoder.pkl (278 bytes)
- label_encoders.pkl (1.1 KB)
- scaler.pkl (2.2 KB)
- X_train.npy, X_test.npy, y_train.npy, y_test.npy
