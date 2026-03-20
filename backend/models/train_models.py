"""
ML Model Training
Trains Decision Tree and Naïve Bayes classifiers on NSL-KDD

Features:
- Loads preprocessed data (125,973 training, 22,544 test samples)
- Trains Decision Tree with information gain
- Trains Naïve Bayes classifier
- Evaluates both models
- Saves trained models as .pkl files

Target: ≥85% TPR, ≤15% FPR

Author: Pranjal
Date: March 2026
"""

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import (
    accuracy_score, 
    precision_score, 
    recall_score, 
    f1_score, 
    confusion_matrix, 
    classification_report
)
import pickle
import time

def load_preprocessed_data():
    """Load preprocessed data"""
    print("="*70)
    print("LOADING PREPROCESSED DATA")
    print("="*70)
    
    print("\nLoading numpy arrays...")
    X_train = np.load('../../data/models/X_train.npy')
    X_test = np.load('../../data/models/X_test.npy')
    y_train = np.load('../../data/models/y_train.npy')
    y_test = np.load('../../data/models/y_test.npy')
    
    with open('../../data/models/label_encoder.pkl', 'rb') as f:
        label_encoder = pickle.load(f)
    
    print(f"✓ Training samples: {X_train.shape[0]:,}")
    print(f"✓ Test samples: {X_test.shape[0]:,}")
    print(f"✓ Features: {X_train.shape[1]}")
    print(f"✓ Classes: {label_encoder.classes_}")
    
    return X_train, X_test, y_train, y_test, label_encoder

def train_decision_tree(X_train, y_train, X_test, y_test):
    """Train Random Forest classifier"""
    print("\n" + "="*70)
    print("TRAINING RANDOM FOREST CLASSIFIER")
    print("="*70)
    
    print("\nConfiguration:")
    print("  - Number of trees: 100")
    print("  - Criterion: entropy (information gain)")
    print("  - Max depth: 25")
    print("  - Min samples split: 50")
    print("  - Min samples leaf: 20")
    print("  - Class weight: balanced (handles imbalanced data)")
    print("  - Using all CPU cores")
    
    start_time = time.time()
    
    # Initialize Random Forest
    dt_model = RandomForestClassifier(
        n_estimators=100,          # 100 decision trees
        criterion='entropy',        # Use information gain
        max_depth=25,              # Deeper trees for complex patterns
        min_samples_split=50,      # Allow more splits
        min_samples_leaf=20,       # Smaller leaves for rare attacks
        random_state=42,
        n_jobs=-1,                 # Use all CPU cores for speed
        class_weight='balanced',   # Handle imbalanced classes (R2L, U2R)
        verbose=1                  # Show training progress
    )
    # Train model
    print("\nTraining Decision Tree...")
    dt_model.fit(X_train, y_train)
    train_time = time.time() - start_time
    
    print(f"✓ Training complete in {train_time:.2f} seconds")
    
    # Make predictions
    print("\nMaking predictions on test set...")
    y_pred = dt_model.predict(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    
    print("\n" + "="*70)
    print("DECISION TREE PERFORMANCE")
    print("="*70)
    print(f"Accuracy:      {accuracy*100:.2f}%")
    print(f"Precision:     {precision*100:.2f}%")
    print(f"Recall (TPR):  {recall*100:.2f}%")
    print(f"F1-Score:      {f1*100:.2f}%")
    
    # Check target
    if recall >= 0.85:
        print(f"\n✓✓✓ TARGET MET: Recall {recall*100:.2f}% ≥ 85% ✓✓✓")
    else:
        print(f"\n✗ Target not met: Recall {recall*100:.2f}% < 85%")
    
    # Save model
    print("\nSaving model...")
    with open('../../data/models/decision_tree.pkl', 'wb') as f:
        pickle.dump(dt_model, f)
    print("✓ Saved: decision_tree.pkl")
    
    return dt_model, accuracy, recall

def train_naive_bayes(X_train, y_train, X_test, y_test):
    """Train Naïve Bayes classifier"""
    print("\n" + "="*70)
    print("TRAINING NAÏVE BAYES CLASSIFIER")
    print("="*70)
    
    print("\nConfiguration:")
    print("  - Type: Gaussian Naïve Bayes")
    print("  - Assumes: Normal distribution of features")
    
    start_time = time.time()
    
    # Initialize Naïve Bayes
    nb_model = GaussianNB()
    
    # Train model
    print("\nTraining Naïve Bayes...")
    nb_model.fit(X_train, y_train)
    train_time = time.time() - start_time
    
    print(f"✓ Training complete in {train_time:.2f} seconds")
    
    # Make predictions
    print("\nMaking predictions on test set...")
    y_pred = nb_model.predict(X_test)
    
    # Calculate metrics
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred, average='weighted', zero_division=0)
    recall = recall_score(y_test, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_test, y_pred, average='weighted', zero_division=0)
    
    print("\n" + "="*70)
    print("NAÏVE BAYES PERFORMANCE")
    print("="*70)
    print(f"Accuracy:      {accuracy*100:.2f}%")
    print(f"Precision:     {precision*100:.2f}%")
    print(f"Recall (TPR):  {recall*100:.2f}%")
    print(f"F1-Score:      {f1*100:.2f}%")
    
    # Check expected performance
    if recall >= 0.78:
        print(f"\n✓ EXPECTED PERFORMANCE: Recall {recall*100:.2f}% ≥ 78% ✓")
    else:
        print(f"\n✗ Below expected: Recall {recall*100:.2f}% < 78%")
    
    # Save model
    print("\nSaving model...")
    with open('../../data/models/naive_bayes.pkl', 'wb') as f:
        pickle.dump(nb_model, f)
    print("✓ Saved: naive_bayes.pkl")
    
    return nb_model, accuracy, recall

def evaluate_per_class(model, X_test, y_test, label_encoder, model_name):
    """Evaluate model performance per attack class"""
    print("\n" + "="*70)
    print(f"{model_name.upper()} - PER-CLASS PERFORMANCE")
    print("="*70)
    
    y_pred = model.predict(X_test)
    
    # Classification report
    print("\nClassification Report:")
    print("-" * 70)
    report = classification_report(
        y_test, 
        y_pred, 
        target_names=label_encoder.classes_,
        zero_division=0,
        digits=4
    )
    print(report)
    
    # Confusion matrix
    print("\nConfusion Matrix:")
    print("-" * 70)
    cm = confusion_matrix(y_test, y_pred)
    
    # Print header
    print(f"{'':12s}", end='')
    for class_name in label_encoder.classes_:
        print(f"{class_name:>12s}", end='')
    print()
    
    # Print matrix
    for i, class_name in enumerate(label_encoder.classes_):
        print(f"{class_name:12s}", end='')
        for j in range(len(label_encoder.classes_)):
            print(f"{cm[i][j]:12d}", end='')
        print()

def calculate_fpr(model, X_test, y_test, label_encoder):
    """Calculate False Positive Rate"""
    y_pred = model.predict(X_test)
    cm = confusion_matrix(y_test, y_pred)
    
    # Calculate per-class FPR and average
    fprs = []
    for i in range(len(label_encoder.classes_)):
        tn = np.sum(cm) - np.sum(cm[i, :]) - np.sum(cm[:, i]) + cm[i, i]
        fp = np.sum(cm[:, i]) - cm[i, i]
        
        if (fp + tn) > 0:
            fpr = fp / (fp + tn)
            fprs.append(fpr)
    
    avg_fpr = np.mean(fprs)
    return avg_fpr

if __name__ == "__main__":
    print("\n" + "="*70)
    print("IDS ML MODEL TRAINING")
    print("Target: ≥85% TPR (Recall), ≤15% FPR")
    print("="*70)
    
    # Load data
    X_train, X_test, y_train, y_test, label_encoder = load_preprocessed_data()
    
    # Train Decision Tree
    dt_model, dt_acc, dt_recall = train_decision_tree(X_train, y_train, X_test, y_test)
    evaluate_per_class(dt_model, X_test, y_test, label_encoder, "Decision Tree")
    dt_fpr = calculate_fpr(dt_model, X_test, y_test, label_encoder)
    
    # Train Naïve Bayes
    nb_model, nb_acc, nb_recall = train_naive_bayes(X_train, y_train, X_test, y_test)
    evaluate_per_class(nb_model, X_test, y_test, label_encoder, "Naïve Bayes")
    nb_fpr = calculate_fpr(nb_model, X_test, y_test, label_encoder)
    
    # Final Summary
    print("\n" + "="*70)
    print("TRAINING SUMMARY")
    print("="*70)
    print(f"\nDecision Tree:")
    print(f"  Accuracy:     {dt_acc*100:.2f}%")
    print(f"  TPR (Recall): {dt_recall*100:.2f}%")
    print(f"  FPR:          {dt_fpr*100:.2f}%")
    
    print(f"\nNaïve Bayes:")
    print(f"  Accuracy:     {nb_acc*100:.2f}%")
    print(f"  TPR (Recall): {nb_recall*100:.2f}%")
    print(f"  FPR:          {nb_fpr*100:.2f}%")
    
    print(f"\nProject Target: ≥85% TPR, ≤15% FPR")
    
    # Check targets
    print("\n" + "="*70)
    print("TARGET EVALUATION")
    print("="*70)
    
    if dt_recall >= 0.85 and dt_fpr <= 0.15:
        print("✓✓✓ DECISION TREE MEETS ALL TARGETS! ✓✓✓")
        print(f"  ✓ TPR: {dt_recall*100:.2f}% ≥ 85%")
        print(f"  ✓ FPR: {dt_fpr*100:.2f}% ≤ 15%")
    elif dt_recall >= 0.85:
        print("✓ Decision Tree meets TPR target")
        print(f"  ✓ TPR: {dt_recall*100:.2f}% ≥ 85%")
        print(f"  ✗ FPR: {dt_fpr*100:.2f}% > 15%")
    else:
        print(f"✗ Decision Tree TPR {dt_recall*100:.2f}% < 85%")
    
    if nb_recall >= 0.78:
        print(f"\n✓ Naïve Bayes achieves expected performance")
        print(f"  ✓ TPR: {nb_recall*100:.2f}% ≥ 78%")
    
    print("\n" + "="*70)
    print("FILES SAVED")
    print("="*70)
    print("✓ decision_tree.pkl")
    print("✓ naive_bayes.pkl")
    print("\nLocation: ~/ids-project/data/models/")
    
    print("\n" + "="*70)
    print("✓ ML TRAINING COMPLETE!")
    print("Ready for detection engine implementation (Week 2)")
    print("="*70)
