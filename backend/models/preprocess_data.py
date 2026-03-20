
"""
NSL-KDD Data Preprocessing Script
Loads, cleans, and prepares NSL-KDD dataset for ML training

Features:
- Loads 125,973 training samples and 22,544 test samples
- Maps 39 specific attacks to 5 categories (normal, dos, probe, r2l, u2r)
- Encodes categorical features (protocol_type, service, flag)
- Normalizes 41 numerical features
- Saves preprocessed data and encoders for later use

Author: Pranjal Neupane
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import pickle
import os

# Column names for NSL-KDD dataset (41 features + label + difficulty)
COLUMN_NAMES = [
    # Basic features (9)
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent',
    
    # Content features (13)
    'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login',
    
    # Traffic features (9)
    'count', 'srv_count', 'serror_rate', 'srv_serror_rate', 'rerror_rate',
    'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    
    # Time-based features (10)
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    
    # Label and difficulty
    'label', 'difficulty'
]

# Attack type mapping (39 specific attacks → 5 categories)
ATTACK_MAPPING = {
    'normal': 'normal',
    
    # DoS attacks (Denial of Service)
    'back': 'dos', 'land': 'dos', 'neptune': 'dos', 'pod': 'dos',
    'smurf': 'dos', 'teardrop': 'dos', 'apache2': 'dos', 'udpstorm': 'dos',
    'processtable': 'dos', 'mailbomb': 'dos',
    
    # Probe attacks (Reconnaissance/Scanning)
    'ipsweep': 'probe', 'nmap': 'probe', 'portsweep': 'probe', 'satan': 'probe',
    'mscan': 'probe', 'saint': 'probe',
    
    # R2L attacks (Remote to Local - unauthorized access from remote)
    'ftp_write': 'r2l', 'guess_passwd': 'r2l', 'imap': 'r2l', 'multihop': 'r2l',
    'phf': 'r2l', 'spy': 'r2l', 'warezclient': 'r2l', 'warezmaster': 'r2l',
    'sendmail': 'r2l', 'named': 'r2l', 'snmpgetattack': 'r2l', 'snmpguess': 'r2l',
    'xlock': 'r2l', 'xsnoop': 'r2l', 'worm': 'r2l',
    
    # U2R attacks (User to Root - privilege escalation)
    'buffer_overflow': 'u2r', 'loadmodule': 'u2r', 'perl': 'u2r', 'rootkit': 'u2r',
    'httptunnel': 'u2r', 'ps': 'u2r', 'sqlattack': 'u2r', 'xterm': 'u2r'
}

def load_data(train_path, test_path):
    """
    Load NSL-KDD training and test data
    
    Args:
        train_path: Path to KDDTrain.txt
        test_path: Path to KDDTest.txt
        
    Returns:
        train_df, test_df: Pandas DataFrames
    """
    print("="*70)
    print("STEP 1: LOADING NSL-KDD DATASET")
    print("="*70)
    
    # Load training data
    print(f"\nLoading training data from: {train_path}")
    train_df = pd.read_csv(train_path, names=COLUMN_NAMES, header=None)
    print(f"✓ Training data loaded: {train_df.shape[0]:,} rows × {train_df.shape[1]} columns")
    
    # Load test data
    print(f"\nLoading test data from: {test_path}")
    test_df = pd.read_csv(test_path, names=COLUMN_NAMES, header=None)
    print(f"✓ Test data loaded: {test_df.shape[0]:,} rows × {test_df.shape[1]} columns")
    
    return train_df, test_df

def explore_data(train_df):
    """Display data statistics and distribution"""
    print("\n" + "="*70)
    print("STEP 2: DATA EXPLORATION")
    print("="*70)
    
    # Attack type distribution
    print("\nOriginal attack type distribution (top 10):")
    attack_counts = train_df['label'].value_counts().head(10)
    for attack, count in attack_counts.items():
        percentage = (count / len(train_df)) * 100
        print(f"  {attack:20s}: {count:6,} ({percentage:5.2f}%)")
    
    # Data types
    print(f"\nFeature data types:")
    print(f"  Numerical features: {len(train_df.select_dtypes(include=[np.number]).columns)}")
    print(f"  Categorical features: {len(train_df.select_dtypes(include=['object']).columns)}")
    
    # Missing values
    missing = train_df.isnull().sum().sum()
    print(f"\nMissing values: {missing}")

def preprocess_data(train_df, test_df):
    """
    Preprocess data for ML training
    
    Steps:
    1. Remove difficulty column (not needed for detection)
    2. Map attack types to 5 categories
    3. Encode categorical features
    4. Separate features and labels
    5. Normalize features
    6. Save encoders and scaler
    
    Returns:
        X_train_scaled, X_test_scaled, y_train, y_test, label_encoder
    """
    print("\n" + "="*70)
    print("STEP 3: DATA PREPROCESSING")
    print("="*70)
    
    # Remove difficulty column (if exists)
    print("\n1. Checking for difficulty column...")
    if 'difficulty' in train_df.columns:
        train_df = train_df.drop(['difficulty'], axis=1)
        test_df = test_df.drop(['difficulty'], axis=1)
        print("   ✓ Difficulty column removed")
    else:
        print("   ✓ Difficulty column already removed")
    
    # Map attack types to categories
    print("\n2. Mapping attack types to categories...")
    train_df['attack_category'] = train_df['label'].map(ATTACK_MAPPING)
    test_df['attack_category'] = test_df['label'].map(ATTACK_MAPPING)
    
    # Check for unmapped attacks
    unmapped_train = train_df[train_df['attack_category'].isnull()]
    unmapped_test = test_df[test_df['attack_category'].isnull()]
    
    if len(unmapped_train) > 0:
        print(f"   ⚠ Warning: {len(unmapped_train)} unmapped attacks in training set:")
        print(f"   {unmapped_train['label'].unique()}")
    
    if len(unmapped_test) > 0:
        print(f"   ⚠ Warning: {len(unmapped_test)} unmapped attacks in test set:")
        print(f"   {unmapped_test['label'].unique()}")
    
    print("\n   Attack category distribution:")
    category_counts = train_df['attack_category'].value_counts()
    for category, count in category_counts.items():
        percentage = (count / len(train_df)) * 100
        print(f"     {category:10s}: {count:6,} ({percentage:5.2f}%)")
    
    # Encode categorical features
    print("\n3. Encoding categorical features...")
    categorical_cols = ['protocol_type', 'service', 'flag']
    
    # Combine train and test for consistent encoding
    combined = pd.concat([train_df[categorical_cols], test_df[categorical_cols]])
    
    label_encoders = {}
    for col in categorical_cols:
        le = LabelEncoder()
        le.fit(combined[col])
        
        # Show encoding
        unique_vals = len(le.classes_)
        print(f"     {col:15s}: {unique_vals:3d} unique values")
        
        # Apply encoding
        train_df[col] = le.transform(train_df[col])
        test_df[col] = le.transform(test_df[col])
        label_encoders[col] = le
    
    # Encode target labels
    print("\n4. Encoding target labels...")
    label_encoder = LabelEncoder()
    label_encoder.fit(train_df['attack_category'])
    
    print(f"   Classes: {list(label_encoder.classes_)}")
    
    # Separate features and labels
    print("\n5. Separating features and labels...")
    X_train = train_df.drop(['label', 'attack_category'], axis=1)
    y_train = label_encoder.transform(train_df['attack_category'])
    
    X_test = test_df.drop(['label', 'attack_category'], axis=1)
    y_test = label_encoder.transform(test_df['attack_category'])
    
    print(f"   Training features shape: {X_train.shape}")
    print(f"   Training labels shape: {y_train.shape}")
    print(f"   Test features shape: {X_test.shape}")
    print(f"   Test labels shape: {y_test.shape}")
    
    # Normalize features
    print("\n6. Normalizing features with StandardScaler...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print("   ✓ Features normalized (mean=0, std=1)")
    
    # Save encoders and scaler
    print("\n7. Saving encoders and scaler...")
    os.makedirs('../../data/models', exist_ok=True)
    
    with open('../../data/models/label_encoders.pkl', 'wb') as f:
        pickle.dump(label_encoders, f)
    print("   ✓ Saved: label_encoders.pkl")
    
    with open('../../data/models/label_encoder.pkl', 'wb') as f:
        pickle.dump(label_encoder, f)
    print("   ✓ Saved: label_encoder.pkl")
    
    with open('../../data/models/scaler.pkl', 'wb') as f:
        pickle.dump(scaler, f)
    print("   ✓ Saved: scaler.pkl")
    
    # Display summary
    print("\n" + "="*70)
    print("PREPROCESSING SUMMARY")
    print("="*70)
    print(f"Features: {X_train.shape[1]}")
    print(f"Training samples: {X_train.shape[0]:,}")
    print(f"Test samples: {X_test.shape[0]:,}")
    print(f"Classes: {len(label_encoder.classes_)}")
    print(f"Class names: {list(label_encoder.classes_)}")
    
    return X_train_scaled, X_test_scaled, y_train, y_test, label_encoder

def save_processed_data(X_train, X_test, y_train, y_test):
    """Save preprocessed numpy arrays"""
    print("\n" + "="*70)
    print("STEP 4: SAVING PREPROCESSED DATA")
    print("="*70)
    
    np.save('../../data/models/X_train.npy', X_train)
    print("✓ Saved: X_train.npy")
    
    np.save('../../data/models/X_test.npy', X_test)
    print("✓ Saved: X_test.npy")
    
    np.save('../../data/models/y_train.npy', y_train)
    print("✓ Saved: y_train.npy")
    
    np.save('../../data/models/y_test.npy', y_test)
    print("✓ Saved: y_test.npy")
    
    print("\n" + "="*70)
    print("✓ PREPROCESSING COMPLETE!")
    print("="*70)

if __name__ == "__main__":
    from sklearn.model_selection import train_test_split
    
    print("\n" + "="*70)
    print("USING STRATIFIED TRAIN-TEST SPLIT (80-20)")
    print("="*70)
    
    # Use ONLY the training file
    TRAIN_PATH = '../../data/nsl-kdd/KDDTrain.txt'
    
    # Verify file exists
    if not os.path.exists(TRAIN_PATH):
        print(f"Error: Training file not found: {TRAIN_PATH}")
        print("Please download NSL-KDD dataset first.")
        exit(1)
    
    print("\nLoading full training dataset...")
    
    # Load full training data
    full_df = pd.read_csv(TRAIN_PATH, names=COLUMN_NAMES, header=None)
    print(f"✓ Loaded: {full_df.shape[0]:,} samples")
    
    # Remove difficulty column
    full_df = full_df.drop(['difficulty'], axis=1)
    
    # Map attacks to categories
    full_df['attack_category'] = full_df['label'].map(ATTACK_MAPPING)
    
    # Show original distribution
    print("\nOriginal dataset distribution:")
    for cat, count in full_df['attack_category'].value_counts().items():
        pct = (count / len(full_df)) * 100
        print(f"  {cat:10s}: {count:6,} ({pct:5.2f}%)")
    
    # Stratified split: 80% train, 20% test
    print("\nPerforming stratified 80-20 split...")
    train_df, test_df = train_test_split(
        full_df,
        test_size=0.20,
        random_state=42,
        stratify=full_df['attack_category']  # Ensures balanced classes
    )
    
    print(f"\n✓ Training set: {train_df.shape[0]:,} samples")
    print(f"✓ Test set: {test_df.shape[0]:,} samples")
    
    # Show train distribution
    print("\nTraining set distribution:")
    for cat, count in train_df['attack_category'].value_counts().items():
        pct = (count / len(train_df)) * 100
        print(f"  {cat:10s}: {count:6,} ({pct:5.2f}%)")
    
    # Show test distribution
    print("\nTest set distribution:")
    for cat, count in test_df['attack_category'].value_counts().items():
        pct = (count / len(test_df)) * 100
        print(f"  {cat:10s}: {count:6,} ({pct:5.2f}%)")
    
    # Continue with normal preprocessing
    X_train, X_test, y_train, y_test, label_encoder = preprocess_data(train_df, test_df)
    
    # Save processed data
    save_processed_data(X_train, X_test, y_train, y_test)
    
    print("\nReady for ML model training!")
    print("Next step: Run train_models.py")
