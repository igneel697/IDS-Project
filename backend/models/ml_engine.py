"""
ML-Based Detection Engine
Classifies packets using the trained Random Forest and Naïve Bayes models.

Author: Pranjal Neupane
Date: April 2026
"""

import numpy as np
import pickle
import os
import warnings
warnings.filterwarnings('ignore')

class MLEngine:
    def __init__(self):
        self.rf_model      = None
        self.nb_model      = None
        self.rf_scaler     = None
        self.nb_scaler     = None
        self.label_encoder = None
        self._load_models()

    def _load_models(self):
        base = os.path.join(os.path.dirname(__file__), '../../data/models/')
        try:
            with open(base + 'decision_tree.pkl', 'rb') as f:
                self.rf_model = pickle.load(f)
            with open(base + 'naive_bayes.pkl', 'rb') as f:
                self.nb_model = pickle.load(f)
            with open(base + 'scaler.pkl', 'rb') as f:
                self.rf_scaler = pickle.load(f)
            with open(base + 'nb_scaler.pkl', 'rb') as f:
                self.nb_scaler = pickle.load(f)
            with open(base + 'label_encoder.pkl', 'rb') as f:
                self.label_encoder = pickle.load(f)
            print('All models loaded successfully')
        except Exception as e:
            print(f'Error loading models: {e}')

    def predict(self, features):
        """
        Classify a feature vector using both models.

        Args:
            features: numpy array shape (1, 20)

        Returns:
            dict with both predictions and a final decision
        """
        # Random Forest
        rf_features  = self.rf_scaler.transform(features)
        rf_pred      = self.rf_model.predict(rf_features)[0]
        rf_proba     = self.rf_model.predict_proba(rf_features)[0]
        rf_confidence= float(np.max(rf_proba))
        rf_label     = self.label_encoder.inverse_transform([rf_pred])[0]

        # Naïve Bayes
        nb_features  = self.nb_scaler.transform(features)
        nb_pred      = self.nb_model.predict(nb_features)[0]
        nb_proba     = self.nb_model.predict_proba(nb_features)[0]
        nb_confidence= float(np.max(nb_proba))
        nb_label     = self.label_encoder.inverse_transform([nb_pred])[0]

        # Final decision: if both agree use that, otherwise use higher confidence
        agreement = (rf_label == nb_label)
        if agreement:
            final      = rf_label
            confidence = (rf_confidence + nb_confidence) / 2
        elif rf_confidence >= nb_confidence:
            final      = rf_label
            confidence = rf_confidence
        else:
            final      = nb_label
            confidence = nb_confidence

        return {
            'rf_prediction':    rf_label,
            'rf_confidence':    rf_confidence,
            'nb_prediction':    nb_label,
            'nb_confidence':    nb_confidence,
            'final_prediction': final,
            'final_confidence': confidence,
            'agreement':        agreement,
        }


if __name__ == '__main__':
    engine = MLEngine()
    dummy  = np.zeros((1, 20))
    result = engine.predict(dummy)
    print(f'\nTest prediction:')
    print(f'  Random Forest : {result["rf_prediction"]} ({result["rf_confidence"]*100:.1f}%)')
    print(f'  Naïve Bayes   : {result["nb_prediction"]} ({result["nb_confidence"]*100:.1f}%)')
    print(f'  Final decision: {result["final_prediction"]} ({result["final_confidence"]*100:.1f}%)')
    print(f'  Models agreed : {result["agreement"]}')
    print('ML engine working!')
