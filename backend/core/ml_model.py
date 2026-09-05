import os
import json
import re
import numpy as np
from typing import Optional


class ThreatClassifier:
    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.path.join(
            os.path.dirname(__file__), "..", "..", "ml_models"
        )
        self.model = None
        self.vectorizer = None
        self._load_model()

    def _load_model(self):
        try:
            model_file = os.path.join(self.model_path, "threat_classifier.json")
            if os.path.exists(model_file):
                with open(model_file, "r") as f:
                    self.model = json.load(f)
            else:
                self._create_default_model()
        except Exception:
            self._create_default_model()

    def _create_default_model(self):
        self.model = {
            "type": "rule_based",
            "version": "1.0",
            "features": {
                "phishing_keywords": [
                    "verify", "account", "suspended", "urgent", "click",
                    "confirm", "identity", "payment", "security", "alert",
                    "unusual", "sign-in", "locked", "reset", "password",
                ],
                "urgency_words": [
                    "immediately", "urgent", "act now", "expires", "limited",
                    "deadline", "final", "last chance", "don't delay",
                ],
                "financial_keywords": [
                    "bank", "credit", "wire", "transfer", "bitcoin", "crypto",
                    "inheritance", "million", "prize", "lottery", "winner",
                ],
            },
        }
        os.makedirs(self.model_path, exist_ok=True)
        model_file = os.path.join(self.model_path, "threat_classifier.json")
        with open(model_file, "w") as f:
            json.dump(self.model, f, indent=2)

    def predict(self, text: str) -> dict:
        text_lower = text.lower()
        features = self.model.get("features", {})

        phishing_hits = sum(
            1 for kw in features.get("phishing_keywords", [])
            if kw in text_lower
        )
        urgency_hits = sum(
            1 for kw in features.get("urgency_words", [])
            if kw in text_lower
        )
        financial_hits = sum(
            1 for kw in features.get("financial_keywords", [])
            if kw in text_lower
        )

        total_words = len(text_lower.split()) or 1
        score = (
            (phishing_hits / max(len(features.get("phishing_keywords", [])), 1)) * 0.4 +
            (urgency_hits / max(len(features.get("urgency_words", [])), 1)) * 0.3 +
            (financial_hits / max(len(features.get("financial_keywords", [])), 1)) * 0.3
        ) * 100

        score = min(max(score, 0), 100)

        if score < 20:
            label = "safe"
        elif score < 40:
            label = "low_risk"
        elif score < 60:
            label = "medium_risk"
        elif score < 80:
            label = "high_risk"
        else:
            label = "critical"

        return {
            "label": label,
            "score": round(score, 2),
            "features": {
                "phishing_hits": phishing_hits,
                "urgency_hits": urgency_hits,
                "financial_hits": financial_hits,
            },
        }

    def save_model(self):
        os.makedirs(self.model_path, exist_ok=True)
        model_file = os.path.join(self.model_path, "threat_classifier.json")
        with open(model_file, "w") as f:
            json.dump(self.model, f, indent=2)
