
from transformers import pipeline


class SemanticAnalyzer:

    def __init__(self):
        print("[Assistant 3] Loading Phishing & Scam Detection Model...")

        self.classifier = pipeline(
            "text-classification",
            model="Horizon-Labs/phishing-scam-detector-base"
        )

        print("[Assistant 3] Model loaded successfully!")
        print("[Assistant 3] Available labels:",
              self.classifier.model.config.id2label)

    def analyze_text(self, text):

        if not text or not text.strip():
            return {
                "status": "NO_TEXT",
                "message": "No website text available for analysis."
            }

        predictions = self.classifier(
            text,
            top_k=None,
            truncation=True,
            max_length=384
        )

        if predictions and isinstance(predictions[0], list):
            predictions = predictions[0]

        best_prediction = max(
            predictions,
            key=lambda item: item["score"]
        )

        scores = {
            item["label"].lower(): round(item["score"], 4)
            for item in predictions
        }

        return {
            "status": "ANALYZED",
            "prediction": best_prediction["label"].lower(),
            "confidence": round(best_prediction["score"], 4),
            "fraud_score": scores.get("fraud", 0.0),
            "spam_score": scores.get("spam", 0.0),
            "legitimate_score": scores.get("legitimate", 0.0)
        }
