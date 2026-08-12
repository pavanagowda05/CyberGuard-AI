# ============================================================
# CyberGuard AI — ai/phishing_classifier.py
# Loads the trained MuRIL model and classifies email text.
# Returns: verdict, confidence, raw scores.
# ============================================================

import os
import sys
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import PHISHING_MODEL_DIR, PHISHING_MAX_LEN

# ── Singleton pattern — load model once, reuse for every request ──
_tokenizer = None
_model     = None
_device    = None

def _load_model():
    global _tokenizer, _model, _device
    if _model is not None:
        return  # already loaded

    print(f"[PhishingClassifier] Loading MuRIL model from {PHISHING_MODEL_DIR} ...")
    _tokenizer = AutoTokenizer.from_pretrained(PHISHING_MODEL_DIR)
    _model     = AutoModelForSequenceClassification.from_pretrained(PHISHING_MODEL_DIR)
    _device    = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    _model.to(_device)
    _model.eval()
    print(f"[PhishingClassifier] Model loaded on {_device}")


def classify_email(text: str) -> dict:
    """
    Classify a single email text as phishing or safe.

    Args:
        text: raw email text (any language)

    Returns:
        {
          "verdict":     "Phishing" or "Safe",
          "confidence":  float (0.0 to 1.0),
          "prob_phishing": float,
          "prob_safe":     float,
          "risk_score":  int (0-100)
        }
    """
    _load_model()

    # Tokenize
    inputs = _tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        padding="max_length",
        max_length=PHISHING_MAX_LEN,
    )
    inputs = {k: v.to(_device) for k, v in inputs.items()}

    # Inference
    with torch.no_grad():
        outputs = _model(**inputs)
        probs   = torch.softmax(outputs.logits, dim=-1)[0]

    prob_safe     = float(probs[0])
    prob_phishing = float(probs[1])

    verdict    = "Phishing" if prob_phishing > prob_safe else "Safe"
    confidence = max(prob_phishing, prob_safe)
    risk_score = int(prob_phishing * 100)

    return {
        "verdict":       verdict,
        "confidence":    round(confidence, 4),
        "prob_phishing": round(prob_phishing, 4),
        "prob_safe":     round(prob_safe, 4),
        "risk_score":    risk_score,
    }


# ── Quick test when run directly ─────────────────────────────
if __name__ == "__main__":
    test_emails = [
        # Phishing example
        "Dear User, your SBI account has been suspended. "
        "Click here immediately to verify your Aadhaar and restore access "
        "within 24 hours or your account will be permanently closed. "
        "— SBI Security Team http://fake-sbi-verify.com",

        # Safe example
        "Hi team, please find attached the Q3 sales report. "
        "Let me know if you have any questions. Thanks, Rahul.",

        # Hindi phishing example
        "प्रिय उपयोगकर्ता, आपका बैंक खाता निलंबित कर दिया गया है। "
        "तुरंत यहाँ क्लिक करें और अपनी जानकारी सत्यापित करें।",
    ]

    print("=" * 60)
    print("CyberGuard AI — Phishing Classifier Test")
    print("=" * 60)

    for i, email in enumerate(test_emails):
        print(f"\nTest {i+1}: {email[:80]}...")
        result = classify_email(email)
        print(f"  Verdict     : {result['verdict']}")
        print(f"  Confidence  : {result['confidence']*100:.1f}%")
        print(f"  Risk score  : {result['risk_score']}/100")
        print(f"  P(phishing) : {result['prob_phishing']:.4f}")
        print(f"  P(safe)     : {result['prob_safe']:.4f}")