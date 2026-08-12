# CyberGuard-AI
A Unified Multilingual Phishing and Insider Threat Detection Platform 

# CyberGuard AI

A unified multilingual phishing and insider-threat detection platform, built as a capstone project for the M.Tech Computer Science program at REVA University (Batch CS-14, SRN R24TF005).

CyberGuard AI combines a nine-stage multilingual phishing detection pipeline (MuRIL-based classification, NER, sender/subject/URL/brand-spoof analysis, live threat-intelligence lookups, and a rule-based scoring engine) with an Isolation Forest-based insider-threat detection module, unified behind a FastAPI backend and a real-time dashboard.

## Note on model weights

The fine-tuned MuRIL phishing classifier checkpoint (`models/phishing_model/`, ~906 MB) is **excluded from this repository** due to GitHub's 100 MB per-file limit. To reproduce it locally:
- Re-run the fine-tuning process described in Chapter 6/8 of the project report, using the training script in `training/`, against the combined English + Indian-language phishing dataset (86,683 labelled samples) described in Chapter 5, **or**
- [Add a download link here if you host the checkpoint separately — e.g. Google Drive, Hugging Face Hub]

The pre-trained Isolation Forest insider-threat model (`models/insider_model.pkl`, `insider_scaler.pkl`, `insider_baselines.pkl`) is included, since it is small enough to commit directly.

## Setup

1. Create and activate a Python virtual environment.
2. Install dependencies: `pip install -r requirements.txt` *(add a requirements.txt if one doesn't exist yet)*
3. Start MongoDB locally.
4. Copy `.env.example` to `.env` and fill in your own API keys (VirusTotal, AlienVault OTX, Google Safe Browsing).
5. Place the fine-tuned MuRIL checkpoint under `models/phishing_model/` (see note above).
6. Run the server:
   ```
   python -m uvicorn api.main:app --reload --host 127.0.0.1 --port 8000
   ```
7. Open `http://127.0.0.1:8000` in a browser.
8. For a live insider-threat demo, run `python simulate.py` in a second terminal.

## Project report

The full capstone report, including architecture, evaluation results, and testing documentation, is available separately as part of the academic submission.
