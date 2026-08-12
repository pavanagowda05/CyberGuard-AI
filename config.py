# ============================================================
# CyberGuard AI — config.py
# Central configuration file. Every other file imports from here.
# ============================================================

import os

# ── PROJECT ROOT ─────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── DATASET PATHS ────────────────────────────────────────────
# Phishing datasets
PHISHING_DIR = r"C:\Users\admin\OneDrive\Desktop\CS-1_DATASET\Dataset_Phishing"

CEAS_PATH       = os.path.join(PHISHING_DIR, "CEAS_08.csv")
ENRON_PATH      = os.path.join(PHISHING_DIR, "enron_legitimate_emails.csv")
PHISHING_PATH   = os.path.join(PHISHING_DIR, "Phishing_Email.csv")

# Insider threat datasets
CERT_DIR        = r"C:\Users\admin\OneDrive\Desktop\CS-1_DATASET\Insider_Threat\r4.2"

LOGON_PATH      = os.path.join(CERT_DIR, "logon.csv")
FILE_PATH       = os.path.join(CERT_DIR, "file.csv")
EMAIL_PATH      = os.path.join(CERT_DIR, "email.csv")
DEVICE_PATH     = os.path.join(CERT_DIR, "device.csv")
PSYCHOMETRIC_PATH = os.path.join(CERT_DIR, "psychometric.csv")
LDAP_DIR        = os.path.join(CERT_DIR, "LDAP")

# http.csv is 14GB — we skip it to save disk space
# HTTP_PATH = os.path.join(CERT_DIR, "http.csv")

# ── PROCESSED DATA OUTPUT ────────────────────────────────────
PROCESSED_DIR           = os.path.join(BASE_DIR, "data", "processed")
PHISHING_TRAIN_PATH     = os.path.join(PROCESSED_DIR, "phishing_train.csv")
PHISHING_TEST_PATH      = os.path.join(PROCESSED_DIR, "phishing_test.csv")
CERT_PROCESSED_PATH     = os.path.join(PROCESSED_DIR, "cert_processed.csv")
CERT_BASELINES_PATH     = os.path.join(PROCESSED_DIR, "cert_baselines.pkl")

# ── MODEL PATHS ──────────────────────────────────────────────
MODELS_DIR              = os.path.join(BASE_DIR, "models")
PHISHING_MODEL_DIR      = os.path.join(MODELS_DIR, "phishing_model")
INSIDER_MODEL_PATH      = os.path.join(MODELS_DIR, "insider_model.pkl")
INSIDER_SCALER_PATH     = os.path.join(MODELS_DIR, "insider_scaler.pkl")
INSIDER_BASELINES_PATH  = os.path.join(MODELS_DIR, "insider_baselines.pkl")

# ── MURIL MODEL (multilingual — supports Indian languages) ───
# We use MuRIL from Google for multilingual phishing detection
# It supports English, Hindi, Kannada, Tamil, Telugu and 13 more
MURIL_MODEL_NAME = "google/muril-base-cased"

# ── MONGODB ──────────────────────────────────────────────────
MONGO_URI       = "mongodb://localhost:27017"
MONGO_DB        = "cyberguard"

# Collections
COL_PHISHING    = "phishing_alerts"
COL_INSIDER     = "insider_alerts"
COL_EMPLOYEES   = "employees"
COL_SIMULATIONS = "simulations"

# ── TRAINING SETTINGS ────────────────────────────────────────
PHISHING_MAX_LEN        = 128       # max token length for email text
PHISHING_TRAIN_EPOCHS   = 3         # number of training epochs
PHISHING_BATCH_SIZE     = 16        # batch size during training
PHISHING_LEARNING_RATE  = 2e-5      # learning rate for fine-tuning
PHISHING_TEST_SIZE      = 0.2       # 20% held out for testing
PHISHING_RANDOM_STATE   = 42

# Insider threat
INSIDER_BASELINE_DAYS   = 90        # days to build behaviour baseline
INSIDER_CONTAMINATION   = 0.05      # expected % of anomalies (5%)
INSIDER_RANDOM_STATE    = 42

# ── RISK SCORING ─────────────────────────────────────────────
# Thresholds for phishing risk score (0-100)
PHISHING_RISK_CRITICAL  = 80
PHISHING_RISK_HIGH      = 60
PHISHING_RISK_MEDIUM    = 40

# Thresholds for insider threat risk score (0-100)
INSIDER_RISK_CRITICAL   = 80
INSIDER_RISK_HIGH       = 60
INSIDER_RISK_MEDIUM     = 40

# ── FASTAPI SETTINGS ─────────────────────────────────────────
API_HOST        = "127.0.0.1"
API_PORT        = 8000
API_TITLE       = "CyberGuard AI"
API_VERSION     = "1.0.0"

# ── SUPPORTED LANGUAGES ──────────────────────────────────────
SUPPORTED_LANGUAGES = {
    "en": "English",
    "hi": "Hindi",
    "kn": "Kannada",
    "ta": "Tamil",
    "te": "Telugu",
}

# ── CREATE DIRECTORIES IF THEY DON'T EXIST ───────────────────
def create_directories():
    dirs = [
        os.path.join(BASE_DIR, "data", "raw"),
        PROCESSED_DIR,
        MODELS_DIR,
        PHISHING_MODEL_DIR,
        os.path.join(BASE_DIR, "api", "routes"),
        os.path.join(BASE_DIR, "dashboard", "templates"),
        os.path.join(BASE_DIR, "dashboard", "static"),
        os.path.join(BASE_DIR, "training"),
        os.path.join(BASE_DIR, "ai"),
        os.path.join(BASE_DIR, "storage"),
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
    print("All directories created successfully.")

if __name__ == "__main__":
    create_directories()
    print("\nDataset paths configured:")
    print(f"  CEAS      : {CEAS_PATH}")
    print(f"  Enron     : {ENRON_PATH}")
    print(f"  Phishing  : {PHISHING_PATH}")
    print(f"  CERT logon: {LOGON_PATH}")
    print(f"  CERT file : {FILE_PATH}")
    print(f"  CERT email: {EMAIL_PATH}")
    print(f"  CERT device:{DEVICE_PATH}")
    print(f"\nAll paths point to your datasets correctly.")
    print(f"MongoDB: {MONGO_URI} / {MONGO_DB}")
    print(f"Model  : {MURIL_MODEL_NAME}")

    # ── THREAT INTELLIGENCE API KEYS ─────────────────────────
VIRUSTOTAL_API_KEY    = "3903015d5eae5a612eb843139a07745ff5cb18dfb4873a95a5aa26179550f3bf"
GOOGLE_SB_API_KEY     = "AIzaSyBeI1gt-6xo4wVV4NF9yb6bB9FoKneWE5c"
ABUSEIPDB_API_KEY     = "ca9427a301604bc4033dd8999343e79adeb8d0d316c01089a6586985176c5f90905edad827cfe921"
ALIENVAULT_OTX_KEY    = "56dcf5c81d68208796d46d722dd9ffaa1dd1aa596cb60d94c80f082699101018"
URLHAUS_API_KEY       = "b141dc1bcfc5f25ea89fd4c19718c2f8c711484c476d45a7"

# ── THREAT INTEL SETTINGS ────────────────────────────────
THREAT_INTEL_TIMEOUT  = 8      # seconds per API call
THREAT_INTEL_ENABLED  = True   # set False to run offline

# ── BRAND SPOOF DETECTION ────────────────────────────────
BRANDS_DB_PATH = os.path.join(BASE_DIR, "data", "brands.json")

# ── REPORT SETTINGS ──────────────────────────────────────
REPORTS_DIR = os.path.join(BASE_DIR, "data", "reports")

OTX_TIMEOUT = THREAT_INTEL_TIMEOUT + 7