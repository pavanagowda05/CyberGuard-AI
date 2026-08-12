# ============================================================
# CyberGuard AI — ai/threat_classifier.py
#
# Context-aware phishing threat classifier
#
# Categories:
#   Credential Theft
#   Banking Fraud
#   KYC Fraud
#   Government Impersonation
#   Lottery Scam
#   Business Email Compromise
#   Tech Support Scam
#   Delivery Scam
#   Job Scam
#   Investment Fraud
#   Security Awareness
#   Brand Impersonation
#   Generic Phishing
#
# IMPORTANT:
# This module classifies the TYPE of threat.
# It should NOT decide whether an email is ultimately
# Phishing/Safe. The rule engine remains responsible for
# the final verdict.
# ============================================================

import re
from typing import Optional


# ============================================================
# THREAT CATEGORIES
# ============================================================

THREAT_CATEGORIES = {

    "Credential Theft": {
        "keywords": [
            "password",
            "username",
            "login",
            "sign in",
            "signin",
            "credentials",
            "verify your account",
            "account access",
            "reset password",
            "password expired",
            "locked out",
            "otp",
            "one time password",
            "two factor",
            "2fa",

            # Hindi
            "पासवर्ड",
            "लॉगिन",
            "ओटीपी",

            # Kannada
            "ಪಾಸ್‌ವರ್ಡ್",
            "ಪಾಸ್ವರ್ಡ್",
            "ಲಾಗಿನ್",
            "ಒಟಿಪಿ",

            # Tamil
            "கடவுச்சொல்",
            "உள்நுழை",
            "ஒருமுறை கடவுச்சொல்",
            "ஓடிபி",

            # Telugu
            "పాస్‌వర్డ్",
            "పాస్వర్డ్",
            "లాగిన్",
            "ఓటీపీ",
        ],
        "weight": 3,
        "description": "Attempts to steal login credentials or authentication information",
        "severity": "Critical",
    },

    "Banking Fraud": {
        "keywords": [
            "bank account",
            "net banking",
            "netbanking",
            "online banking",
            "account suspended",
            "account blocked",
            "account frozen",
            "transaction failed",
            "debit card",
            "credit card",
            "account number",
            "ifsc",
            "upi",
            "payment",
            "bank details",
            "banking details",

            # Hindi
            "बैंक खाता",
            "नेट बैंकिंग",
            "बैंक विवरण",
            "केवाईसी",

            # Kannada
            "ಬ್ಯಾಂಕ್ ಖಾತೆ",
            "ನೆಟ್ ಬ್ಯಾಂಕಿಂಗ್",
            "ಬ್ಯಾಂಕ್ ವಿವರ",
            "ಕೆವೈಸಿ",

            # Tamil
            "வங்கி கணக்கு",
            "நெட் பேங்கிங்",
            "வங்கி விவரங்கள்",
            "கேஒய்சி",

            # Telugu
            "బ్యాంక్ ఖాతా",
            "నెట్ బ్యాంకింగ్",
            "బ్యాంక్ వివరాలు",
            "కెవైసి",
        ],
        "weight": 3,
        "description": "Targets banking credentials or financial information",
        "severity": "Critical",
    },

    "Government Impersonation": {
        "keywords": [
            "income tax",
            "tax refund",
            "it department",
            "gst",
            "aadhaar",
            "aadhar",
            "uidai",
            "pan card",
            "epfo",
            "passport",
            "visa",
            "court notice",
            "legal notice",
            "police",
            "cybercrime",
            "enforcement",
            "fir",
            "penalty",
            "fine",
            "dues",
            "outstanding",

            # Hindi
            "आधार",
            "पैन कार्ड",
            "आयकर",
            "सरकार",
            "सरकारी",

            # Kannada
            "ಆಧಾರ್",
            "ಪ್ಯಾನ್ ಕಾರ್ಡ್",
            "ಆದಾಯ ತೆರಿಗೆ",
            "ಸರ್ಕಾರ",
            "ಸರ್ಕಾರಿ",

            # Tamil
            "ஆதார்",
            "பான் கார்டு",
            "வருமான வரி",
            "அரசு",
            "அரசாங்கம்",

            # Telugu
            "ఆధార్",
            "పాన్ కార్డ్",
            "ఆదాయపు పన్ను",
            "ప్రభుత్వం",
            "ప్రభుత్వ",
        ],
        "weight": 3,
        "description": "Impersonates government agencies or officials",
        "severity": "Critical",
    },

    "Lottery Scam": {
        "keywords": [
            "lottery",
            "winner",
            "won",
            "prize",
            "reward",
            "congratulations",
            "selected",
            "lucky draw",
            "claim your",
            "free gift",
            "cash prize",
            "sweepstakes",
            "jackpot",
            "bonus",

            # Hindi
            "लॉटरी",
            "इनाम",
            "पुरस्कार",
            "जीते",

            # Kannada
            "ಲಾಟರಿ",
            "ಬಹುಮಾನ",
            "ಜಯ",

            # Tamil
            "லாட்டரி",
            "பரிசு",
            "வெற்றி",

            # Telugu
            "లాటరీ",
            "బహుమతి",
            "గెలుపు",
        ],
        "weight": 2,
        "description": "Fake lottery, prize or reward scam",
        "severity": "High",
    },

    "Business Email Compromise": {
        "keywords": [
            "wire transfer",
            "fund transfer",
            "urgent payment",
            "invoice attached",
            "payment required",
            "ceo",
            "director",
            "management",
            "confidential",
            "do not discuss",
            "keep this private",
            "change bank details",
            "new account",
            "vendor payment",
            "supplier",
        ],
        "weight": 2,
        "description": "Business Email Compromise targeting financial or business processes",
        "severity": "Critical",
    },

    "Tech Support Scam": {
        "keywords": [
            "virus detected",
            "malware",
            "hacked",
            "infected",
            "call immediately",
            "toll free",
            "helpline",
            "microsoft support",
            "apple support",
            "google support",
            "computer at risk",
            "your device",
            "windows",
            "license expired",
            "subscription expired",
            "technical support",
            "customer care",
        ],
        "weight": 2,
        "description": "Fake technical support or security alert scam",
        "severity": "High",
    },

    "Delivery Scam": {
        "keywords": [
            "package",
            "parcel",
            "delivery failed",
            "shipment",
            "courier",
            "dhl",
            "fedex",
            "ups",
            "india post",
            "customs",
            "clearance fee",
            "tracking number",
            "out for delivery",
            "missed delivery",
            "reschedule delivery",
            "delivery address",
        ],
        "weight": 2,
        "description": "Fake delivery or parcel notification scam",
        "severity": "Medium",
    },

    "Job Scam": {
        "keywords": [
            "job offer",
            "work from home",
            "salary",
            "hiring",
            "recruitment",
            "selected for interview",
            "offer letter",
            "joining bonus",
            "part time",
            "earn from home",
            "daily earning",
            "passive income",
            "investment required",
            "registration fee",
        ],
        "weight": 2,
        "description": "Fake job offer or work-from-home scam",
        "severity": "High",
    },

    "Investment Fraud": {
        "keywords": [
            "investment",
            "returns",
            "profit",
            "cryptocurrency",
            "bitcoin",
            "trading",
            "forex",
            "stock tips",
            "guaranteed returns",
            "double your money",
            "high returns",
            "risk free",
            "roi",
            "mutual fund",
            "portfolio",
            "scheme",
        ],
        "weight": 2,
        "description": "Fake investment, cryptocurrency or trading scheme",
        "severity": "High",
    },

    "KYC Fraud": {
        "keywords": [
            "kyc",
            "know your customer",
            "kyc update",
            "kyc verification",
            "kyc pending",
            "kyc expired",
            "submit kyc",
            "complete kyc",
            "kyc required",

            # Hindi
            "केवाईसी",

            # Kannada
            "ಕೆವೈಸಿ",

            # Tamil
            "கேஒய்சி",

            # Telugu
            "కెవైసి",
        ],
        "weight": 3,
        "description": "KYC-related fraud targeting financial account holders",
        "severity": "Critical",
    },
}


# ============================================================
# SECURITY-AWARENESS / EDUCATIONAL LANGUAGE
# ============================================================

SECURITY_AWARENESS_PATTERNS = {

    "English": [
        "security awareness",
        "stay safe",
        "stay alert",
        "be careful",
        "do not share your password",
        "do not share your otp",
        "do not share otp",
        "never share your password",
        "never share otp",
        "protect your account",
        "protect yourself",
        "do not click suspicious links",
        "avoid suspicious links",
        "do not share bank details",
        "do not share your bank details",
        "do not share personal information",
        "do not share credentials",
        "money mule",
        "do not become a money mule",
        "easy money is not worth the risk",
    ],

    "Hindi": [
        "सुरक्षा जागरूकता",
        "सतर्क रहें",
        "सावधान रहें",
        "सुरक्षित रहें",
        "अपना खाता सुरक्षित रखें",
        "पासवर्ड साझा न करें",
        "ओटीपी साझा न करें",
        "otp साझा न करें",
        "बैंक विवरण साझा न करें",
        "व्यक्तिगत जानकारी साझा न करें",
        "लिंक पर क्लिक न करें",
        "संदिग्ध लिंक",
        "जागरूक रहें",
        "साझा न करें",
        "मनी म्यूल",
        "आसान पैसा",
    ],

    "Kannada": [
        "ಭದ್ರತಾ ಜಾಗೃತಿ",
        "ಜಾಗರೂಕರಾಗಿರಿ",
        "ಎಚ್ಚರಿಕೆಯಿಂದಿರಿ",
        "ಸುರಕ್ಷಿತವಾಗಿರಿ",
        "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ರಕ್ಷಿಸಿಕೊಳ್ಳಿ",
        "ಪಾಸ್‌ವರ್ಡ್ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
        "ಪಾಸ್ವರ್ಡ್ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
        "ಒಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
        "ಬ್ಯಾಂಕ್ ವಿವರಗಳನ್ನು ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
        "ವೈಯಕ್ತಿಕ ಮಾಹಿತಿಯನ್ನು ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
        "ಸಂದೇಹಾಸ್ಪದ ಲಿಂಕ್",
        "ಲಿಂಕ್ ಕ್ಲಿಕ್ ಮಾಡಬೇಡಿ",
        "ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
        "ಮನಿ ಮ್ಯೂಲ್",
        "ಎಚ್ಚರಿಕೆ",
        "ಜಾಗೃತಿ",
    ],

    "Tamil": [
        "பாதுகாப்பு விழிப்புணர்வு",
        "விழிப்புடன் இருங்கள்",
        "எச்சரிக்கையாக இருங்கள்",
        "பாதுகாப்பாக இருங்கள்",
        "கடவுச்சொல்லை பகிர வேண்டாம்",
        "ஓடிபியை பகிர வேண்டாம்",
        "otp பகிர வேண்டாம்",
        "வங்கி விவரங்களை பகிர வேண்டாம்",
        "தனிப்பட்ட தகவல்களை பகிர வேண்டாம்",
        "சந்தேகமான இணைப்பு",
        "இணைப்பை கிளிக் செய்ய வேண்டாம்",
        "பகிர வேண்டாம்",
        "மணி மியூல்",
    ],

    "Telugu": [
        "భద్రతా అవగాహన",
        "జాగ్రత్తగా ఉండండి",
        "అప్రమత్తంగా ఉండండి",
        "సురక్షితంగా ఉండండి",
        "పాస్‌వర్డ్ పంచుకోవద్దు",
        "పాస్వర్డ్ పంచుకోవద్దు",
        "ఓటీపీ పంచుకోవద్దు",
        "బ్యాంక్ వివరాలు పంచుకోవద్దు",
        "వ్యక్తిగత సమాచారాన్ని పంచుకోవద్దు",
        "సందేహాస్పద లింక్",
        "లింక్ క్లిక్ చేయవద్దు",
        "పంచుకోవద్దు",
        "మనీ మ్యూల్",
    ],
}


# ============================================================
# MALICIOUS CONTEXT PATTERNS
#
# These prevent innocent words such as:
#   "sign in"
#   "account"
#   "password"
#   "OTP"
#
# from automatically becoming a phishing category.
# ============================================================

MALICIOUS_CONTEXT_PATTERNS = {

    "Credential Theft": [
        "verify your password",
        "confirm your password",
        "enter your password",
        "submit your password",
        "provide your password",
        "enter otp",
        "enter the otp",
        "provide otp",
        "submit otp",
        "share otp",
        "send otp",
        "verify your otp",
        "confirm otp",
        "verify your account",
        "confirm your account",
        "account will be suspended",
        "account has been suspended",
        "account will be closed",
        "account has been locked",
        "login immediately",
        "sign in immediately",
        "click here to login",
        "click here to sign in",
        "reset your password",
        "password has expired",
        "password will expire",
        "credentials have expired",
        "unlock your account",

        # Hindi
        "पासवर्ड दर्ज करें",
        "ओटीपी दर्ज करें",
        "ओटीपी साझा करें",
        "खाता सत्यापित करें",
        "खाता बंद",
        "खाता निलंबित",
        "तुरंत लॉगिन",
        "पासवर्ड सत्यापित",

        # Kannada
        "ಪಾಸ್‌ವರ್ಡ್ ನಮೂದಿಸಿ",
        "ಪಾಸ್ವರ್ಡ್ ನಮೂದಿಸಿ",
        "ಒಟಿಪಿ ನಮೂದಿಸಿ",
        "ಒಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ",
        "ಖಾತೆಯನ್ನು ಪರಿಶೀಲಿಸಿ",
        "ಖಾತೆ ಸ್ಥಗಿತ",
        "ಖಾತೆ ಮುಚ್ಚಲಾಗುತ್ತದೆ",
        "ತಕ್ಷಣ ಲಾಗಿನ್",
        "ಪಾಸ್‌ವರ್ಡ್ ಪರಿಶೀಲಿಸಿ",

        # Tamil
        "கடவுச்சொல்லை உள்ளிடவும்",
        "otp உள்ளிடவும்",
        "கணக்கை சரிபார்க்கவும்",
        "கணக்கு முடக்கப்படும்",
        "உடனடியாக உள்நுழையவும்",

        # Telugu
        "పాస్‌వర్డ్ నమోదు చేయండి",
        "ఓటీపీ నమోదు చేయండి",
        "ఖాతాను ధృవీకరించండి",
        "ఖాతా నిలిపివేయబడుతుంది",
        "వెంటనే లాగిన్ అవ్వండి",
    ],

    "Banking Fraud": [
        "verify your bank account",
        "confirm your bank account",
        "bank account will be suspended",
        "bank account has been suspended",
        "bank account will be blocked",
        "bank account has been blocked",
        "update your bank details",
        "confirm your bank details",
        "provide your bank details",
        "enter your bank details",
        "verify your debit card",
        "verify your credit card",
        "update your upi",
        "verify your upi",
        "payment failed verify",
        "transaction failed verify",
        "account frozen verify",
    ],

    "KYC Fraud": [
        "kyc is pending",
        "kyc has expired",
        "complete your kyc",
        "submit your kyc",
        "update your kyc",
        "verify your kyc",
        "kyc required immediately",
        "kyc verification required",
        "kyc will be suspended",
        "kyc will expire",
        "submit aadhaar",
        "submit pan card",
        "provide aadhaar",
        "provide pan card",
    ],

    "Government Impersonation": [
        "tax refund is pending",
        "claim your tax refund",
        "verify your aadhaar",
        "verify your aadhar",
        "submit your aadhaar",
        "submit your pan card",
        "pay the penalty",
        "pay the fine",
        "legal action will be taken",
        "court action will be taken",
        "police case will be filed",
        "fir will be filed",
        "verify your government account",
    ],

    "Lottery Scam": [
        "you have won",
        "you won",
        "claim your prize",
        "claim your reward",
        "claim your cash prize",
        "claim your lottery",
        "pay fee to claim",
        "pay tax to claim",
        "pay processing fee",
        "selected as a winner",
    ],

    "Business Email Compromise": [
        "send the payment",
        "make the payment",
        "transfer the funds",
        "transfer the money",
        "wire the money",
        "wire transfer immediately",
        "urgent payment required",
        "change the bank details",
        "use this new account",
        "send payment to this account",
    ],

    "Tech Support Scam": [
        "your computer is infected",
        "your computer has a virus",
        "your device is infected",
        "virus detected call",
        "call support immediately",
        "call microsoft support",
        "call apple support",
        "call technical support immediately",
        "your computer is at risk",
        "your license has expired",
    ],

    "Delivery Scam": [
        "delivery failed pay",
        "package is held",
        "parcel is held",
        "pay customs fee",
        "pay clearance fee",
        "pay delivery fee",
        "update delivery address",
        "confirm delivery address",
        "reschedule your delivery",
    ],

    "Job Scam": [
        "pay registration fee",
        "pay application fee",
        "pay joining fee",
        "pay training fee",
        "investment required for job",
        "send money to get the job",
        "pay to receive offer letter",
    ],

    "Investment Fraud": [
        "guaranteed returns",
        "guaranteed profit",
        "double your money",
        "triple your money",
        "risk free investment",
        "risk-free investment",
        "invest now",
        "send money to invest",
        "deposit to start trading",
        "limited investment opportunity",
        "crypto investment opportunity",
    ],
}


# ============================================================
# LANGUAGE DETECTION
# ============================================================

def detect_language(text: str) -> str:
    """
    Basic script-based language detection.

    Returns:
        English / Hindi / Kannada / Tamil / Telugu / Other
    """

    if not text:
        return "Other"

    # Kannada Unicode block
    if re.search(r"[\u0C80-\u0CFF]", text):
        return "Kannada"

    # Telugu Unicode block
    if re.search(r"[\u0C00-\u0C7F]", text):
        return "Telugu"

    # Tamil Unicode block
    if re.search(r"[\u0B80-\u0BFF]", text):
        return "Tamil"

    # Devanagari Unicode block
    if re.search(r"[\u0900-\u097F]", text):
        return "Hindi"

    # If mostly ASCII / Latin
    if re.search(r"[A-Za-z]", text):
        return "English"

    return "Other"


# ============================================================
# TEXT NORMALIZATION
# ============================================================

def normalize_text(text: str) -> str:
    if not text:
        return ""

    text = text.lower()

    # Normalize common apostrophe variants
    text = text.replace("’", "'")
    text = text.replace("‘", "'")
    text = text.replace("“", '"')
    text = text.replace("”", '"')

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ============================================================
# MATCHING HELPERS
# ============================================================

def contains_phrase(text: str, phrase: str) -> bool:
    """
    Match a phrase safely.

    For Latin text, use word boundaries.
    For Indic scripts, substring matching is more reliable.
    """

    phrase = normalize_text(phrase)

    if not phrase:
        return False

    # Indic language phrase
    if re.search(
        r"[\u0900-\u097F"
        r"\u0B80-\u0BFF"
        r"\u0C00-\u0C7F"
        r"\u0C80-\u0CFF]",
        phrase,
    ):
        return phrase in text

    # English / Latin phrase
    pattern = r"(?<!\w)" + re.escape(phrase) + r"(?!\w)"

    return re.search(pattern, text, flags=re.IGNORECASE) is not None


def find_matches(text: str, keywords: list) -> list:
    matches = []

    for keyword in keywords:
        if contains_phrase(text, keyword):
            matches.append(keyword)

    return matches


# ============================================================
# SECURITY AWARENESS DETECTION
# ============================================================

def detect_security_awareness(text: str) -> tuple:
    """
    Detect educational/protective messages.

    Returns:
        (is_awareness, language, matched_patterns)
    """

    language = detect_language(text)

    # Search all languages rather than only the detected language.
    # This helps with mixed-language messages.
    all_matches = []

    for lang, patterns in SECURITY_AWARENESS_PATTERNS.items():
        matches = find_matches(text, patterns)

        for match in matches:
            all_matches.append(match)

    # Strong awareness signals
    strong_patterns = [
        "security awareness",
        "stay safe",
        "stay alert",
        "protect your account",
        "do not share",
        "never share",
        "avoid suspicious links",
        "money mule",
        "सुरक्षा जागरूकता",
        "सतर्क रहें",
        "सावधान रहें",
        "जागरूक रहें",
        "साझा न करें",
        "ಭದ್ರತಾ ಜಾಗೃತಿ",
        "ಜಾಗರೂಕರಾಗಿರಿ",
        "ಎಚ್ಚರಿಕೆಯಿಂದಿರಿ",
        "ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
        "பாதுகாப்பு விழிப்புணர்வு",
        "விழிப்புடன் இருங்கள்",
        "பகிர வேண்டாம்",
        "భద్రతా అవగాహన",
        "జాగ్రత్తగా ఉండండి",
        "పంచుకోవద్దు",
    ]

    strong_matches = find_matches(text, strong_patterns)

    # Two or more awareness indicators is enough.
    is_awareness = (
        len(strong_matches) >= 1
        or len(all_matches) >= 2
    )

    # If the message contains explicit protective language,
    # consider it awareness even if only one phrase was matched.
    protective_words = [
        "do not share",
        "never share",
        "protect",
        "avoid",
        "stay safe",
        "stay alert",
        "साझा न करें",
        "सतर्क रहें",
        "ಸುರಕ್ಷಿತ",
        "ಹಂಚಿಕೊಳ್ಳಬೇಡಿ",
        "பகிர வேண்டாம்",
        "பாதுகாப்பாக",
        "పంచుకోవద్దు",
        "సురక్షితంగా",
    ]

    if find_matches(text, protective_words):
        is_awareness = True

    return (
        is_awareness,
        language,
        list(dict.fromkeys(all_matches))[:10],
    )


# ============================================================
# MALICIOUS CONTEXT DETECTION
# ============================================================

def detect_malicious_context(text: str) -> dict:
    """
    Find phrases that indicate an actual malicious action.

    This is the important difference from the old classifier:

        "sign in" alone
        "account" alone
        "password" alone
        "OTP" alone

    do NOT automatically become Credential Theft.
    """

    result = {}

    for category, patterns in MALICIOUS_CONTEXT_PATTERNS.items():
        matches = find_matches(text, patterns)

        if matches:
            result[category] = list(dict.fromkeys(matches))

    return result


# ============================================================
# CATEGORY CLASSIFICATION
# ============================================================

def classify_threat(
    email_text: str,
    subject: str = "",
    spoofed_brand: Optional[str] = None,
    sender_domain: str = "",
    final_verdict: Optional[str] = None,
) -> dict:
    """
    Classify the type of phishing threat.

    Parameters:
        email_text:
            Email body.

        subject:
            Email subject.

        spoofed_brand:
            Brand detected by brand-spoofing logic.

        sender_domain:
            Sender domain.

        final_verdict:
            Optional final verdict from the rule engine.

            If supplied as "Safe", the classifier will NOT
            return a phishing category.

    Returns:
        {
            "primary_category": str or None,
            "secondary_category": str or None,
            "description": str,
            "severity": str,
            "confidence": float,
            "all_scores": dict,
            "indicators": list,
            "language": str,
            "security_awareness": bool,
        }
    """

    # --------------------------------------------------------
    # Combine text
    # --------------------------------------------------------

    body = email_text or ""
    subj = subject or ""

    full_text = normalize_text(
        body + " " + subj
    )

    language = detect_language(full_text)

    # --------------------------------------------------------
    # Empty input
    # --------------------------------------------------------

    if not full_text:
        return {
            "primary_category": None,
            "secondary_category": None,
            "description": "No email content available for threat classification",
            "severity": "Low",
            "confidence": 0.0,
            "all_scores": {},
            "indicators": [],
            "language": language,
            "security_awareness": False,
        }

    # --------------------------------------------------------
    # FINAL VERDICT OVERRIDE
    #
    # This is the most important safety check.
    #
    # If the rule engine says Safe, don't display a threat
    # category such as Credential Theft.
    # --------------------------------------------------------

    if final_verdict:
        verdict_normalized = str(final_verdict).strip().lower()

        if verdict_normalized in {
            "safe",
            "benign",
            "legitimate",
        }:
            return {
                "primary_category": None,
                "secondary_category": None,
                "description": "No phishing threat identified",
                "severity": "Low",
                "confidence": 1.0,
                "all_scores": {},
                "indicators": [],
                "language": language,
                "security_awareness": False,
            }

    # --------------------------------------------------------
    # SECURITY AWARENESS
    # --------------------------------------------------------

    awareness, awareness_language, awareness_matches = (
        detect_security_awareness(full_text)
    )

    # --------------------------------------------------------
    # Malicious context
    # --------------------------------------------------------

    malicious_context = detect_malicious_context(full_text)

    # --------------------------------------------------------
    # Calculate normal keyword scores
    # --------------------------------------------------------

    scores = {}
    indicators = {}

    for category, config in THREAT_CATEGORIES.items():

        matched = find_matches(
            full_text,
            config["keywords"],
        )

        if matched:

            # Remove harmless authentication words from
            # Credential Theft unless there is malicious context.
            if category == "Credential Theft":

                malicious_auth = malicious_context.get(
                    "Credential Theft",
                    [],
                )

                harmless_only = set(
                    normalize_text(x)
                    for x in matched
                ).issubset({
                    "login",
                    "sign in",
                    "signin",
                    "account access",
                    "username",
                    "password",
                    "credentials",
                    "otp",
                    "one time password",
                    "two factor",
                    "2fa",
                    "पासवर्ड",
                    "लॉगिन",
                    "ओटीपी",
                    "ಪಾಸ್‌ವರ್ಡ್",
                    "ಪಾಸ್ವರ್ಡ್",
                    "ಲಾಗಿನ್",
                    "ಒಟಿಪಿ",
                    "கடவுச்சொல்",
                    "உள்நுழை",
                    "ஓடிபி",
                    "పాస్‌వర్డ్",
                    "పాస్వర్డ్",
                    "లాగిన్",
                    "ఓటీపీ",
                })

                if harmless_only and not malicious_auth:
                    continue

            scores[category] = (
                len(matched) * config["weight"]
            )

            indicators[category] = matched[:5]

    # --------------------------------------------------------
    # Add malicious-context scores
    # --------------------------------------------------------

    for category, matches in malicious_context.items():

        config = THREAT_CATEGORIES.get(category)

        if not config:
            continue

        # Contextual malicious evidence is stronger than
        # merely mentioning a word.
        context_score = len(matches) * config["weight"] * 2

        scores[category] = (
            scores.get(category, 0)
            + context_score
        )

        existing = indicators.get(category, [])

        indicators[category] = list(
            dict.fromkeys(
                existing + matches
            )
        )[:5]

    # --------------------------------------------------------
    # Security-awareness protection
    #
    # Awareness messages should not become Credential Theft
    # simply because they mention OTP/password/account.
    # --------------------------------------------------------

    if awareness:

        # If there is no strong malicious context,
        # classify as Security Awareness.
        if not malicious_context:

            awareness_confidence = min(
                0.95,
                0.70 + (len(awareness_matches) * 0.05),
            )

            return {
                "primary_category": "Security Awareness",
                "secondary_category": None,
                "description": (
                    "Security-awareness or educational message "
                    "using protective language rather than "
                    "requesting credentials, payment, or account access"
                ),
                "severity": "Low",
                "confidence": round(
                    awareness_confidence,
                    2,
                ),
                "all_scores": {},
                "indicators": (
                    [f"Language: {awareness_language}"]
                    + awareness_matches[:5]
                ),
                "language": awareness_language,
                "security_awareness": True,
            }

    # --------------------------------------------------------
    # No meaningful category
    # --------------------------------------------------------

    if not scores:

        if spoofed_brand:
            return {
                "primary_category": "Brand Impersonation",
                "secondary_category": None,
                "description": (
                    f"Impersonates {spoofed_brand} "
                    "without a specific attack pattern"
                ),
                "severity": "High",
                "confidence": 0.50,
                "all_scores": {},
                "indicators": [],
                "language": language,
                "security_awareness": awareness,
            }

        return {
            "primary_category": None,
            "secondary_category": None,
            "description": (
                "No specific phishing threat category identified"
            ),
            "severity": "Low",
            "confidence": 0.0,
            "all_scores": {},
            "indicators": [],
            "language": language,
            "security_awareness": awareness,
        }

    # --------------------------------------------------------
    # Sort categories
    # --------------------------------------------------------

    sorted_categories = sorted(
        scores.items(),
        key=lambda item: item[1],
        reverse=True,
    )

    primary = sorted_categories[0][0]

    secondary = (
        sorted_categories[1][0]
        if len(sorted_categories) > 1
        else None
    )

    total_score = sum(scores.values())

    confidence = min(
        scores[primary] / max(total_score, 1),
        0.99,
    )

    # --------------------------------------------------------
    # Awareness + malicious context
    #
    # Example:
    #
    # "Security awareness: don't share OTP"
    #
    # should remain awareness.
    #
    # But:
    #
    # "Your account is suspended, enter OTP immediately"
    #
    # should remain Credential Theft.
    # --------------------------------------------------------

    if awareness and malicious_context:

        # If malicious evidence is substantially stronger,
        # retain the malicious category.
        malicious_total = sum(
            len(v)
            for v in malicious_context.values()
        )

        awareness_count = len(awareness_matches)

        if awareness_count > malicious_total:
            return {
                "primary_category": "Security Awareness",
                "secondary_category": primary,
                "description": (
                    "Security-awareness message containing "
                    "some security-related terminology"
                ),
                "severity": "Low",
                "confidence": 0.85,
                "all_scores": scores,
                "indicators": (
                    [f"Language: {language}"]
                    + awareness_matches[:4]
                ),
                "language": language,
                "security_awareness": True,
            }

    # --------------------------------------------------------
    # Final category result
    # --------------------------------------------------------

    return {
        "primary_category": primary,
        "secondary_category": secondary,
        "description": THREAT_CATEGORIES[primary]["description"],
        "severity": THREAT_CATEGORIES[primary]["severity"],
        "confidence": round(confidence, 2),
        "all_scores": scores,
        "indicators": indicators.get(primary, [])[:5],
        "language": language,
        "security_awareness": awareness,
    }


# ============================================================
# TEST CASES
# ============================================================

if __name__ == "__main__":

    tests = [

        (
            "Your SBI net banking password has expired. "
            "Login now to reset your OTP.",
            "Account Suspended",
        ),

        (
            "Congratulations! You have won a lottery prize "
            "of Rs 50,000. Claim now.",
            "You Won a Prize",
        ),

        (
            "Your KYC is pending. Submit Aadhaar and PAN "
            "card details immediately.",
            "KYC Update",
        ),

        (
            "Income tax refund of Rs 12,500 is pending. "
            "Verify your bank account.",
            "IT Refund Alert",
        ),

        (
            "Package delivery failed. Pay Rs 50 customs fee "
            "to release your parcel.",
            "Delivery Notice",
        ),

        (
            "Your computer has a virus. Call our toll-free "
            "Microsoft support helpline.",
            "Security Alert",
        ),

        # ----------------------------------------------------
        # LEGITIMATE EMAIL
        # ----------------------------------------------------

        (
            "With your Elsevier account you can sign in, "
            "edit your details and make institutional "
            "connections for a range of Elsevier products. "
            "You can change your communication preferences "
            "from your Elsevier Account. "
            "The Elsevier team",
            "Welcome to Elsevier",
        ),

        (
            "Hi Rahul, please find attached the quarterly "
            "sales report. Let me know if you have any "
            "questions. Thanks.",
            "Quarterly Sales Report",
        ),

        # ----------------------------------------------------
        # ENGLISH SECURITY AWARENESS
        # ----------------------------------------------------

        (
            "Do not share your password or OTP with anyone. "
            "Stay alert and protect your account.",
            "Security Awareness",
        ),

        # ----------------------------------------------------
        # HINDI SECURITY AWARENESS
        # ----------------------------------------------------

        (
            "अपना पासवर्ड और ओटीपी किसी के साथ साझा न करें। "
            "सतर्क रहें और अपने खाते को सुरक्षित रखें।",
            "बैंक सुरक्षा जागरूकता",
        ),

        # ----------------------------------------------------
        # KANNADA SECURITY AWARENESS
        # ----------------------------------------------------

        (
            "ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ ಒಟಿಪಿಯನ್ನು ಯಾರೊಂದಿಗೂ "
            "ಹಂಚಿಕೊಳ್ಳಬೇಡಿ. ಎಚ್ಚರಿಕೆಯಿಂದಿರಿ ಮತ್ತು ನಿಮ್ಮ "
            "ಖಾತೆಯನ್ನು ರಕ್ಷಿಸಿಕೊಳ್ಳಿ.",
            "ಬ್ಯಾಂಕ್ ಭದ್ರತಾ ಜಾಗೃತಿ",
        ),

        # ----------------------------------------------------
        # TAMIL SECURITY AWARENESS
        # ----------------------------------------------------

        (
            "உங்கள் கடவுச்சொல் அல்லது OTP யாருடனும் "
            "பகிர வேண்டாம். விழிப்புடன் இருங்கள்.",
            "வங்கி பாதுகாப்பு விழிப்புணர்வு",
        ),

        # ----------------------------------------------------
        # TELUGU SECURITY AWARENESS
        # ----------------------------------------------------

        (
            "మీ పాస్‌వర్డ్ లేదా ఓటీపీ ఎవరితోనూ "
            "పంచుకోవద్దు. జాగ్రత్తగా ఉండండి.",
            "బ్యాంక్ భద్రతా అవగాహన",
        ),

        # ----------------------------------------------------
        # ACTUAL CREDENTIAL PHISHING
        # ----------------------------------------------------

        (
            "URGENT: Your account has been suspended. "
            "Click here immediately and enter your password "
            "and OTP to restore access.",
            "URGENT: Verify Your Account",
        ),

        # ----------------------------------------------------
        # ACTUAL KYC PHISHING
        # ----------------------------------------------------

        (
            "Your KYC is pending and your bank account will "
            "be suspended. Submit your Aadhaar, PAN and OTP "
            "immediately.",
            "Urgent KYC Verification",
        ),
    ]

    print("=" * 70)
    print("CyberGuard AI — Context-Aware Threat Classifier Test")
    print("=" * 70)

    for text, subject in tests:

        result = classify_threat(
            email_text=text,
            subject=subject,
        )

        print("\n" + "-" * 70)
        print(f"Subject        : {subject}")
        print(f"Language       : {result['language']}")
        print(f"Category       : {result['primary_category']}")
        print(f"Secondary      : {result['secondary_category']}")
        print(f"Severity       : {result['severity']}")
        print(f"Confidence     : {result['confidence']:.0%}")
        print(f"Awareness      : {result['security_awareness']}")
        print(f"Description    : {result['description']}")
        print(f"Signals        : {result['indicators']}")
        print(f"Scores         : {result['all_scores']}")