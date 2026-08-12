# ============================================================
# CyberGuard AI — ai/subject_analyzer.py
#
# Multilingual Email Subject Analyzer
#
# Supported languages:
#   - English
#   - Hindi
#   - Kannada
#   - Tamil
#   - Telugu
#
# Purpose:
#   Detect phishing/social-engineering signals from the
#   email subject line.
#
# Output:
#   - subject
#   - found
#   - urgency_words
#   - urgency_count
#   - is_reply
#   - is_forward
#   - has_numbers
#   - risk_boost
#   - subject_risk
#   - flags
#
# IMPORTANT:
#   This module is only ONE signal in the CyberGuard AI
#   phishing pipeline. It does not make the final verdict.
# ============================================================

import re


# ============================================================
# ENGLISH PHISHING / URGENCY SUBJECT PATTERNS
# ============================================================

URGENCY_SUBJECTS_EN = [

    # --------------------------------------------------------
    # General urgency
    # --------------------------------------------------------

    "urgent",
    "urgently",
    "immediate",
    "immediately",
    "action required",
    "action needed",
    "action needed immediately",
    "act now",
    "take action",
    "respond now",
    "respond immediately",
    "attention required",
    "important",
    "important notice",
    "important update",
    "critical notice",
    "critical alert",

    # --------------------------------------------------------
    # Account security
    # --------------------------------------------------------

    "account suspended",
    "account has been suspended",
    "account will be suspended",
    "account blocked",
    "account has been blocked",
    "account locked",
    "account has been locked",
    "account disabled",
    "account has been disabled",
    "account compromised",
    "account security",
    "account security alert",
    "account verification",
    "account verification required",
    "verify account",
    "verify your account",
    "verify account now",
    "verify your identity",
    "confirm your identity",
    "confirm your account",
    "confirm account",
    "validate your account",
    "update your account",
    "secure your account",

    # --------------------------------------------------------
    # Login / sign-in
    # --------------------------------------------------------

    "new sign-in",
    "new signin",
    "new login",
    "new login attempt",
    "unusual sign-in",
    "unusual signin",
    "unusual login",
    "unusual login activity",
    "unusual sign-in activity",
    "suspicious login",
    "suspicious login activity",
    "suspicious sign-in",
    "suspicious sign-in activity",
    "unknown login",
    "unknown sign-in",
    "unauthorized login",
    "unauthorized sign-in",
    "unauthorized access",
    "unrecognized login",
    "unrecognized sign-in",
    "new device",
    "new device detected",
    "login alert",
    "sign-in alert",
    "security alert",

    # --------------------------------------------------------
    # Password
    # --------------------------------------------------------

    "password expired",
    "password has expired",
    "password reset",
    "reset password",
    "reset your password",
    "change password",
    "password change required",
    "password verification",
    "password required",
    "password alert",
    "password security",

    # --------------------------------------------------------
    # Security warnings
    # --------------------------------------------------------

    "security warning",
    "security notice",
    "security alert",
    "security update",
    "security notification",
    "security verification",
    "security check",
    "security issue",
    "security breach",
    "security incident",
    "suspicious activity",
    "unusual activity",
    "unauthorized activity",
    "fraud alert",
    "fraud warning",
    "fraud detected",
    "suspicious activity detected",
    "unusual activity detected",
    "unauthorized activity detected",

    # --------------------------------------------------------
    # KYC / verification
    # --------------------------------------------------------

    "kyc",
    "kyc update",
    "kyc required",
    "kyc pending",
    "kyc verification",
    "kyc verification required",
    "complete kyc",
    "verify kyc",
    "update kyc",
    "identity verification",
    "identity verification required",
    "verification required",
    "verification pending",
    "verify now",
    "verify immediately",
    "verification needed",

    # --------------------------------------------------------
    # Warning / final warning
    # --------------------------------------------------------

    "warning",
    "final warning",
    "last warning",
    "final notice",
    "last notice",
    "final reminder",
    "last reminder",
    "final chance",
    "last chance",
    "account warning",
    "security warning",

    # --------------------------------------------------------
    # Time pressure
    # --------------------------------------------------------

    "limited time",
    "expires soon",
    "expiring soon",
    "expires today",
    "expires tomorrow",
    "deadline",
    "deadline today",
    "deadline tomorrow",
    "within 24 hours",
    "within 48 hours",
    "within 12 hours",
    "respond within",
    "act within",
    "only today",
    "today only",

    # --------------------------------------------------------
    # Financial / banking
    # --------------------------------------------------------

    "payment failed",
    "payment pending",
    "payment required",
    "payment declined",
    "payment rejected",
    "payment verification",
    "payment verification required",
    "verify payment",
    "confirm payment",
    "invoice",
    "invoice overdue",
    "invoice pending",
    "invoice payment",
    "refund",
    "refund pending",
    "claim refund",
    "tax refund",
    "it refund",
    "bank alert",
    "banking alert",
    "transaction alert",
    "transaction failed",
    "transaction pending",
    "transaction declined",
    "unusual transaction",
    "unauthorized transaction",

    # --------------------------------------------------------
    # Rewards / prizes / lottery
    # --------------------------------------------------------

    "prize",
    "winner",
    "you won",
    "you have won",
    "congratulations",
    "lottery",
    "lottery winner",
    "reward",
    "cashback",
    "cashback offer",
    "free gift",
    "gift waiting",
    "claim your prize",
    "claim your reward",
    "claim your gift",
    "selected",
    "you have been selected",
    "exclusive reward",
    "exclusive offer",
    "special offer",
    "bonus",
    "free reward",

    # --------------------------------------------------------
    # Delivery / parcel
    # --------------------------------------------------------

    "delivery failed",
    "delivery attempt failed",
    "parcel held",
    "parcel pending",
    "package held",
    "package pending",
    "package delivery",
    "delivery update",
    "delivery confirmation",
    "shipping update",
    "shipment pending",
    "shipment delayed",
    "customs clearance",
    "customs fee",
    "delivery fee",

    # --------------------------------------------------------
    # Common phishing thread manipulation
    # --------------------------------------------------------

    "re:",
    "fwd:",
    "fw:",
    "[external]",
    "[external email]",
]


# ============================================================
# HINDI PHISHING / URGENCY SUBJECT PATTERNS
# ============================================================

URGENCY_SUBJECTS_HI = [

    # General urgency
    "तुरंत",
    "अभी",
    "अभी करें",
    "तुरंत करें",
    "तुरंत कार्रवाई",
    "तुरंत कार्रवाई करें",
    "जरूरी",
    "अति आवश्यक",
    "अत्यावश्यक",
    "तत्काल",
    "तत्काल कार्रवाई",
    "कार्रवाई आवश्यक",
    "कार्रवाई जरूरी",
    "ध्यान दें",

    # Account
    "खाता",
    "आपका खाता",
    "खाता बंद",
    "खाता बंद हो जाएगा",
    "खाता निलंबित",
    "खाता निलंबित हो जाएगा",
    "खाता लॉक",
    "खाता लॉक हो जाएगा",
    "खाता अवरुद्ध",
    "खाता ब्लॉक",
    "खाता ब्लॉक हो जाएगा",
    "खाता निष्क्रिय",
    "खाते की सुरक्षा",
    "खाता सुरक्षित करें",
    "अपना खाता सत्यापित करें",
    "खाता सत्यापित करें",

    # Verification
    "सत्यापित",
    "सत्यापन",
    "सत्यापन आवश्यक",
    "सत्यापन जरूरी",
    "पुष्टि करें",
    "अपनी पहचान सत्यापित करें",
    "पहचान सत्यापन",
    "पहचान सत्यापन आवश्यक",
    "खाता सत्यापन",

    # Login / activity
    "साइन-इन",
    "साइन इन",
    "साइनिन",
    "लॉगिन",
    "लॉग इन",
    "नया लॉगिन",
    "नया साइन-इन",
    "असामान्य",
    "असामान्य गतिविधि",
    "संदिग्ध गतिविधि",
    "अनधिकृत गतिविधि",
    "असामान्य लॉगिन",
    "संदिग्ध लॉगिन",
    "अनधिकृत लॉगिन",
    "सुरक्षा चेतावनी",
    "सुरक्षा सूचना",
    "सुरक्षा अलर्ट",
    "सुरक्षा जांच",

    # Password
    "पासवर्ड",
    "पासवर्ड समाप्त",
    "पासवर्ड समाप्त हो गया",
    "पासवर्ड रीसेट",
    "पासवर्ड बदलें",
    "पासवर्ड बदलना आवश्यक",
    "पासवर्ड सत्यापन",

    # KYC
    "केवाईसी",
    "KYC",
    "केवाईसी अपडेट",
    "केवाईसी आवश्यक",
    "केवाईसी लंबित",
    "केवाईसी सत्यापन",
    "केवाईसी पूरा करें",
    "अपना केवाईसी अपडेट करें",

    # Warnings
    "चेतावनी",
    "अंतिम चेतावनी",
    "अंतिम सूचना",
    "अंतिम मौका",
    "आखिरी चेतावनी",
    "आखिरी मौका",
    "महत्वपूर्ण सूचना",
    "महत्वपूर्ण अपडेट",

    # Financial
    "भुगतान",
    "भुगतान विफल",
    "भुगतान लंबित",
    "भुगतान आवश्यक",
    "भुगतान सत्यापन",
    "बैंक अलर्ट",
    "बैंक चेतावनी",
    "लेनदेन",
    "लेनदेन विफल",
    "अनधिकृत लेनदेन",
    "संदिग्ध लेनदेन",
    "रिफंड",
    "रिफंड लंबित",
    "टैक्स रिफंड",

    # Prize / lottery
    "इनाम",
    "पुरस्कार",
    "लॉटरी",
    "लॉटरी विजेता",
    "आप जीत गए",
    "आपने जीत लिया",
    "बधाई",
    "कैशबैक",
    "कैशबैक ऑफर",
    "मुफ्त उपहार",
    "अपना इनाम प्राप्त करें",
    "इनाम प्राप्त करें",
    "आप चुने गए हैं",

    # Delivery
    "डिलीवरी विफल",
    "डिलीवरी असफल",
    "पार्सल",
    "पार्सल रोका गया",
    "पैकेज",
    "पैकेज रोका गया",
    "शिपमेंट",
    "शिपमेंट लंबित",
    "कस्टम शुल्क",
]


# ============================================================
# KANNADA PHISHING / URGENCY SUBJECT PATTERNS
# ============================================================

URGENCY_SUBJECTS_KN = [

    # General urgency
    "ತಕ್ಷಣ",
    "ತಕ್ಷಣವೇ",
    "ಈಗಲೇ",
    "ಈಗಲೇ ಮಾಡಿ",
    "ತುರ್ತು",
    "ಅಗತ್ಯ",
    "ಅತ್ಯಗತ್ಯ",
    "ತಕ್ಷಣ ಕ್ರಮ",
    "ಕ್ರಮ ಅಗತ್ಯ",
    "ತಕ್ಷಣ ಕ್ರಮ ಕೈಗೊಳ್ಳಿ",
    "ಗಮನಿಸಿ",
    "ಮುಖ್ಯ ಸೂಚನೆ",

    # Account
    "ಖಾತೆ",
    "ನಿಮ್ಮ ಖಾತೆ",
    "ಖಾತೆ ಮುಚ್ಚು",
    "ಖಾತೆ ಮುಚ್ಚಲಾಗುವುದು",
    "ಖಾತೆ ಸ್ಥಗಿತ",
    "ಖಾತೆ ಸ್ಥಗಿತಗೊಳಿಸಲಾಗಿದೆ",
    "ಖಾತೆ ಲಾಕ್",
    "ಖಾತೆ ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ",
    "ಖಾತೆ ಬ್ಲಾಕ್",
    "ಖಾತೆ ನಿಷ್ಕ್ರಿಯ",
    "ಖಾತೆಯ ಸುರಕ್ಷತೆ",
    "ನಿಮ್ಮ ಖಾತೆಯನ್ನು ಪರಿಶೀಲಿಸಿ",

    # Verification
    "ಪರಿಶೀಲಿಸಿ",
    "ಪರಿಶೀಲನೆ",
    "ಪರಿಶೀಲನೆ ಅಗತ್ಯ",
    "ಖಾತೆ ಪರಿಶೀಲನೆ",
    "ಗುರುತಿನ ಪರಿಶೀಲನೆ",
    "ಗುರುತನ್ನು ಪರಿಶೀಲಿಸಿ",
    "ದೃಢೀಕರಿಸಿ",
    "ದೃಢೀಕರಣ",
    "ದೃಢೀಕರಣ ಅಗತ್ಯ",

    # Login / activity
    "ಸೈನ್ ಇನ್",
    "ಸೈನ್-ಇನ್",
    "ಲಾಗಿನ್",
    "ಹೊಸ ಲಾಗಿನ್",
    "ಅಸಾಮಾನ್ಯ",
    "ಅಸಾಮಾನ್ಯ ಚಟುವಟಿಕೆ",
    "ಸಂದೇಹಾಸ್ಪದ ಚಟುವಟಿಕೆ",
    "ಅನುಮತಿಯಿಲ್ಲದ ಚಟುವಟಿಕೆ",
    "ಅಸಾಮಾನ್ಯ ಲಾಗಿನ್",
    "ಸಂದೇಹಾಸ್ಪದ ಲಾಗಿನ್",
    "ಅನುಮತಿಯಿಲ್ಲದ ಲಾಗಿನ್",
    "ಭದ್ರತಾ ಎಚ್ಚರಿಕೆ",
    "ಭದ್ರತಾ ಸೂಚನೆ",
    "ಭದ್ರತಾ ಎಚ್ಚರಿಕೆ ಸಂದೇಶ",
    "ಭದ್ರತಾ ಪರಿಶೀಲನೆ",

    # Password
    "ಪಾಸ್‌ವರ್ಡ್",
    "ಪಾಸ್ವರ್ಡ್",
    "ಪಾಸ್‌ವರ್ಡ್ ಅವಧಿ ಮುಗಿದಿದೆ",
    "ಪಾಸ್‌ವರ್ಡ್ ಮರುಹೊಂದಿಸಿ",
    "ಪಾಸ್‌ವರ್ಡ್ ಬದಲಾಯಿಸಿ",
    "ಪಾಸ್‌ವರ್ಡ್ ಪರಿಶೀಲನೆ",

    # KYC
    "ಕೆವೈಸಿ",
    "KYC",
    "ಕೆವೈಸಿ ನವೀಕರಿಸಿ",
    "ಕೆವೈಸಿ ಅಗತ್ಯ",
    "ಕೆವೈಸಿ ಬಾಕಿ",
    "ಕೆವೈಸಿ ಪರಿಶೀಲನೆ",
    "ಕೆವೈಸಿ ಪೂರ್ಣಗೊಳಿಸಿ",

    # Warning
    "ಎಚ್ಚರಿಕೆ",
    "ಅಂತಿಮ ಎಚ್ಚರಿಕೆ",
    "ಕೊನೆಯ ಎಚ್ಚರಿಕೆ",
    "ಅಂತಿಮ ಸೂಚನೆ",
    "ಕೊನೆಯ ಅವಕಾಶ",
    "ಮುಖ್ಯ ಸೂಚನೆ",
    "ಮುಖ್ಯ ನವೀಕರಣ",

    # Financial
    "ಪಾವತಿ",
    "ಪಾವತಿ ವಿಫಲ",
    "ಪಾವತಿ ಬಾಕಿ",
    "ಪಾವತಿ ಅಗತ್ಯ",
    "ಪಾವತಿ ಪರಿಶೀಲನೆ",
    "ಬ್ಯಾಂಕ್ ಎಚ್ಚರಿಕೆ",
    "ಬ್ಯಾಂಕ್ ಸೂಚನೆ",
    "ವಹಿವಾಟು",
    "ವಹಿವಾಟು ವಿಫಲ",
    "ಅನುಮತಿಯಿಲ್ಲದ ವಹಿವಾಟು",
    "ಸಂದೇಹಾಸ್ಪದ ವಹಿವಾಟು",
    "ಹಣ ಮರುಪಾವತಿ",

    # Prize / lottery
    "ಬಹುಮಾನ",
    "ಲಾಟರಿ",
    "ಲಾಟರಿ ವಿಜೇತ",
    "ನೀವು ಗೆದ್ದಿದ್ದೀರಿ",
    "ಅಭಿನಂದನೆಗಳು",
    "ಬಹುಮಾನ ಪಡೆಯಿರಿ",
    "ಕ್ಯಾಶ್‌ಬ್ಯಾಕ್",
    "ಉಚಿತ ಉಡುಗೊರೆ",
    "ನೀವು ಆಯ್ಕೆಯಾಗಿದ್ದೀರಿ",

    # Delivery
    "ವಿತರಣಾ ವಿಫಲ",
    "ಪಾರ್ಸೆಲ್",
    "ಪಾರ್ಸೆಲ್ ತಡೆಹಿಡಿಯಲಾಗಿದೆ",
    "ಪ್ಯಾಕೇಜ್",
    "ಪ್ಯಾಕೇಜ್ ತಡೆಹಿಡಿಯಲಾಗಿದೆ",
    "ಸರಕು ಸಾಗಣೆ",
    "ಶುಲ್ಕ",
]


# ============================================================
# TAMIL PHISHING / URGENCY SUBJECT PATTERNS
# ============================================================

URGENCY_SUBJECTS_TA = [

    # General urgency
    "உடனடியாக",
    "உடனே",
    "இப்போதே",
    "அவசரம்",
    "மிகவும் அவசரம்",
    "அவசியம்",
    "உடனடி நடவடிக்கை",
    "நடவடிக்கை தேவை",
    "உடனடியாக நடவடிக்கை எடுக்கவும்",
    "கவனம்",
    "முக்கிய அறிவிப்பு",

    # Account
    "கணக்கு",
    "உங்கள் கணக்கு",
    "கணக்கு மூடப்படும்",
    "கணக்கு முடக்கப்பட்டது",
    "கணக்கு இடைநிறுத்தப்பட்டது",
    "கணக்கு பூட்டப்பட்டது",
    "கணக்கு தடைசெய்யப்பட்டது",
    "கணக்கு செயலிழக்கப்பட்டது",
    "கணக்கு பாதுகாப்பு",
    "உங்கள் கணக்கை சரிபார்க்கவும்",

    # Verification
    "சரிபார்க்க",
    "சரிபார்க்கவும்",
    "சரிபார்ப்பு",
    "சரிபார்ப்பு தேவை",
    "கணக்கு சரிபார்ப்பு",
    "அடையாள சரிபார்ப்பு",
    "அடையாளத்தை சரிபார்க்கவும்",
    "உறுதிப்படுத்தவும்",
    "உறுதிப்படுத்தல்",
    "உறுதிப்படுத்தல் தேவை",

    # Login / activity
    "சைன்-இன்",
    "சைன் இன்",
    "உள்நுழைவு",
    "புதிய உள்நுழைவு",
    "அசாதாரண",
    "அசாதாரண செயல்பாடு",
    "சந்தேகத்திற்கிடமான செயல்பாடு",
    "அனுமதியற்ற செயல்பாடு",
    "அசாதாரண உள்நுழைவு",
    "சந்தேகத்திற்கிடமான உள்நுழைவு",
    "அனுமதியற்ற உள்நுழைவு",
    "பாதுகாப்பு எச்சரிக்கை",
    "பாதுகாப்பு அறிவிப்பு",
    "பாதுகாப்பு சரிபார்ப்பு",

    # Password
    "கடவுச்சொல்",
    "கடவுச்சொல் காலாவதியானது",
    "கடவுச்சொல் மீட்டமைப்பு",
    "கடவுச்சொல்லை மாற்றவும்",
    "கடவுச்சொல் சரிபார்ப்பு",

    # KYC
    "கேஒய்சி",
    "KYC",
    "கேஒய்சி புதுப்பிப்பு",
    "கேஒய்சி தேவை",
    "கேஒய்சி நிலுவையில்",
    "கேஒய்சி சரிபார்ப்பு",
    "கேஒய்சியை முடிக்கவும்",

    # Warning
    "எச்சரிக்கை",
    "இறுதி எச்சரிக்கை",
    "கடைசி எச்சரிக்கை",
    "இறுதி அறிவிப்பு",
    "கடைசி வாய்ப்பு",
    "முக்கிய அறிவிப்பு",
    "முக்கிய புதுப்பிப்பு",

    # Financial
    "கட்டணம்",
    "கட்டணம் தோல்வியடைந்தது",
    "கட்டணம் நிலுவையில்",
    "கட்டணம் தேவை",
    "கட்டண சரிபார்ப்பு",
    "வங்கி எச்சரிக்கை",
    "வங்கி அறிவிப்பு",
    "பரிவர்த்தனை",
    "பரிவர்த்தனை தோல்வி",
    "அனுமதியற்ற பரிவர்த்தனை",
    "சந்தேகத்திற்கிடமான பரிவர்த்தனை",
    "பணத்தைத் திரும்பப் பெறுதல்",

    # Prize / lottery
    "பரிசு",
    "லாட்டரி",
    "லாட்டரி வெற்றியாளர்",
    "நீங்கள் வென்றுள்ளீர்கள்",
    "வாழ்த்துக்கள்",
    "உங்கள் பரிசைப் பெறுங்கள்",
    "கேஷ்பேக்",
    "இலவச பரிசு",
    "நீங்கள் தேர்ந்தெடுக்கப்பட்டுள்ளீர்கள்",

    # Delivery
    "டெலிவரி தோல்வி",
    "பார்சல்",
    "பார்சல் நிறுத்தப்பட்டுள்ளது",
    "தொகுப்பு",
    "தொகுப்பு நிறுத்தப்பட்டுள்ளது",
    "ஷிப்மென்ட்",
    "ஷிப்மென்ட் நிலுவையில்",
    "சுங்கக் கட்டணம்",
]


# ============================================================
# TELUGU PHISHING / URGENCY SUBJECT PATTERNS
# ============================================================

URGENCY_SUBJECTS_TE = [

    # General urgency
    "వెంటనే",
    "తక్షణమే",
    "ఇప్పుడే",
    "అత్యవసరం",
    "అవసరం",
    "తక్షణ చర్య",
    "చర్య అవసరం",
    "వెంటనే చర్య తీసుకోండి",
    "గమనించండి",
    "ముఖ్యమైన నోటీసు",

    # Account
    "ఖాతా",
    "మీ ఖాతా",
    "ఖాతా మూసివేయబడుతుంది",
    "ఖాతా నిలిపివేయబడింది",
    "ఖాతా సస్పెండ్",
    "ఖాతా లాక్",
    "ఖాతా బ్లాక్",
    "ఖాతా నిలిపివేత",
    "ఖాతా క్రియారహితం",
    "ఖాతా భద్రత",
    "మీ ఖాతాను ధృవీకరించండి",

    # Verification
    "ధృవీకరించండి",
    "ధృవీకరణ",
    "ధృవీకరణ అవసరం",
    "ఖాతా ధృవీకరణ",
    "గుర్తింపు ధృవీకరణ",
    "మీ గుర్తింపును ధృవీకరించండి",
    "నిర్ధారించండి",
    "నిర్ధారణ",
    "నిర్ధారణ అవసరం",

    # Login / activity
    "సైన్-ఇన్",
    "సైన్ ఇన్",
    "లాగిన్",
    "కొత్త లాగిన్",
    "అసాధారణ",
    "అసాధారణ కార్యకలాపం",
    "అనుమానాస్పద కార్యకలాపం",
    "అనధికార కార్యకలాపం",
    "అసాధారణ లాగిన్",
    "అనుమానాస్పద లాగిన్",
    "అనధికార లాగిన్",
    "భద్రతా హెచ్చరిక",
    "భద్రతా నోటీసు",
    "భద్రతా తనిఖీ",
    "భద్రతా ధృవీకరణ",

    # Password
    "పాస్‌వర్డ్",
    "పాస్వర్డ్",
    "పాస్‌వర్డ్ గడువు ముగిసింది",
    "పాస్‌వర్డ్ రీసెట్",
    "పాస్‌వర్డ్ మార్చండి",
    "పాస్‌వర్డ్ ధృవీకరణ",

    # KYC
    "కెవైసి",
    "KYC",
    "కెవైసి నవీకరణ",
    "కెవైసి అవసరం",
    "కెవైసి పెండింగ్",
    "కెవైసి ధృవీకరణ",
    "కెవైసి పూర్తి చేయండి",

    # Warning
    "హెచ్చరిక",
    "చివరి హెచ్చరిక",
    "చివరి నోటీసు",
    "చివరి అవకాశం",
    "ముఖ్యమైన నోటీసు",
    "ముఖ్యమైన నవీకరణ",

    # Financial
    "చెల్లింపు",
    "చెల్లింపు విఫలమైంది",
    "చెల్లింపు పెండింగ్",
    "చెల్లింపు అవసరం",
    "చెల్లింపు ధృవీకరణ",
    "బ్యాంక్ హెచ్చరిక",
    "బ్యాంక్ నోటీసు",
    "లావాదేవీ",
    "లావాదేవీ విఫలమైంది",
    "అనధికార లావాదేవీ",
    "అనుమానాస్పద లావాదేవీ",
    "రిఫండ్",

    # Prize / lottery
    "బహుమతి",
    "లాటరీ",
    "లాటరీ విజేత",
    "మీరు గెలిచారు",
    "అభినందనలు",
    "మీ బహుమతిని పొందండి",
    "క్యాష్‌బ్యాక్",
    "ఉచిత బహుమతి",
    "మీరు ఎంపికయ్యారు",

    # Delivery
    "డెలివరీ విఫలమైంది",
    "పార్సెల్",
    "పార్సెల్ నిలిపివేయబడింది",
    "ప్యాకేజీ",
    "ప్యాకేజీ నిలిపివేయబడింది",
    "షిప్‌మెంట్",
    "షిప్‌మెంట్ పెండింగ్",
    "కస్టమ్స్ ఫీజు",
]


# ============================================================
# COMBINE ALL LANGUAGES
# ============================================================

ALL_URGENCY = (
    URGENCY_SUBJECTS_EN
    + URGENCY_SUBJECTS_HI
    + URGENCY_SUBJECTS_KN
    + URGENCY_SUBJECTS_TA
    + URGENCY_SUBJECTS_TE
)


# ============================================================
# LANGUAGE-SPECIFIC INFORMATION
# ============================================================

LANGUAGE_PATTERNS = {
    "en": URGENCY_SUBJECTS_EN,
    "hi": URGENCY_SUBJECTS_HI,
    "kn": URGENCY_SUBJECTS_KN,
    "ta": URGENCY_SUBJECTS_TA,
    "te": URGENCY_SUBJECTS_TE,
}


# ============================================================
# NORMALIZE SUBJECT
# ============================================================

def normalize_subject(subject: str) -> str:
    """
    Normalize subject text without destroying Unicode characters.

    Keeps:
        - English
        - Hindi
        - Kannada
        - Tamil
        - Telugu

    Only normalizes whitespace and common dash variations.
    """

    if not subject:
        return ""

    subject = str(subject)

    # Normalize different Unicode dash characters
    subject = subject.replace("–", "-")
    subject = subject.replace("—", "-")
    subject = subject.replace("-", "-")

    # Normalize whitespace
    subject = re.sub(r"\s+", " ", subject)

    return subject.strip()


# ============================================================
# PHRASE MATCHING
# ============================================================

def _phrase_pattern(phrase: str) -> str:
    """
    Build a flexible regex pattern for a phrase.

    Example:

        "account suspended"

    can match:

        "account suspended"
        "account   suspended"
        "account will be suspended"

    without requiring an exact literal substring.

    Unicode text is supported.
    """

    phrase = normalize_subject(phrase)

    if not phrase:
        return ""

    words = phrase.split()

    # --------------------------------------------------------
    # Special handling for phrases containing punctuation.
    # --------------------------------------------------------

    pattern_parts = []

    for word in words:

        escaped = re.escape(word)

        # Allow common punctuation variation around words
        escaped = escaped.replace(r"\-", r"[--–— ]?")

        pattern_parts.append(escaped)

    # --------------------------------------------------------
    # Join words flexibly.
    #
    # We intentionally allow a small number of words between
    # important words for English phrases such as:
    #
    # "account will be suspended"
    #
    # while still avoiding arbitrary substring matching.
    # --------------------------------------------------------

    if len(pattern_parts) == 1:
        return pattern_parts[0]

    return r"\b" + r"(?:\W+|\s+)".join(pattern_parts) + r"\b"


def _contains_phrase(subject_lower: str, phrase: str) -> bool:
    """
    Check whether a phrase exists in the subject.
    """

    phrase = normalize_subject(phrase)

    if not phrase:
        return False

    # --------------------------------------------------------
    # First try direct Unicode-aware substring matching.
    #
    # This is particularly useful for Indian-language text
    # where word boundaries are not always handled consistently
    # by regex engines.
    # --------------------------------------------------------

    if phrase.lower() in subject_lower:
        return True

    # --------------------------------------------------------
    # Flexible regex matching
    # --------------------------------------------------------

    pattern = _phrase_pattern(phrase)

    if not pattern:
        return False

    try:
        return bool(
            re.search(
                pattern,
                subject_lower,
                flags=re.IGNORECASE,
            )
        )
    except re.error:
        return False


# ============================================================
# DETECT URGENCY / PHISHING PHRASES
# ============================================================

def detect_urgency_phrases(subject: str) -> list[str]:
    """
    Detect known phishing/urgency phrases.

    Returns unique matched phrases.
    """

    subject = normalize_subject(subject)

    if not subject:
        return []

    subject_lower = subject.lower()

    found = []

    # --------------------------------------------------------
    # Check all multilingual phrases
    # --------------------------------------------------------

    for phrase in ALL_URGENCY:

        if _contains_phrase(subject_lower, phrase):

            if phrase not in found:
                found.append(phrase)

    return found


# ============================================================
# DETECT LANGUAGE-SPECIFIC MATCHES
# ============================================================

def detect_language_matches(subject: str) -> dict:
    """
    Return urgency matches grouped by language.

    Example:

    {
        "en": [...],
        "hi": [...],
        "kn": [...],
        "ta": [...],
        "te": [...]
    }
    """

    subject = normalize_subject(subject)

    result = {
        "en": [],
        "hi": [],
        "kn": [],
        "ta": [],
        "te": [],
    }

    if not subject:
        return result

    subject_lower = subject.lower()

    for language, patterns in LANGUAGE_PATTERNS.items():

        for phrase in patterns:

            if _contains_phrase(subject_lower, phrase):

                if phrase not in result[language]:
                    result[language].append(phrase)

    return result


# ============================================================
# DETECT REPLY / FORWARD
# ============================================================

def detect_reply_forward(subject: str) -> tuple[bool, bool]:
    """
    Detect fake reply/forward prefixes.

    Examples:

        Re:
        Re:
        Fwd:
        FW:
        FW:
        FWD:
    """

    subject = normalize_subject(subject)

    if not subject:
        return False, False

    subject_lower = subject.lower().strip()

    # --------------------------------------------------------
    # Reply
    # --------------------------------------------------------

    is_reply = bool(
        re.match(
            r"^re\s*:",
            subject_lower,
            flags=re.IGNORECASE,
        )
    )

    # --------------------------------------------------------
    # Forward
    # --------------------------------------------------------

    is_forward = bool(
        re.match(
            r"^(fwd|fw)\s*:",
            subject_lower,
            flags=re.IGNORECASE,
        )
    )

    return is_reply, is_forward


# ============================================================
# DETECT NUMBERS
# ============================================================

def detect_numbers(subject: str) -> bool:
    """
    Detect long numeric sequences.

    Examples:

        Invoice 45892
        OTP 123456
        Transaction 987654321
        Ref: 20260811
    """

    if not subject:
        return False

    return bool(
        re.search(
            r"\d{4,}",
            subject,
        )
    )


# ============================================================
# DETECT ALL CAPS
# ============================================================

def detect_all_caps(subject: str) -> bool:
    """
    Detect excessive English uppercase usage.

    Does not incorrectly classify Indian-language Unicode
    subjects as ALL CAPS.
    """

    if not subject:
        return False

    # Extract English alphabetic characters only
    english_letters = re.findall(
        r"[A-Za-z]",
        subject,
    )

    if len(english_letters) < 6:
        return False

    return all(
        char.isupper()
        for char in english_letters
    )


# ============================================================
# DETECT EXCESSIVE PUNCTUATION
# ============================================================

def detect_excessive_punctuation(subject: str) -> bool:
    """
    Detect multiple exclamation marks.

    Examples:

        URGENT!!!
        ACT NOW!!
        VERIFY YOUR ACCOUNT!!!
    """

    if not subject:
        return False

    return subject.count("!") >= 2


# ============================================================
# DETECT SECURITY / ACCOUNT CONTEXT
# ============================================================

SECURITY_CONTEXT_PATTERNS = [

    # English
    "account",
    "login",
    "sign in",
    "signin",
    "password",
    "security",
    "verify",
    "verification",
    "identity",
    "bank",
    "payment",
    "transaction",
    "kyc",
    "otp",

    # Hindi
    "खाता",
    "लॉगिन",
    "साइन इन",
    "पासवर्ड",
    "सुरक्षा",
    "सत्यापन",
    "सत्यापित",
    "बैंक",
    "भुगतान",
    "लेनदेन",
    "ओटीपी",
    "केवाईसी",

    # Kannada
    "ಖಾತೆ",
    "ಲಾಗಿನ್",
    "ಸೈನ್ ಇನ್",
    "ಪಾಸ್‌ವರ್ಡ್",
    "ಪಾಸ್ವರ್ಡ್",
    "ಭದ್ರತೆ",
    "ಪರಿಶೀಲನೆ",
    "ಪರಿಶೀಲಿಸಿ",
    "ಬ್ಯಾಂಕ್",
    "ಪಾವತಿ",
    "ವಹಿವಾಟು",
    "ಒಟಿಪಿ",
    "ಕೆವೈಸಿ",

    # Tamil
    "கணக்கு",
    "உள்நுழைவு",
    "சைன் இன்",
    "கடவுச்சொல்",
    "பாதுகாப்பு",
    "சரிபார்ப்பு",
    "சரிபார்க்க",
    "வங்கி",
    "கட்டணம்",
    "பரிவர்த்தனை",
    "ஓடிபி",
    "கேஒய்சி",

    # Telugu
    "ఖాతా",
    "లాగిన్",
    "సైన్ ఇన్",
    "పాస్‌వర్డ్",
    "పాస్వర్డ్",
    "భద్రత",
    "ధృవీకరణ",
    "ధృవీకరించండి",
    "బ్యాంక్",
    "చెల్లింపు",
    "లావాదేవీ",
    "ఓటీపీ",
    "కెవైసి",
]


def detect_security_context(subject: str) -> list[str]:
    """
    Detect security/account-related terminology.

    This is a contextual signal and should not by itself
    classify an email as phishing.
    """

    subject = normalize_subject(subject)

    if not subject:
        return []

    subject_lower = subject.lower()

    found = []

    for phrase in SECURITY_CONTEXT_PATTERNS:

        if _contains_phrase(
            subject_lower,
            phrase,
        ):
            if phrase not in found:
                found.append(phrase)

    return found


# ============================================================
# CALCULATE SUBJECT RISK
# ============================================================

def calculate_subject_risk(
    urgency_count: int,
    is_reply: bool,
    is_forward: bool,
    has_numbers: bool,
    is_all_caps: bool,
    excessive_punctuation: bool,
    security_context_count: int,
) -> tuple[int, list[str]]:
    """
    Calculate subject risk.

    Maximum:
        30 points

    The score is intentionally capped because the subject is
    only one component of the complete phishing pipeline.
    """

    risk_boost = 0
    flags = []

    # --------------------------------------------------------
    # Urgency / phishing phrases
    # --------------------------------------------------------

    if urgency_count > 0:

        urgency_score = min(
            urgency_count * 8,
            30,
        )

        risk_boost += urgency_score

        flags.append(
            "Urgency/security phrases in subject"
        )

    # --------------------------------------------------------
    # Reply manipulation
    # --------------------------------------------------------

    if is_reply:

        risk_boost += 5

        flags.append(
            "Subject starts with Re: — may be used to "
            "appear as part of a legitimate conversation"
        )

    # --------------------------------------------------------
    # Forward manipulation
    # --------------------------------------------------------

    if is_forward:

        risk_boost += 5

        flags.append(
            "Subject starts with Fwd:/Fw: — may be used "
            "to appear as a forwarded legitimate message"
        )

    # --------------------------------------------------------
    # Long numbers
    # --------------------------------------------------------

    if has_numbers:

        risk_boost += 5

        flags.append(
            "Subject contains a long numeric reference — "
            "possible invoice, transaction or OTP reference"
        )

    # --------------------------------------------------------
    # ALL CAPS
    # --------------------------------------------------------

    if is_all_caps:

        risk_boost += 8

        flags.append(
            "Subject uses ALL CAPS — common urgency/"
            "social-engineering tactic"
        )

    # --------------------------------------------------------
    # Excessive punctuation
    # --------------------------------------------------------

    if excessive_punctuation:

        risk_boost += 5

        flags.append(
            "Multiple exclamation marks — possible "
            "urgency manipulation"
        )

    # --------------------------------------------------------
    # Security context
    #
    # Do NOT add risk merely because words like account,
    # password or security appear.
    #
    # They are contextual signals.
    # --------------------------------------------------------

    if security_context_count >= 2:

        flags.append(
            "Subject contains multiple account/security-related "
            "terms"
        )

    # --------------------------------------------------------
    # Final cap
    # --------------------------------------------------------

    risk_boost = min(
        risk_boost,
        30,
    )

    return risk_boost, flags


# ============================================================
# DETERMINE SUBJECT RISK LEVEL
# ============================================================

def get_subject_risk_level(
    risk_boost: int,
) -> str:
    """
    Convert subject risk score to a readable level.

        0-9   = Low
        10-19 = Medium
        20-29 = High
        30    = Critical
    """

    if risk_boost >= 30:
        return "Critical"

    if risk_boost >= 20:
        return "High"

    if risk_boost >= 10:
        return "Medium"

    return "Low"


# ============================================================
# EXTRACT SUBJECT FROM RAW EMAIL
# ============================================================

def extract_subject_from_email(
    email_text: str,
) -> str:
    """
    Extract Subject: from raw email text.

    Supports:

        Subject: Test

    and common whitespace variations.
    """

    if not email_text:
        return ""

    match = re.search(
        r"(?im)^\s*subject\s*:\s*(.+?)\s*$",
        email_text,
    )

    if match:
        return normalize_subject(
            match.group(1)
        )

    return ""


# ============================================================
# MAIN SUBJECT ANALYZER
# ============================================================

def analyze_subject(
    subject: str = "",
    email_text: str = "",
) -> dict:
    """
    Analyse email subject for phishing signals.

    If subject is not explicitly provided, the function tries
    to extract it from email_text.

    Returns:
        {
            "subject": str,
            "found": bool,
            "urgency_words": list,
            "urgency_count": int,
            "language_matches": dict,
            "security_context": list,
            "is_reply": bool,
            "is_forward": bool,
            "has_numbers": bool,
            "is_all_caps": bool,
            "excessive_punctuation": bool,
            "risk_boost": int,
            "subject_risk": str,
            "flags": list
        }
    """

    # ========================================================
    # STEP 1 — GET SUBJECT
    # ========================================================

    if not subject and email_text:

        subject = extract_subject_from_email(
            email_text
        )

    subject = normalize_subject(
        subject
    )

    # ========================================================
    # EMPTY SUBJECT
    # ========================================================

    if not subject:

        return {
            "subject": "",
            "found": False,
            "urgency_words": [],
            "urgency_count": 0,
            "language_matches": {
                "en": [],
                "hi": [],
                "kn": [],
                "ta": [],
                "te": [],
            },
            "security_context": [],
            "is_reply": False,
            "is_forward": False,
            "has_numbers": False,
            "is_all_caps": False,
            "excessive_punctuation": False,
            "risk_boost": 0,
            "subject_risk": "Unknown",
            "flags": [],
        }

    # ========================================================
    # STEP 2 — DETECT URGENCY PHRASES
    # ========================================================

    found_urgency = detect_urgency_phrases(
        subject
    )

    # ========================================================
    # STEP 3 — LANGUAGE-SPECIFIC MATCHING
    # ========================================================

    language_matches = detect_language_matches(
        subject
    )

    # ========================================================
    # STEP 4 — SECURITY CONTEXT
    # ========================================================

    security_context = detect_security_context(
        subject
    )

    # ========================================================
    # STEP 5 — REPLY / FORWARD
    # ========================================================

    is_reply, is_forward = detect_reply_forward(
        subject
    )

    # ========================================================
    # STEP 6 — NUMBERS
    # ========================================================

    has_numbers = detect_numbers(
        subject
    )

    # ========================================================
    # STEP 7 — ALL CAPS
    # ========================================================

    is_all_caps = detect_all_caps(
        subject
    )

    # ========================================================
    # STEP 8 — PUNCTUATION
    # ========================================================

    excessive_punctuation = (
        detect_excessive_punctuation(
            subject
        )
    )

    # ========================================================
    # STEP 9 — CALCULATE RISK
    # ========================================================

    risk_boost, flags = calculate_subject_risk(

        urgency_count=len(
            found_urgency
        ),

        is_reply=is_reply,

        is_forward=is_forward,

        has_numbers=has_numbers,

        is_all_caps=is_all_caps,

        excessive_punctuation=(
            excessive_punctuation
        ),

        security_context_count=len(
            security_context
        ),
    )

    # ========================================================
    # STEP 10 — RISK LEVEL
    # ========================================================

    subject_risk = get_subject_risk_level(
        risk_boost
    )

    # ========================================================
    # STEP 11 — RETURN RESULT
    # ========================================================

    return {
        "subject": subject,

        "found": True,

        "urgency_words": found_urgency[:10],

        "urgency_count": len(
            found_urgency
        ),

        "language_matches": language_matches,

        "security_context": security_context[:15],

        "is_reply": is_reply,

        "is_forward": is_forward,

        "has_numbers": has_numbers,

        "is_all_caps": is_all_caps,

        "excessive_punctuation": (
            excessive_punctuation
        ),

        "risk_boost": risk_boost,

        "subject_risk": subject_risk,

        "flags": flags,
    }


# ============================================================
# TEST CASES
# ============================================================

if __name__ == "__main__":

    tests = [
        ("URGENT: Your SBI Account Has Been Suspended!!!", "English"),
        ("तुरंत करें - आपका खाता बंद हो जाएगा", "Hindi"),
        ("ತಕ್ಷಣ ಮಾಡಿ - ನಿಮ್ಮ ಖಾತೆಯನ್ನು ಮುಚ್ಚಲಾಗುತ್ತದೆ", "Kannada"),
        ("உடனடியாக செய்யவும் - உங்கள் கணக்கு மூடப்படும்", "Tamil"),
        ("వెంటనే చేయండి - మీ ఖాతా మూసివేయబడుతుంది", "Telugu"),
        ("Q3 Sales Report - Please Review", "Safe English"),
        ("बैंक खाते की सुरक्षा के लिए सावधान रहें", "Safe Hindi"),
        ("ಬ್ಯಾಂಕ್ ಖಾತೆಯ ಸುರಕ್ಷತೆಗಾಗಿ ಎಚ್ಚರಿಕೆಯಿಂದಿರಿ", "Safe Kannada"),
        ("வங்கி கணக்கு பாதுகாப்பிற்காக எச்சரிக்கையாக இருங்கள்", "Safe Tamil"),
        ("బ్యాంక్ ఖాతా భద్రత కోసం జాగ్రత్తగా ఉండండి", "Safe Telugu"),
    ]

    print("=" * 70)
    print("CyberGuard AI — Subject Analyzer Test")
    print("=" * 70)

    for subject, language in tests:

        result = analyze_subject(subject=subject)

        print("\n" + "-" * 70)
        print(f"Language       : {language}")
        print(f"Subject        : {subject}")
        print(f"Found          : {result.get('found')}")
        print(f"Urgency count  : {result.get('urgency_count')}")
        print(f"Urgency words  : {result.get('urgency_words')}")
        print(f"Reply          : {result.get('is_reply')}")
        print(f"Forward        : {result.get('is_forward')}")
        print(f"Numbers        : {result.get('has_numbers')}")
        print(f"Risk boost     : +{result.get('risk_boost')}")
        print(f"Subject risk   : {result.get('subject_risk')}")

        flags = result.get("flags", [])

        if flags:
            print("Flags:")
            for flag in flags:
                print(f"  - {flag}")
        else:
            print("Flags          : None")

    print("\n" + "=" * 70)
    print("Subject analyzer test completed.")
    print("=" * 70)
