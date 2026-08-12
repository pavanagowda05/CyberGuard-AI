# ============================================================
# CyberGuard AI — ai/ocr_extractor.py
#
# Extracts text from images using Tesseract OCR.
#
# OCR is intentionally ENGLISH-ONLY.
#
# Multilingual processing is handled later by the CyberGuard
# AI text-analysis pipeline (MuRIL, threat classifier, etc.).
# ============================================================

import pytesseract
from PIL import Image
import io


# ============================================================
# TESSERACT CONFIGURATION
# ============================================================

pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)


# ============================================================
# OCR LANGUAGE
# ============================================================

OCR_LANGUAGE = "eng"


# ============================================================
# OCR CONFIGURATION
# ============================================================

# PSM 6 works well for email screenshots and blocks of text.
TESSERACT_CONFIG = "--psm 6"


# ============================================================
# CONFIDENCE CALCULATION
# ============================================================

def calculate_average_confidence(data: dict) -> float:
    """
    Calculate the average Tesseract OCR confidence.
    """

    confidences = []

    for value in data.get("conf", []):
        try:
            confidence = float(value)

            # -1 means Tesseract did not assign confidence.
            if confidence >= 0:
                confidences.append(confidence)

        except (ValueError, TypeError):
            continue

    if not confidences:
        return 0.0

    return round(
        sum(confidences) / len(confidences),
        1
    )


# ============================================================
# OCR EXTRACTION
# ============================================================

def extract_text_from_image(
    image_bytes: bytes,
    lang: str = "en"
) -> dict:
    """
    Extract text from an image using English Tesseract OCR.

    IMPORTANT:
        The `lang` argument is retained for API compatibility,
        but OCR itself always uses English.

    Multilingual classification is performed later by
    the CyberGuard AI text-analysis pipeline.

    Args:
        image_bytes:
            Raw image bytes.

        lang:
            Original/requested language. This is stored for
            pipeline compatibility but does not change OCR.

    Returns:
        {
            "text": extracted text,
            "confidence": average OCR confidence,
            "language": requested language,
            "ocr_language": "eng",
            "char_count": number of extracted characters,
            "success": bool
        }
    """

    try:

        # ====================================================
        # OPEN IMAGE
        # ====================================================

        image = Image.open(
            io.BytesIO(image_bytes)
        )

        # ====================================================
        # NORMALIZE IMAGE MODE
        # ====================================================

        if image.mode not in ("RGB", "L"):
            image = image.convert("RGB")

        # ====================================================
        # ENGLISH-ONLY OCR
        # ====================================================

        text = pytesseract.image_to_string(
            image,
            lang=OCR_LANGUAGE,
            config=TESSERACT_CONFIG
        )

        data = pytesseract.image_to_data(
            image,
            lang=OCR_LANGUAGE,
            config=TESSERACT_CONFIG,
            output_type=pytesseract.Output.DICT
        )

        # ====================================================
        # CLEAN TEXT
        # ====================================================

        text = text.strip()

        # Remove unnecessary blank lines.
        lines = []

        for line in text.splitlines():

            line = line.strip()

            if line:
                lines.append(line)

        text = "\n".join(lines)

        # ====================================================
        # OCR CONFIDENCE
        # ====================================================

        avg_conf = calculate_average_confidence(
            data
        )

        # ====================================================
        # SUCCESS
        # ====================================================

        success = len(text) > 0

        # ====================================================
        # DEBUG OUTPUT
        # ====================================================

        print(
            f"[OCR] Requested language : {lang}"
        )

        print(
            f"[OCR] OCR language       : {OCR_LANGUAGE}"
        )

        print(
            f"[OCR] Characters         : {len(text)}"
        )

        print(
            f"[OCR] Confidence         : {avg_conf}%"
        )

        print(
            f"[OCR] Success            : {success}"
        )

        # ====================================================
        # RETURN
        # ====================================================

        return {
            "text": text,
            "confidence": avg_conf,
            "language": lang,
            "ocr_language": OCR_LANGUAGE,
            "char_count": len(text),
            "success": success,
        }

    except Exception as e:

        print(
            f"[OCR] Error: {e}"
        )

        return {
            "text": "",
            "confidence": 0.0,
            "language": lang,
            "ocr_language": OCR_LANGUAGE,
            "char_count": 0,
            "success": False,
            "error": str(e),
        }


# ============================================================
# QUICK TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)
    print("CyberGuard AI — OCR Extractor Test")
    print("=" * 60)

    print("\nTesseract version:")

    try:
        print(
            pytesseract.get_tesseract_version()
        )
    except Exception as e:
        print(
            f"Could not determine Tesseract version: {e}"
        )

    print("\nOCR language:")
    print("  English (eng)")

    print("\nMultilingual text analysis:")
    print("  English")
    print("  Hindi")
    print("  Kannada")
    print("  Tamil")
    print("  Telugu")

    print("\nOCR extractor ready.")