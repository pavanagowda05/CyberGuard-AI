from ai.threat_classifier import classify_threat

# This text should NOT match "Government Impersonation" via loose substring
# matching (e.g. "fine" inside "define", "visa" inside "revisable", etc.)
# but genuinely unrelated text with no real government keywords in it.
test_text = (
    "Thank you for your interest in the Research Assistant position "
    "within the Psychology Department of UC Berkeley University. "
    "This message is to confirm that your inquiry was received."
)

result = classify_threat(email_text=test_text, subject="Inquiry Received!")
print(result)
