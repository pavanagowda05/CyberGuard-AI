import os, sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import pandas as pd
from storage.db import save_insider_alert, get_db
from config import CERT_PROCESSED_PATH

print("Loading CERT data into MongoDB...")
df = pd.read_csv(CERT_PROCESSED_PATH)

# Only load high-risk rows to keep demo clean
# Flag rows where files > 200 OR login hour < 6 OR usb > 0
flagged = df[
    (df["files_accessed"] > 200) |
    (df["login_hour_avg"] < 6) |
    (df["usb_connects"] > 0)
].copy()

print(f"Found {len(flagged)} flagged employee-days from CERT data")

# Load top 50 most suspicious
flagged["risk_proxy"] = flagged["files_accessed"] + flagged["usb_connects"]*100
top50 = flagged.nlargest(50, "risk_proxy")

db = get_db()
db["insider_alerts"].delete_many({"source": "cert"})  # clear old test data

for _, row in top50.iterrows():
    save_insider_alert({
        "user":        row["user"],
        "day":         str(row["day"]),
        "risk_score":  min(int(row["files_accessed"] / 10 + row["usb_connects"] * 20), 100),
        "severity":    "Critical" if row["files_accessed"] > 500 else "High",
        "is_anomaly":  True,
        "reason":      f"Files: {int(row['files_accessed'])} | Login: {row['login_hour_avg']:.0f}:00 | USB: {int(row['usb_connects'])}",
        "anomaly_score": -0.15,
        "features":    row[["login_hour_avg","files_accessed","emails_sent","usb_connects"]].to_dict(),
        "source":      "cert",
    })

print(f"Loaded {len(top50)} real CERT employee alerts into MongoDB")
print("Refresh your dashboard to see real employee data.")