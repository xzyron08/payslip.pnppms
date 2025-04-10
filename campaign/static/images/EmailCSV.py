import smtplib
import pandas as pd
import re
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# Email Configuration
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "nulldecipher001@gmail.com"
EMAIL_PASSWORD = "phgs cpde fudn rbxc"

# Load email list from CSV (Force the first row to be treated as data)
csv_file = "EmailCSV.csv"

# Read CSV without headers and set the column name manually
df = pd.read_csv(csv_file, header=None, names=["email"])

# Debugging: Print first few rows to confirm correct reading
print("CSV Data Preview:\n", df.head())

# Remove empty values, strip spaces, and filter valid emails
df['email'] = df['email'].astype(str).str.strip()
df = df.dropna(subset=['email'])

# Email validation regex (RFC 5322 compliant)
EMAIL_REGEX = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
df = df[df['email'].str.match(EMAIL_REGEX, na=False)]  # Keep only valid emails

# Function to send emails
def send_email(to_email, subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())

        print(f"✅ Email sent to {to_email}")
    except Exception as e:
        print(f"❌ Failed to send email to {to_email}: {e}")

# Email content
subject = "Change Password Notice"
body = "Please Change your password: \n https://bit.ly/PNP-PAYSLIP-CHANGE-PASSWORD"

# Send emails to all valid recipients
for email in df['email']:
    send_email(email, subject, body)

print("✅ All emails have been sent successfully!")
