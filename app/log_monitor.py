import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import Flask, render_template
from collections import defaultdict

# Flask app setup
app = Flask(__name__)

# Email configuration
EMAIL_SENDER = "eath2eath1@gmail.com"
EMAIL_PASSWORD = "Abdifatah&q1"  # Use an app-specific password if using Gmail
EMAIL_RECEIVER = "abdifatahosman205@gmail.com"

# Log file to monitor
LOG_FILE = "/var/log/auth.log"
SUSPICIOUS_KEYWORDS = ["Failed password", "Invalid user"]
TRUSTED_IPS = ["192.168.0.20.", "127.0.0.1"]  # Add your trusted IPs here
FAILED_ATTEMPTS_THRESHOLD = 5  # Number of failed attempts to trigger alert

# Track failed login attempts
failed_attempts = defaultdict(int)

# Function to send email alerts
def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_SENDER
        msg['To'] = EMAIL_RECEIVER
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())
        print("Email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")

# Watchdog event handler for log monitoring
class LogFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        if event.src_path.endswith(LOG_FILE):
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()
                for line in lines[-10:]:  # Check the last 10 lines
                    self.detect_anomalies(line)

    def detect_anomalies(self, line):
        # Check for suspicious keywords
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in line:
                subject = "Suspicious Activity Detected"
                body = f"Suspicious activity found in {LOG_FILE}:\n\n{line}"
                send_email(subject, body)

        # Check for repeated failed login attempts
        if "Failed password" in line:
            ip = self.extract_ip(line)
            if ip:
                failed_attempts[ip] += 1
                if failed_attempts[ip] >= FAILED_ATTEMPTS_THRESHOLD:
                    subject = "Repeated Failed Login Attempts Detected"
                    body = f"IP {ip} has exceeded the failed login threshold.\n\n{line}"
                    send_email(subject, body)

        # Check for access from unknown IPs
        ip = self.extract_ip(line)
        if ip and ip not in TRUSTED_IPS:
            subject = "Access from Unknown IP Detected"
            body = f"Access detected from unknown IP {ip}.\n\n{line}"
            send_email(subject, body)

    def extract_ip(self, line):
        # Extract IP address from the log line
        parts = line.split()
        for part in parts:
            if part.count('.') == 3:  # Simple check for IP format
                return part
        return None

# Flask route to display monitored logs
@app.route('/')
def index():
    try:
        with open(LOG_FILE, 'r') as f:
            logs = f.readlines()[-50:]  # Display the last 50 lines
    except Exception as e:
        logs = [f"Error reading log file: {e}"]
    return render_template('index.html', logs=logs)

# Main function to start monitoring and Flask app
if __name__ == "__main__":
    # Start log monitoring
    event_handler = LogFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path="/var/log/", recursive=False)
    observer.start()

    # Start Flask app
    try:
        app.run(host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
