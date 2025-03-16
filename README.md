# Shadowlogs
Advance Keylogger

# Description
This project is an advanced keylogger and data collector system designed for Windows. It captures various system activities, including keystrokes, clipboard content, audio, screenshots, and network activity (DNS queries). It logs this data and uploads it to a remote AWS S3 bucket for storage.

The keylogger continuously runs in the background, collecting information at specified intervals and uploading the logs to a cloud storage solution. The system also features a method for adding the program to Windows startup, ensuring that it runs automatically when the computer starts.

# Features
Keystroke Logging: Logs every keystroke made by the user.
Clipboard Monitoring: Captures clipboard data at regular intervals.
Audio Recording: Records audio from the microphone at specified intervals.
Screenshot Capturing: Takes screenshots at regular intervals.
Network Activity Logging: Captures and logs DNS queries, including visited website URLs and their IP addresses.
System Information Logging: Gathers system information such as the operating system, processor, username, IP address, and location.
File Upload: Uploads the collected data to an AWS S3 bucket.
File Cleanup: After uploading, logs and captured files are deleted to ensure no trace remains.
Startup Integration: Adds the program to the system's startup registry to ensure it runs automatically when the system starts.

# Requirements
Python 3.x (preferably Python 3.7+)
Required Libraries:
pynput
sounddevice
scipy
pillow
requests
boto3
scapy
pywin32
You can install the required libraries using the following:

bash
Copy
Edit
pip install pynput sounddevice scipy pillow requests boto3 scapy pywin32
Configuration
Before running the program, configure the AWS credentials and S3 bucket in the environment variables:

AWS_ACCESS_KEY: Your AWS Access Key.
AWS_SECRET_KEY: Your AWS Secret Key.
AWS_BUCKET_NAME: The S3 bucket name where logs will be uploaded.
AWS_REGION: The AWS region for the S3 bucket.
Ensure these values are set in your environment. For example, you can add them to your .env file or set them directly in your system environment.


svchost.py
The script will start running continuously, logging keystrokes, capturing audio, and uploading data to your S3 bucket at regular intervals.

# Automatic Startup:
The script will automatically add itself to the Windows startup registry to ensure it runs on system startup.

# Security Notice
This tool is intended for educational purposes only. Use it responsibly and with proper authorization. Unauthorized use of keylogging and data collection tools is illegal and unethical. Always get explicit consent from the system owner before using any surveillance software.
