# PhishSweep – Email Phishing Scanner with VirusTotal

This project was built for my cybersecurity bootcamp final project, BootCon.

## What It Does

PhishSweep is a Python script that scans the most recent unread emails from a Gmail inbox and checks any found URLs against the VirusTotal API to detect phishing attempts.

## Files Included

- `phishsweep.py`: Python script that scans and reports phishing links
- `PhishSweep_Slides.pdf`: My final presentation for BootCon
- `vt_phishing_report.txt`: Sample report output from the tool

## How It Works

1. Connects to Gmail using IMAP
2. Extracts links using regex
3. Submits each URL to VirusTotal
4. Flags malicious links and logs results

## Future Expansion

- Scale to scan multiple inboxes
- Feed into SIEM
- Add attachment scanning
