from imap_tools import MailBox, AND
import re
import requests
import time

# Defender inbox (the one we are scanning)
EMAIL = "scanmedefenseproject@gmail.com"
PASSWORD = "eynpigxfcyhfiqux "
IMAP_SERVER = "imap.gmail.com"

# VirusTotal API
VT_API_KEY = "15a14815796df8ef2d779c711b20ff4a1e8f08911392c992373803ff5bb1693d"

def extract_links(text):
    return re.findall(r'https?://\S+', text)

def check_url_virustotal(url):
    headers = {"x-apikey": VT_API_KEY}  # Send your API key in the headers

    # Step 1: Submit the URL for analysis
    response = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        return False  # If submission failed, treat it as safe for now

    # Step 2: Get the analysis ID from the response
    analysis_id = response.json()["data"]["id"]

    # Step 3: Wait a few seconds to avoid hitting rate limits (and to let VT process the scan)
    time.sleep(15)

    # Step 4: Retrieve the scan results using the analysis ID
    report = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers
    )

    if report.status_code != 200:
        return False

    # Step 5: Extract how many scanners marked it as malicious or suspicious
    stats = report.json()["data"]["attributes"]["stats"]

    # Step 6: Return True if any engines found it suspicious or malicious
    return stats["malicious"] > 0 or stats["suspicious"] > 0

def main():
    print("Connecting to inbox...")

    # Connect to the Gmail inbox using IMAP
    with MailBox(IMAP_SERVER).login(EMAIL, PASSWORD) as mailbox:
        # Fetch the 4 most recent unread emails (VirusTotal free limit is 4 requests/min)
        emails = mailbox.fetch(AND(seen=False), limit=4, headers_only=False)
        
        flagged = []  # This list will hold any phishing results we find

        # Go through each email one by one
        for msg in emails:
            print(f"Scanning email from: {msg.from_}")
            
            # Extract links from the email's body
            links = extract_links(msg.text or "")

            # Scan each link using VirusTotal
            for link in links:
                print(f"  Checking: {link}")
                try:
                    if check_url_virustotal(link):
                        # Save details about flagged emails
                        flagged.append({
                            "from": msg.from_,
                            "subject": msg.subject,
                            "link": link
                        })
                except Exception as e:
                    print(f"    [Error checking link]: {e}")

        # Write results to a report file
        with open("vt_phishing_report.txt", "w", encoding="utf-8") as f:
            for item in flagged:
                f.write(f"FROM: {item['from']}\n")
                f.write(f"SUBJECT: {item['subject']}\n")
                f.write(f"FLAGGED LINK: {item['link']}\n\n")

    print(f"\nScan complete. {len(flagged)} emails flagged.")
    print("Results saved to vt_phishing_report.txt")

if __name__ == "__main__":
    main()
