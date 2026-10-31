# PhishTriage

A lightning-fast, dependency-free Bash script for SOC analysts to triage reported phishing emails. 

## Why Bash?
Python is great, but when a SOC analyst is staring at a terminal with 50 reported emails to triage, native Linux tools (`grep`, `awk`, `sed`, `curl`) are instant and require zero setup. 

PhishTriage parses raw `.eml` files, extracts key headers, identifies the true originating IP address, extracts all embedded URLs, and automatically checks them against the VirusTotal API.

## Features
- **Defanged Output:** Automatically defangs URLs (e.g., `hxxp://evil[.]com`) so analysts can safely share reports.
- **Color-Coded VT Results:** Instantly see RED (malicious), GREEN (clean), or YELLOW (unknown) threat intel results.
- **Auth Header Parsing:** Extracts SPF, DKIM, and DMARC Authentication-Results to spot sender spoofing.
- **Header Extraction:** Quickly view `From`, `Subject`, `Return-Path`, and `Reply-To`.
- **Network Analysis:** Parses `Received` headers to find the originating IP.
- **Zero Dependencies:** Runs natively on any Linux distribution (requires `jq`, `curl`, `grep`).

## Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/MasterxNooh/phish-triage-bash.git
   cd phish-triage-bash
