#!/bin/bash

# ==========================================
# PhishTriage: Automated Email Header & URL Analyzer
# Author: Nooh Abdul Ghaffar
# ==========================================

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

if [ -f .env ]; then
    source .env
else
    echo "[!] Warning: .env file not found. VirusTotal checks will be skipped."
fi

if [ -z "$1" ]; then
    echo "Usage: $0 <path_to_email.eml>"
    exit 1
fi

EMAIL_FILE=$1
if [ ! -f "$EMAIL_FILE" ]; then
    echo "[!] Error: File '$EMAIL_FILE' not found."
    exit 1
fi

echo "=================================================="
echo " PHISHING TRIAGE REPORT: $(basename "$EMAIL_FILE")"
echo "=================================================="
echo ""

# 1. Extract Headers
echo "[+] BASIC HEADERS"
grep -i "^From:" "$EMAIL_FILE" | head -n 1
grep -i "^Subject:" "$EMAIL_FILE" | head -n 1
grep -i "^Reply-To:" "$EMAIL_FILE" | head -n 1
grep -i "^Return-Path:" "$EMAIL_FILE" | head -n 1
echo ""

# 2. Authentication Results (SPF/DKIM/DMARC)
echo "[+] EMAIL AUTHENTICATION (SPF/DKIM/DMARC)"
AUTH_RES=$(grep -i "^Authentication-Results:" "$EMAIL_FILE" | head -n 1)
if [ -n "$AUTH_RES" ]; then
    echo "$AUTH_RES"
else
    echo "No Authentication-Results header found (Suspicious)."
fi
echo ""

# 3. IP Reputation
echo "[+] NETWORK ANALYSIS (Originating IP)"
ORIG_IP=$(grep -i "^Received:" "$EMAIL_FILE" | tail -n 1 | grep -oE '\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\]' | tr -d '[]')

if [ -n "$ORIG_IP" ]; then
    echo "Originating IP: $ORIG_IP"
    if [ -n "$VT_API_KEY" ]; then
        echo -n "  -> VirusTotal Check: "
        VT_RES=$(curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/$ORIG_IP")
        MALICIOUS=$(echo "$VT_RES" | jq -r '.data.attributes.last_analysis_stats.malicious' 2>/dev/null)
        
        if [ "$MALICIOUS" == "null" ] || [ -z "$MALICIOUS" ]; then
            echo -e "${YELLOW}No data in VT (Clean or Unknown)${NC}"
        elif [ "$MALICIOUS" -gt 0 ]; then
            echo -e "${RED}MALICIOUS ($MALICIOUS vendors flagged this IP!)${NC}"
        else
            echo -e "${GREEN}CLEAN (0 vendors flagged)${NC}"
        fi
    fi
else
    echo "Could not extract originating IP."
fi
echo ""

# 4. URL Analysis & Defanging
echo "[+] URL ANALYSIS"
URLS=$(grep -oE 'https?://[^"[:space:]]+' "$EMAIL_FILE" | sort -u)

if [ -z "$URLS" ]; then
    echo "No URLs found in the email."
else
    for URL in $URLS; do
        URL=$(echo "$URL" | sed 's/[<>"]//g')
        # Defang the URL for safe reading
        DEFANGED=$(echo "$URL" | sed 's/http/hxxp/g' | sed 's/\./[.]/g')
        echo "URL: $DEFANGED"
        
        if [ -n "$VT_API_KEY" ]; then
            echo -n "  -> VirusTotal Check: "
            URL_ID=$(echo -n "$URL" | base64 | tr '+/' '-_' | tr -d '=')
            VT_RES=$(curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/urls/$URL_ID")
            MALICIOUS=$(echo "$VT_RES" | jq -r '.data.attributes.last_analysis_stats.malicious' 2>/dev/null)
            
            if [ "$MALICIOUS" == "null" ] || [ -z "$MALICIOUS" ]; then
                echo -e "${YELLOW}Not found in VT database${NC}"
            elif [ "$MALICIOUS" -gt 0 ]; then
                echo -e "${RED}MALICIOUS ($MALICIOUS vendors flagged!)${NC}"
            else
                echo -e "${GREEN}CLEAN (0 vendors flagged)${NC}"
            fi
        fi
    done
fi
echo ""
echo "=================================================="
