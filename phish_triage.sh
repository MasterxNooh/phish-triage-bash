#!/bin/bash

# ==========================================
# PhishTriage v4.0: Enterprise SOC Interface
# Author: Nooh Abdul Ghaffar
# ==========================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

SCORE=0
FINDINGS=()

if [ -f .env ]; then
    source .env
else
    echo -e "${RED}[!] Warning: .env file not found. VT checks skipped.${NC}"
fi

if [ -z "$1" ] || [ ! -f "$1" ]; then
    echo "Usage: $0 <path_to_email.eml>"
    exit 1
fi

EMAIL_FILE=$1
REPORT_DIR="./reports"
mkdir -p "$REPORT_DIR"
REPORT_FILE="$REPORT_DIR/triage-$(date +%Y%m%d-%H%M%S).log"

clear

# Solid Block ASCII Art (Thick & Accurate)
echo -e "${MAGENTA}${BOLD}"
echo "██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ████████╗██████╗ ██╗ █████╗  ██████╗ ███████╗"
echo "██╔══██╗██║  ██║██║██╔════╝██║  ██║    ╚══██╔══╝██╔══██╗██║██╔══██╗██╔════╝ ██╔════╝"
echo "██████╔╝███████║██║███████╗███████║       ██║   ██████╔╝██║███████║██║  ███╗█████╗  "
echo "██╔═══╝ ██╔══██║██║╚════██║██╔══██║       ██║   ██╔══██╗██║██╔══██║██║   ██║██╔══╝  "
echo "██║     ██║  ██║██║███████║██║  ██║       ██║   ██║  ██║██║██║  ██║╚██████╔╝███████╗"
echo "╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝       ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝"
echo -e "${NC}"

echo -e "${CYAN}${BOLD}================================================================================${NC}"
echo -e "${CYAN}${BOLD}                  PHISHING .EML TRIAGE ANALYZER v4.0${NC}"
echo -e "${CYAN}${BOLD}                     Author: Nooh Abdul Ghaffar${NC}"
echo -e "${CYAN}${BOLD}================================================================================${NC}\n"

log_finding() {
    FINDINGS+=("$1")
}

# 1. Header & Spoofing
echo -e "${BLUE}${BOLD}[*] Analyzing Headers & Spoofing...${NC}"
FROM=$(grep -i "^From:" "$EMAIL_FILE" | head -n 1 | cut -d: -f2- | sed 's/^ //')
RETURN_PATH=$(grep -i "^Return-Path:" "$EMAIL_FILE" | head -n 1 | cut -d: -f2- | sed 's/^ //')
SUBJECT=$(grep -i "^Subject:" "$EMAIL_FILE" | head -n 1 | cut -d: -f2- | sed 's/^ //')

echo -e "  ${CYAN}Subject:${NC}     $SUBJECT"
echo -e "  ${CYAN}From:${NC}        $FROM"
echo -e "  ${CYAN}Return-Path:${NC} $RETURN_PATH"

FROM_DOMAIN=$(echo "$FROM" | grep -oP '(?<=@)[^>]+')
RETURN_DOMAIN=$(echo "$RETURN_PATH" | grep -oP '(?<=@)[^>]+')

if [ -n "$FROM_DOMAIN" ] && [ -n "$RETURN_DOMAIN" ] && [ "$FROM_DOMAIN" != "$RETURN_DOMAIN" ]; then
    log_finding "Spoofing: From domain ($FROM_DOMAIN) does not match Return-Path ($RETURN_DOMAIN)"
    SCORE=$((SCORE + 2))
fi
echo ""

# 2. Authentication
echo -e "${BLUE}${BOLD}[*] Verifying SPF/DKIM/DMARC...${NC}"
AUTH_RES=$(grep -i "^Authentication-Results:" "$EMAIL_FILE" | head -n 1)
if [ -n "$AUTH_RES" ]; then
    echo -e "  ${CYAN}Result:${NC} $AUTH_RES"
    if echo "$AUTH_RES" | grep -qi "spf=fail\|dkim=fail\|dmarc=fail"; then
        log_finding "Authentication failed (SPF/DKIM/DMARC fail detected)"
        SCORE=$((SCORE + 3))
    fi
else
    log_finding "Missing Authentication-Results header"
    SCORE=$((SCORE + 1))
fi
echo ""

# 3. Network Analysis
echo -e "${BLUE}${BOLD}[*] Extracting Originating IP...${NC}"
ORIG_IP=$(grep -i "^Received:" "$EMAIL_FILE" | tail -n 1 | grep -oE '\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\]' | tr -d '[]')

if [ -n "$ORIG_IP" ]; then
    echo -e "  ${CYAN}Originating IP:${NC} $ORIG_IP"
    if [ -n "$VT_API_KEY" ]; then
        VT_RES=$(curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/ip_addresses/$ORIG_IP")
        MALICIOUS=$(echo "$VT_RES" | jq -r '.data.attributes.last_analysis_stats.malicious' 2>/dev/null)
        if [[ "$MALICIOUS" =~ ^[0-9]+$ ]] && [ "$MALICIOUS" -gt 0 ]; then
            log_finding "VT flagged IP $ORIG_IP ($MALICIOUS engines)"
            SCORE=$((SCORE + 3))
        fi
    fi
fi
echo ""

# 4. URL Analysis
echo -e "${BLUE}${BOLD}[*] Extracting & Checking URLs...${NC}"
URLS=$(grep -oE 'https?://[^"[:space:]]+' "$EMAIL_FILE" | sort -u)

if [ -z "$URLS" ]; then
    echo -e "  ${CYAN}No URLs found.${NC}"
else
    for URL in $URLS; do
        URL=$(echo "$URL" | sed 's/[<>"]//g')
        DEFANGED=$(echo "$URL" | sed 's/http/hxxp/g' | sed 's/\./[.]/g')
        echo -e "  ${CYAN}Found URL:${NC} $DEFANGED"
        
        if [ -n "$VT_API_KEY" ]; then
            URL_ID=$(echo -n "$URL" | base64 | tr '+/' '-_' | tr -d '=')
            VT_RES=$(curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/urls/$URL_ID")
            MALICIOUS=$(echo "$VT_RES" | jq -r '.data.attributes.last_analysis_stats.malicious' 2>/dev/null)
            if [[ "$MALICIOUS" =~ ^[0-9]+$ ]] && [ "$MALICIOUS" -gt 0 ]; then
                log_finding "VT flagged URL $DEFANGED ($MALICIOUS engines)"
                SCORE=$((SCORE + 3))
            fi
        fi
    done
fi
echo ""

# 5. Attachments
echo -e "${BLUE}${BOLD}[*] Checking Attachments...${NC}"
ATTACHMENTS=$(awk '/Content-Disposition: attachment/{flag=1;next}/^--/{if(flag)flag=0}flag' "$EMAIL_FILE" | base64 -d 2>/dev/null)
if [ -n "$ATTACHMENTS" ]; then
    HASH=$(echo "$ATTACHMENTS" | sha256sum | awk '{print $1}')
    echo -e "  ${CYAN}Found Attachment SHA256:${NC} $HASH"
    if [ -n "$VT_API_KEY" ]; then
        VT_RES=$(curl -s -H "x-apikey: $VT_API_KEY" "https://www.virustotal.com/api/v3/files/$HASH")
        MALICIOUS=$(echo "$VT_RES" | jq -r '.data.attributes.last_analysis_stats.malicious' 2>/dev/null)
        if [[ "$MALICIOUS" =~ ^[0-9]+$ ]] && [ "$MALICIOUS" -gt 0 ]; then
            log_finding "VT flagged Attachment ($MALICIOUS engines)"
            SCORE=$((SCORE + 4))
        fi
    fi
else
    echo -e "  ${CYAN}No attachments found.${NC}"
fi
echo ""

# 6. Final Verdict
if [ "$SCORE" -ge 4 ]; then
    VERDICT="${RED}${BOLD}MALICIOUS${NC}"
elif [ "$SCORE" -ge 1 ]; then
    VERDICT="${YELLOW}${BOLD}SUSPICIOUS${NC}"
else
    VERDICT="${GREEN}${BOLD}LIKELY CLEAN${NC}"
fi

echo -e "${CYAN}${BOLD}================================================================================${NC}"
echo -e "  ${MAGENTA}${BOLD}VERDICT:${NC} $VERDICT (Threat Score: $SCORE)"
echo -e "${CYAN}${BOLD}================================================================================${NC}"

if [ ${#FINDINGS[@]} -gt 0 ]; then
    echo -e "${MAGENTA}${BOLD}FINDINGS:${NC}"
    for i in "${!FINDINGS[@]}"; do
        echo -e "  ${RED}[!]${NC} ${FINDINGS[$i]}"
    done
else
    echo -e "  ${GREEN}[OK] No malicious indicators found.${NC}"
fi
echo -e "${CYAN}${BOLD}================================================================================${NC}"

# Save to file
{
    echo "PHISH TRIAGE REPORT: $EMAIL_FILE"
    echo "Score: $SCORE"
    echo "Verdict: $VERDICT"
    echo "Findings:"
    for F in "${FINDINGS[@]}"; do echo " - $F"; done
} > "$REPORT_FILE"

echo -e "\n${GREEN}[*] Artifacts saved to: $REPORT_FILE${NC}\n"
