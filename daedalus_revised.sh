#!/bin/bash

# Daedalus Recon Script - With Tool Check, Auto-Install, No-API Option, and Summary
# Requirements: amass, subfinder, httpx, nuclei, assetfinder, dnsx, naabu, gau, ffuf, jq

TARGET=$1
NO_API=false

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain> [--no-api]"
    exit 1
fi

if [ "$2" == "--no-api" ]; then
    NO_API=true
fi

# Tool installation check
TOOLS=(subfinder assetfinder amass dnsx httpx naabu gau ffuf nuclei jq)
for tool in "${TOOLS[@]}"; do
    if ! command -v $tool &> /dev/null; then
        echo "[*] $tool not found. Attempting to install via 'go install'..."
        case $tool in
            subfinder)
                go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest ;;
            assetfinder)
                go install github.com/tomnomnom/assetfinder@latest ;;
            amass)
                go install github.com/owasp-amass/amass/v3/...@latest ;;
            dnsx)
                go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest ;;
            httpx)
                go install github.com/projectdiscovery/httpx/cmd/httpx@latest ;;
            naabu)
                go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest ;;
            gau)
                go install github.com/lc/gau/v2/cmd/gau@latest ;;
            ffuf)
                go install github.com/ffuf/ffuf@latest ;;
            nuclei)
                go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest ;;
            jq)
                sudo apt install -y jq ;;
        esac
        export PATH=$PATH:$(go env GOPATH)/bin
    fi
done

WORKDIR="recon-$TARGET"
mkdir -p "$WORKDIR"
cd "$WORKDIR" || exit

echo "[+] Starting recon for $TARGET"
echo "[+] Using NO_API mode: $NO_API"

# Subdomain Enumeration
echo "[+] Running subfinder..."
if [ "$NO_API" = true ]; then
    subfinder -d "$TARGET" -sources anubis,crtsh,alienvault,threatminer,waybackarchive -silent > subfinder.txt
else
    subfinder -d "$TARGET" -silent > subfinder.txt
fi

echo "[+] Running assetfinder..."
assetfinder --subs-only "$TARGET" | tee assetfinder.txt

echo "[+] Running crt.sh scrape..."
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh.txt

echo "[+] Running amass (passive)..."
amass enum -passive -d "$TARGET" | tee amass.txt

# Merge all sources
cat subfinder.txt assetfinder.txt crtsh.txt amass.txt 2>/dev/null | sort -u > all_subs.txt
if [ ! -s all_subs.txt ]; then
    echo "[!] No subdomains found. Exiting."
    exit 1
fi

# DNS Resolution
echo "[+] Resolving live domains..."
dnsx -l all_subs.txt -silent -resp-only | tee resolved.txt

# HTTP Probing
echo "[+] Probing for live HTTP services..."
cat resolved.txt | httpx -silent -title -tech-detect -status-code | tee httpx.txt

# Port Scanning
echo "[+] Running naabu..."
naabu -i resolved.txt -top-ports 100 -silent | tee ports.txt

# JS File Scraping
echo "[+] Scraping JavaScript files with gau..."
cat resolved.txt | gau --threads 5 --blacklist png,jpg,jpeg,gif,svg,woff,ttf,css | grep ".js" | sort -u | tee js_files.txt

# URL Fuzzing
echo "[+] Running ffuf..."
mkdir -p ffuf_results
for url in $(cat resolved.txt); do
    ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirb/common.txt -of md -o ffuf_results/$(echo "$url" | sed 's/https\?:\/\///g').md -t 25
done

# Vulnerability Scanning
echo "[+] Running nuclei..."
nuclei -l resolved.txt -t cves/ -severity medium,high,critical -silent | tee nuclei-results.txt

# Summary
echo "-----------------------------------"
echo "[✓] Recon complete for $TARGET"
echo "Files generated:"
echo "- all_subs.txt ($(wc -l < all_subs.txt) lines)"
echo "- resolved.txt ($(wc -l < resolved.txt) lines)"
echo "- httpx.txt ($(wc -l < httpx.txt) lines)"
echo "- ports.txt ($(wc -l < ports.txt) lines)"
echo "- js_files.txt ($(wc -l < js_files.txt) lines)"
echo "- nuclei-results.txt ($(wc -l < nuclei-results.txt) lines)"
echo "Check ffuf_results/ for directory fuzzing output."
echo "-----------------------------------"
