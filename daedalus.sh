#!/bin/bash

# Recon Script with JS File Scraping and URL Fuzzing
# Requirements: amass, subfinder, httpx, nuclei, assetfinder, dnsx, naabu, gau, katana, ffuf

TARGET=$1

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <domain>"
    exit 1
fi

WORKDIR=recon-$TARGET
mkdir -p $WORKDIR
cd $WORKDIR

echo "[+] Starting recon for $TARGET"

# Subdomain Enumeration
echo "[+] Running subfinder..."
subfinder -d $TARGET -silent > subfinder.txt

echo "[+] Running assetfinder..."
assetfinder --subs-only $TARGET | tee assetfinder.txt

echo "[+] Running amass (passive)..."
amass enum -passive -d $TARGET | tee amass.txt

cat subfinder.txt assetfinder.txt amass.txt | sort -u > all_subs.txt

# DNS Resolution
echo "[+] Resolving live domains..."
dnsx -l all_subs.txt -silent -resp-only | tee resolved.txt

# HTTP Probing
echo "[+] Probing for live HTTP services..."
httpx -l resolved.txt -silent -title -tech-detect -status-code | tee httpx.txt

# Port Scanning
echo "[+] Running naabu..."
naabu -l resolved.txt -top-ports 100 -silent | tee ports.txt

# JS File Scraping
echo "[+] Scraping JavaScript files with gau..."
cat resolved.txt | gau --threads 5 --blacklist png,jpg,jpeg,gif,svg,woff,ttf,css | grep ".js" | sort -u | tee js_files.txt

# URL Fuzzing with FFUF (basic wordlist)
echo "[+] Running ffuf on discovered endpoints..."
mkdir -p ffuf_results
for url in $(cat resolved.txt); do
    ffuf -u $url/FUZZ -w /usr/share/wordlists/dirb/common.txt -of md -o ffuf_results/$(echo $url | sed 's/https\?:\/\///g').md -t 25
done

# Vulnerability Scanning
echo "[+] Running nuclei..."
nuclei -l resolved.txt -t cves/ -severity medium,high,critical -silent | tee nuclei-results.txt

echo "[+] Recon complete. Results saved in $WORKDIR"
