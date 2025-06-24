#!/bin/bash

set -euo pipefail
trap 'echo -e "\n\e[91m[!] Script interrupted. Cleaning up...\e[0m"; exit 1' SIGINT SIGTERM

# Daedalus Revised - Full Recon Automation
# Dependencies: subfinder, assetfinder, amass, dnsx, httpx, naabu, gau, ffuf, nuclei, jq, zip, shodan, cron

TARGET=${1:-}
NO_API=true  # default is now --no-api unless explicitly overridden
STEALTH=false
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

if [[ -z "$TARGET" ]]; then
    echo -e "\e[91m[!] Usage: $0 <domain> [--api] [--stealth]\e[0m"
    exit 1
fi

# Basic domain validation
if ! [[ "$TARGET" =~ ^([a-zA-Z0-9][-a-zA-Z0-9]*\.)+[a-zA-Z]{2,}$ ]]; then
    echo -e "\e[91m[!] Invalid domain: $TARGET\e[0m"
    exit 1
fi

WORKDIR="recon-$TARGET-$TIMESTAMP"
LOGFILE="$WORKDIR/daedalus.log"
mkdir -p "$WORKDIR/osint"
cd "$WORKDIR" || exit 1
export PS4='+ $(date "+%Y-%m-%d %H:%M:%S") '
set -x  # Enable debug trace mode for full command logging


print_banner() {
    echo -e "\e[96m[+] $1\e[0m"
}

check_dependency() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo -e "\e[93m[*] Installing missing dependency: $1\e[0m"
        if command -v go >/dev/null 2>&1; then
            go install github.com/projectdiscovery/$1/cmd/$1@latest || true
        fi
        sudo apt-get install -y "$1" || echo "\e[91m[!] Manual install required: $1\e[0m"
    fi
}

print_banner "Checking dependencies..."
for dep in subfinder assetfinder amass dnsx httpx naabu gau ffuf nuclei jq zip shodan; do
    check_dependency "$dep"
done

# Parse args
for arg in "$@"
do
    case $arg in
        --api)
        NO_API=false
        shift
        ;;
        --stealth)
        STEALTH=true
        shift
        ;;
    esac
done

if [[ "$NO_API" == false ]]; then
  if [[ -z "${ABUSE_API_KEY:-}" || "$ABUSE_API_KEY" == "YOUR_ABUSEIPDB_API_KEY" ]]; then
    echo "❌ API mode requires a valid AbuseIPDB API key. Set it in the script or via an environment variable."
    exit 1
  fi
fi

exec > >(tee -a "$LOGFILE") 2>&1


print_banner "Starting Recon on: $TARGET"
print_banner "NO_API Mode: $NO_API | Stealth Mode: $STEALTH"

print_banner "Running subdomain enumeration..."
if [ "$NO_API" = true ]; then
    subfinder -d "$TARGET" -sources anubis,crtsh,alienvault,threatminer -silent > subfinder.txt
else
    subfinder -d "$TARGET" -silent > subfinder.txt
fi

assetfinder --subs-only "$TARGET" > assetfinder.txt
print_banner "Fetching crt.sh data..."
crtsh_raw=$(curl -s "https://crt.sh/?q=%25.$TARGET&output=json" || true)

if [[ -z "$crtsh_raw" ]]; then
    echo -e "\e[93m[!] Warning: crt.sh returned empty response. Skipping.\e[0m"
    touch crtsh.txt
elif echo "$crtsh_raw" | jq empty >/dev/null 2>&1; then
    echo "$crtsh_raw" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh.txt
else
    echo -e "\e[93m[!] Warning: crt.sh returned invalid JSON. Skipping.\e[0m"
    touch crtsh.txt
fi


print_banner "Running amass (max 2 min)..."
if [[ -f ../good_resolvers.txt ]]; then
    if ! timeout 120s amass enum -passive -d "$TARGET" -rf ../good_resolvers.txt > amass.txt 2>/dev/null; then
        echo -e "\e[93m[!] Amass failed or timed out. Continuing without it.\e[0m"
        touch amass.txt
    fi
else
    if ! timeout 120s amass enum -passive -d "$TARGET" > amass.txt 2>/dev/null; then
        echo -e "\e[93m[!] Amass failed or timed out. Continuing without it.\e[0m"
        touch amass.txt
    fi
fi


cat subfinder.txt assetfinder.txt crtsh.txt amass.txt | sort -u > all_subs.txt

if [ ! -s all_subs.txt ]; then
    echo -e "\e[91m[!] No subdomains found, exiting.\e[0m"
    echo -e "\e[93m[!] No subdomains found, continuing anyway for debug...\e[0m"
sleep 2

fi

echo "--- all_subs.txt ---"
cat all_subs.txt


print_banner "Running DNS resolution..."
dnsx -l all_subs.txt -silent > resolved.txt

echo "--- resolved.txt ---"
cat resolved.txt

RESOLVED_COUNT=$(wc -l < resolved.txt)
echo -e "\e[96m[+] Resolved $RESOLVED_COUNT subdomains\e[0m"

if [ ! -s resolved.txt ]; then
    echo -e "\e[93m[!] No resolved domains. Skipping HTTP probing and port scan.\e[0m"
    touch httpx.txt ports.txt
else
    print_banner "Running HTTP probing..."
    httpx -l resolved.txt -title -tech-detect -status-code -no-color > httpx.txt

    if [ "$STEALTH" = false ]; then
        print_banner "Running port scanning with naabu..."
        naabu -list resolved.txt -top-ports 100 -silent > ports.txt
    else
        print_banner "Stealth mode enabled: Skipping port scan."
        touch ports.txt
    fi
fi


print_banner "Scraping JS files with gau..."
touch js_files.txt  # Ensure file exists even if empty

while read -r url; do
    gau --blacklist png,jpg,jpeg,gif,svg,woff,ttf,css "$url" 2>/dev/null | grep "\.js" || true
done < resolved.txt | sort -u > js_files.txt

if [ ! -s js_files.txt ]; then
    echo -e "\e[93m[!] No JS files found. Skipping JS analysis.\e[0m"
fi


if [ ! -s resolved.txt ]; then
    echo "[!] No resolved domains, skipping ffuf."
else
    mkdir -p ffuf_results
    for url in $(cat resolved.txt); do
        [[ "$url" =~ ^http ]] || url="https://$url"
        ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirb/common.txt \
            -of md -o "ffuf_results/$(echo "$url" | sed 's|https\?://||g').md" -t 25 || true
        sleep 1
    done
fi

print_banner "Running ffuf fuzzing..."
mkdir -p ffuf_results
for url in $(cat resolved.txt); do
    [[ "$url" =~ ^http ]] || url="https://$url"  # Ensure valid URL
    ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirb/common.txt \
        -of md -o ffuf_results/$(echo "$url" | sed 's|https\?://||g').md -t 25 || \
        echo -e "\e[93m[!] FFUF failed for $url\e[0m"
    sleep 1
done


print_banner "Running nuclei vulnerability scan..."
nuclei -l resolved.txt -t cves/ -severity medium,high,critical -v | tee nuclei-results.txt


print_banner "Running OSINT enrichment..."
echo "var mapMarkers = []" > osint/geo.js
while read -r domain; do
    ip=$(dig +short "$domain" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
    if [ -n "$ip" ]; then
        ipinfo=$(curl -s "https://ipinfo.io/$ip")
        echo "$ipinfo" > "osint/$domain-ipinfo.json"
        echo $ipinfo | jq -r '"mapMarkers.push({lat: \(.loc|split(",")[0]), lng: \(.loc|split(",")[1]), label: \"$domain ($ip)\"});"' >> osint/geo.js
# Only run AbuseIPDB check if API key is set and not placeholder
if [[ -n "${ABUSE_API_KEY:-}" && "$ABUSE_API_KEY" != "YOUR_ABUSEIPDB_API_KEY" ]]; then
    abuse_response=$(curl -sG --data-urlencode "ip=$ip" "https://api.abuseipdb.com/api/v2/check" \
        -H "Key: $ABUSE_API_KEY" \
        -H "Accept: application/json")

    if echo "$abuse_response" | jq . >/dev/null 2>&1; then
        echo "$abuse_response" > "osint/$domain-abuseipdb.json"
    else
        echo -e "\e[93m[!] Warning: AbuseIPDB returned invalid response for $ip. Skipping.\e[0m"
        touch "osint/$domain-abuseipdb.json"
    fi
else
    echo -e "\e[93m[!] AbuseIPDB API key not set or still default. Skipping AbuseIPDB enrichment.\e[0m"
    touch "osint/$domain-abuseipdb.json"
fi

        if ! shodan info >/dev/null 2>&1; then
    echo -e "\e[93m[!] Shodan CLI is not initialized. Skipping Shodan enrichment.\e[0m"
else
    shodan host "$ip" > "osint/$domain-shodan.txt"
fi
    fi
    sleep 1
done < resolved.txt

# Report generation and visualization logic to be appended as needed

print_banner "Generating HTML report..."
cat <<EOF > report.html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Recon Report - $TARGET</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.min.css">
    <style>
        body { background: #121212; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 2em; }
        h1, h2, h3 { color: #00ffe5; border-bottom: 1px solid #444; }
        pre { background: #1e1e1e; padding: 1em; overflow-x: auto; border-left: 4px solid #00ffe5; }
        section { margin-bottom: 2em; }
    </style>
</head>
<body>
    <h1>Recon Report for $TARGET</h1>

    <section>
        <h2>Resolved Subdomains</h2>
        <pre>$(cat resolved.txt)</pre>
    </section>

    <section>
        <h2>HTTP Probing Results</h2>
        <pre>$(cat httpx.txt)</pre>
    </section>

    <section>
        <h2>Nuclei Vulnerabilities</h2>
        <pre>$(cat nuclei-results.txt)</pre>
    </section>

    <section>
        <h2>JavaScript Files Found</h2>
        <pre>$(cat js_files.txt)</pre>
    </section>

    <section>
        <h2>OSINT Map</h2>
        <div id="map" style="height: 500px;"></div>
        <script src="https://unpkg.com/leaflet@1.9.3/dist/leaflet.js"></script>
        <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.3/dist/leaflet.css" />
        <script>
            var map = L.map('map').setView([20, 0], 2);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                maxZoom: 18,
            }).addTo(map);
        </script>
        <script>
        $(cat osint/geo.js)
        mapMarkers.forEach(marker => {
            L.marker([marker.lat, marker.lng]).addTo(map).bindPopup(marker.label);
        });
        </script>
    </section>

</body>
</html>
EOF

print_banner "HTML report generated as report.html"
