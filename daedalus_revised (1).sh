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

# Ensure API key is set
if grep -q 'YOUR_ABUSEIPDB_API_KEY' "$0"; then
    echo -e "\e[91m[!] You must set your AbuseIPDB API key in the script before continuing.\e[0m"
    exit 1
fi

mkdir -p "$WORKDIR/osint"
cd "$WORKDIR" || exit 1

print_banner "Starting Recon on: $TARGET"
print_banner "NO_API Mode: $NO_API | Stealth Mode: $STEALTH"

print_banner "Running subdomain enumeration..."
if [ "$NO_API" = true ]; then
    subfinder -d "$TARGET" -sources anubis,crtsh,alienvault,threatminer -silent > subfinder.txt
else
    subfinder -d "$TARGET" -silent > subfinder.txt
fi

assetfinder --subs-only "$TARGET" > assetfinder.txt
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > crtsh.txt
amass enum -passive -d "$TARGET" > amass.txt

cat subfinder.txt assetfinder.txt crtsh.txt amass.txt | sort -u > all_subs.txt

if [ ! -s all_subs.txt ]; then
    echo -e "\e[91m[!] No subdomains found, exiting.\e[0m"
    exit 1
fi

print_banner "Running DNS resolution..."
dnsx -l all_subs.txt -silent -resp-only > resolved.txt

print_banner "Running HTTP probing..."
cat resolved.txt | httpx -silent -title -tech-detect -status-code > httpx.txt

if [ "$STEALTH" = false ]; then
    print_banner "Running port scanning with naabu..."
    naabu -i resolved.txt -top-ports 100 -silent > ports.txt
else
    print_banner "Stealth mode enabled: Skipping port scan."
fi

print_banner "Scraping JS files with gau..."
cat resolved.txt | gau --blacklist png,jpg,jpeg,gif,svg,woff,ttf,css | grep ".js" | sort -u > js_files.txt

print_banner "Running ffuf fuzzing..."
mkdir -p ffuf_results
for url in $(cat resolved.txt); do
    ffuf -u "$url/FUZZ" -w /usr/share/wordlists/dirb/common.txt -of md -o ffuf_results/$(echo "$url" | sed 's|https\?://||g').md -t 25
    sleep 1
done

print_banner "Running nuclei vulnerability scan..."
nuclei -l resolved.txt -t cves/ -severity medium,high,critical -silent > nuclei-results.txt

print_banner "Running OSINT enrichment..."
echo "var mapMarkers = []" > osint/geo.js
while read -r domain; do
    ip=$(dig +short "$domain" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
    if [ -n "$ip" ]; then
        ipinfo=$(curl -s "https://ipinfo.io/$ip")
        echo "$ipinfo" > "osint/$domain-ipinfo.json"
        echo $ipinfo | jq -r '"mapMarkers.push({lat: \(.loc|split(",")[0]), lng: \(.loc|split(",")[1]), label: \"$domain ($ip)\"});"' >> osint/geo.js
        curl -sG --data-urlencode "ip=$ip" "https://api.abuseipdb.com/api/v2/check" \
            -H "Key: YOUR_ABUSEIPDB_API_KEY" -H "Accept: application/json" > "osint/$domain-abuseipdb.json"
        shodan host "$ip" > "osint/$domain-shodan.txt"
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
