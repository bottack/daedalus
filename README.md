Daedalus Revised - Automated Recon Suite

Daedalus Revised is a comprehensive bash-based reconnaissance automation tool for cybersecurity professionals. Designed for passive and semi-active enumeration with optional OSINT enrichment, Daedalus gathers, analyzes, and presents recon data for a given domain in a beautifully styled HTML report. It defaults to a no-API, stealth-aware mode for cautious engagement, but can be escalated for full API-powered enrichment.



Features



Passive Subdomain Enumeration: subfinder, assetfinder, crt.sh, amass

DNS & HTTP Probing: dnsx, httpx

Optional Port Scanning: naabu (disabled by default in stealth mode)

JS File Discovery: gau

Directory Fuzzing: ffuf (with markdown output)

Vulnerability Scanning: nuclei (CVEs, medium+ severity)

IP OSINT Enrichment: abuseipdb, ipinfo.io, shodan

Geolocation Mapping: IP markers rendered via Leaflet.js in HTML report

HTML Report Generation: color-coded, styled output with embedded mapping

Dependency Checking: auto-install fallback with warnings

Safe Execution: hardened bash with fail-fast, traps, and validation



Dependencies

This script requires the following tools:

subfinder, assetfinder, amass, dnsx, httpx, naabu, gau, ffuf, nuclei, jq, zip, shodan, cron

The script will attempt to install missing tools using go install or apt-get.



Installation

Clone this repo and ensure the script is executable:

git clone https://github.com/your-repo/daedalus-revised.git
cd daedalus-revised
chmod +x daedalus.sh



API Keys

To use the AbuseIPDB and Shodan enrichment features:

Replace YOUR_ABUSEIPDB_API_KEY in the script with your valid key.

Ensure Shodan CLI is authenticated (shodan init <YOUR_KEY>).



Usage

./daedalus.sh <domain> [--api] [--stealth]

Arguments:

<domain>: Target domain for reconnaissance

--api: Enables API sources (e.g. full subfinder sources, abuseipdb)

--stealth: Disables active port scanning



Output

A folder recon-<target>-<timestamp>/ is created, containing:

resolved.txt, httpx.txt, ports.txt, etc.

osint/ folder with JSON and Shodan info

report.html: full visual recon summary with map

Open the report in your browser:

xdg-open report.html



To-Do / Roadmap





Disclaimer

Use Daedalus only on targets you are authorized to test. The authors are not responsible for misuse.
