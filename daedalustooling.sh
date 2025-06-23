#!/bin/bash

# Tool Installer for DAEDALUS
# Installs: amass, subfinder, httpx, nuclei, assetfinder, dnsx, naabu, gau, ffuf

echo "[+] Updating package lists..."
sudo apt update -y && sudo apt install -y unzip curl git wget make build-essential

echo "[+] Installing Go (if not installed)..."
if ! command -v go &> /dev/null; then
    wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
    source ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
fi

echo "[+] Creating Go bin directory..."
mkdir -p ~/go/bin
export PATH=$PATH:~/go/bin

echo "[+] Installing tools with go install..."

go install github.com/owasp-amass/amass/v4/...@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf/v2@latest

echo "[+] All tools installed. You may need to restart your shell or run:"
echo 'export PATH=$PATH:~/go/bin'
