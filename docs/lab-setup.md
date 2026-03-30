# Lab Setup Guide

This guide sets up the ARTASF test lab: a DVWA target VM and a Windows 11 attacker host sharing a VirtualBox host-only network.

---

## Prerequisites

| Component | Version |
|---|---|
| VirtualBox | 7.x |
| Ubuntu Server ISO | 22.04 LTS |
| DVWA | latest (GitHub) |
| Metasploit Framework | 6.x |
| Python | 3.11+ |
| nmap | 7.x |

---

## 1. Create the Host-Only Network

1. Open **VirtualBox → File → Tools → Network Manager**
2. Create a host-only adapter: `192.168.56.1/24`, DHCP enabled
3. Note the adapter name (e.g. `vboxnet0` on Linux, `VirtualBox Host-Only Ethernet Adapter` on Windows)

---

## 2. Build the Target VM (Ubuntu + DVWA)

### 2a. Install Ubuntu Server

1. Create a new VM: 2 vCPU, 2 GB RAM, 20 GB disk
2. Attach the host-only adapter (in addition to NAT for initial setup)
3. Install Ubuntu Server (minimal), note the IP on the host-only interface

### 2b. Install DVWA

```bash
sudo apt update && sudo apt install -y apache2 php php-mysqli mariadb-server git

# Clone DVWA
sudo git clone https://github.com/digininja/DVWA /var/www/html/dvwa

# Permissions
sudo chown -R www-data:www-data /var/www/html/dvwa
sudo chmod -R 755 /var/www/html/dvwa

# Configure DB
sudo mysql -e "CREATE DATABASE dvwa; CREATE USER 'dvwa'@'localhost' IDENTIFIED BY 'p@ssw0rd'; GRANT ALL ON dvwa.* TO 'dvwa'@'localhost';"

# Copy config
cd /var/www/html/dvwa/config
sudo cp config.inc.php.dist config.inc.php
# Edit DB credentials to match above
sudo nano config.inc.php

sudo systemctl enable --now apache2 mariadb
```

### 2c. Initialise DVWA

Navigate to `http://<VM_IP>/dvwa/setup.php` and click **Create / Reset Database**.

Default credentials: `admin` / `password`

Set security level to **Low** for initial testing: **DVWA Security → Low → Submit**.

---

## 3. Configure the Attacker Host (Windows 11)

### 3a. Install Metasploit

Download and install from [metasploit.com](https://metasploit.com). After installation:

```powershell
# Start Metasploit RPC daemon (runs in background)
msfrpcd -P msf -S -a 127.0.0.1 -p 55553
```

### 3b. Install nmap

Download from [nmap.org](https://nmap.org/download.html) and add to PATH.

### 3c. Install ARTASF

```powershell
git clone https://github.com/Aayush-GBC/autonomous-redteam-framework
cd autonomous-redteam-framework
pip install -e .
cp .env.example .env
```

Edit `.env`:

```ini
ANTHROPIC_API_KEY=<your-anthropic-api-key>   # from console.anthropic.com
TARGET_NETWORK=192.168.56.0/24
LHOST=192.168.56.1                   # host-only adapter IP of the Windows host
MSF_PASSWORD=msf
```

---

## 4. Verify Connectivity

```powershell
# Ping the target
ping 192.168.56.101

# Quick nmap check
nmap -p 80 192.168.56.101

# Check DVWA is up
curl http://192.168.56.101/dvwa/login.php
```

---

## 5. Run the Framework

```powershell
# Dry-run (no exploits)
artasf run --dry-run

# Full pipeline
artasf run --target 192.168.56.0/24
```

Artifacts are written to `artifacts/` — reports in `artifacts/reports/`, loot in `artifacts/loot/`.
