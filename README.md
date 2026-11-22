# Network Monitor

A lightweight, per-application network traffic monitor for **Windows**. It shows which apps are talking to the internet, how much data they send and receive, which IP addresses and countries they connect to, and warns you when an app contacts a country it has never connected to before.

## Features

- Live per-app upload / download totals
- Top remote IP addresses per app, with a detailed view (double-click a row) showing domain names, countries and traffic per IP
- Country lookup for public IPs (can be turned off)
- **New country warning:** an app that connects to a country it has not used before is highlighted
- Detection of reused PIDs and `svchost.exe` service names
- Search box: filter by app, PID, IP, domain or country
- Copy selected cells with `Ctrl+C`
- Shows traffic that could not be matched to an app, so nothing is silently hidden

## Requirements

- Windows 10 / 11 (the code uses Windows-specific APIs)
- Python 3.9 or newer
- [Npcap](https://npcap.com/) (required by Scapy to capture packets)
- Administrator rights (without them, data may be incomplete)

Python packages:

```
psutil
scapy
PySide6
```

## Installation

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
pip install -r requirements.txt
```

## Usage

Run the script from an **administrator** terminal.

English interface:

```bash
python eng/network_monitor.py
```

Turkish interface (Türkçe arayüz):

```bash
python tr/network_monitor.py
```

## Project structure

```
.
├── eng/
│   └── network_monitor.py   # English version
├── tr/
│   └── network_monitor.py   # Turkish version
├── requirements.txt
└── README.md
```

## How it works

1. Scapy sniffs packets on all interfaces.
2. `psutil` maps local ports to processes.
3. Traffic is added up per process and per remote IP.
4. Country names come from [ip-api.com](https://ip-api.com/) and domain names from reverse DNS.
5. Countries seen for each app are saved to `known_countries.json` next to the script. On the next start, any new country for that app is flagged.

## Privacy

- When **Look up country** is enabled, the public IP addresses your apps connect to are sent to ip-api.com. The connection uses plain HTTP, so it is not encrypted.
- The free tier of ip-api.com is limited to non-commercial use and has a rate limit.
- Untick the checkbox to disable country lookups completely. Reverse DNS lookups still go through your normal DNS resolver.
- `known_countries.json` contains your connection history. Do not commit or share it.

## Limitations

- Windows only.
- Very short-lived connections may appear as "Unmatched traffic" because they close before the process list is updated.
- ICMP (ping) traffic has no port, so Windows cannot tell which process sent it.



