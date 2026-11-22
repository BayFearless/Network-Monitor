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

1. Click the green **Code** button at the top of this page and choose **Download ZIP**.
2. Extract the ZIP file anywhere you like.
3. Install [Python](https://www.python.org/downloads/) (tick **Add python.exe to PATH** during setup) and [Npcap](https://npcap.com/).
4. Open a command prompt and install the required packages once:

```
pip install psutil scapy PySide6
```

(Or run `pip install -r requirements.txt` inside the extracted folder.)

## Usage

Pick the language version you want:

- `ENG/NetworkMonitor-ENG.py` - English
- `TR/NetworkMonitor-TR.py` - Turkish (Türkçe)

There are two ways to start it:

**Option 1 - Double-click.** Double-click the `.py` file. The program opens, but without administrator rights some traffic may be missing. The window title shows **NOT ADMIN** in that case.

**Option 2 - As administrator (recommended).**
1. Open **Command Prompt** as administrator (search for `cmd`, right-click, **Run as administrator**).
2. Type `python ` (with a space after it), drag the `.py` file into the window and press **Enter**.

## Project structure

```
Network-Monitor/
├── ENG/
│   └── NetworkMonitor-ENG.py   # English version
├── TR/
│   └── NetworkMonitor-TR.py    # Turkish version
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

## License

Add a license of your choice (for example MIT) as a `LICENSE` file.
