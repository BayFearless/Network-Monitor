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
- 64-bit Python 3.10 - 3.14 (see [Supported Python versions](#supported-python-versions))
- [Npcap](https://npcap.com/) (required by Scapy to capture packets)
- Administrator rights (without them, data may be incomplete)

Python packages:

```
psutil
scapy
PySide6
```

## Supported Python versions

The program needs three packages. The Python range that works for all of them at once is **3.10 to 3.14 (64-bit)**.

| Package | Python versions it supports |
|---|---|
| `psutil` | 3.6 and newer |
| `scapy` | 3.7 - 3.14 |
| `PySide6` | 3.10 - 3.14 (current releases) |

| Python | Status |
|---|---|
| 3.15 and newer | Not supported yet (current PySide6 does not support it) |
| 3.14 | Supported |
| 3.10 - 3.13 | Supported |
| 3.9 and older | Not supported by current PySide6 (it needs 3.10+) |

Notes:
- These ranges come from the official requirements of each package, so they may change with new releases. Check the PyPI pages of the packages if you use a very new Python.
- Use **64-bit** Python. PySide6 does not provide 32-bit Windows packages.
- To see your version, run `python --version` in a command prompt.

## Installation

1. Click the green **Code** button at the top of this page and choose **Download ZIP**. The file is saved as `Network-Monitor-main.zip`.
2. Extract the ZIP file anywhere you like. This creates a folder called `Network-Monitor-main`. Open it, then open the `Network Monitor` folder inside; the `ENG` and `TR` folders are there.
3. Install [Python](https://www.python.org/downloads/) (tick **Add python.exe to PATH** during setup) and [Npcap](https://npcap.com/) (keep the default options; leave "WinPcap API-compatible Mode" unticked).
4. Open a command prompt and install the required packages once:

```
pip install psutil scapy PySide6
```

(Or run `pip install -r requirements.txt` inside the extracted folder.)

## Usage

Pick the language version you want:

- `Network Monitor/ENG/NetworkMonitor-ENG.py` - English
- `Network Monitor/TR/NetworkMonitor-TR.py` - Turkish (Türkçe)

There are three ways to start it:

**Option 1 - Double-click.** Double-click the `.py` file. The program opens, but without administrator rights some traffic may be missing. The window title shows **NOT ADMIN** in that case.

**Option 2 - As administrator (recommended).**
1. Open **Command Prompt** as administrator (search for `cmd`, right-click, **Run as administrator**).
2. Type `python ` (with a space after it), drag the `.py` file into the window and press **Enter**.

**Option 3 - Visual Studio Code as administrator (easiest for developers).**
1. Right-click **Visual Studio Code** and choose **Run as administrator**.
2. Go to **File > Open Folder** and select the extracted `Network-Monitor-main` folder.
3. Install the **Python** extension if VS Code asks for it.
4. Open the `.py` file you want and click the **Run** button (the triangle at the top right).

## Troubleshooting

| Error / problem | Cause | Solution |
|---|---|---|
| `'python' is not recognized` or `'pip' is not recognized` | Python is not on PATH | Reinstall Python and tick **Add python.exe to PATH**, or use `py` instead of `python` (for example `py -m pip install psutil scapy PySide6`) |
| `Could not find a version that satisfies the requirement PySide6` / `No matching distribution found` | Python is older than 3.10, newer than 3.14, or 32-bit | Check `python --version` and install a 64-bit Python between 3.10 and 3.14 |
| `ModuleNotFoundError: No module named 'scapy'` (or `psutil`, `PySide6`) | Packages are not installed, or they were installed for a different Python | Run `python -m pip install psutil scapy PySide6` with the same Python you use to start the program |
| `ImportError: DLL load failed while importing QtCore` | Microsoft Visual C++ Redistributable is missing | Install the latest **Microsoft Visual C++ Redistributable (x64)** and restart |
| `no Qt platform plugin could be initialized` | Broken PySide6 installation | Run `python -m pip install --force-reinstall PySide6` |
| `WARNING: No libpcap provider available` | Npcap is not installed | Install [Npcap](https://npcap.com/) and restart the program |
| Window title shows **NOT ADMIN** or some traffic is missing | The program runs without administrator rights | Start it as administrator (see Usage, options 2 and 3) |
| The table stays empty / no traffic is shown | Npcap missing, no administrator rights, or no active network traffic | Install Npcap, run as administrator, then open a website to generate traffic |
| The window opens and closes immediately when double-clicked | An error occurs at startup and the window closes before you can read it | Start the program from Command Prompt (Usage, option 2) to see the error message |
| The Country column shows `…` for a long time | ip-api.com cannot be reached (no internet, firewall, or rate limit) | Check your connection and wait; failed lookups are retried automatically after about a minute |
| The Country column shows `—` | Country lookup is switched off | Tick **Look up country** at the top of the window |
| Many entries under "Unmatched traffic" | Very short-lived connections close before the process list updates | This is normal and not an error |
| Antivirus or firewall warns about the program or Npcap | Packet capture tools are sometimes flagged | Read the source code, and download Npcap only from npcap.com. Add an exception if you trust it |

If your problem is not listed, open an issue and include the full error message and your Python version.

## Project structure

```
Network-Monitor-main/        (folder name after extracting the ZIP)
├── Network Monitor/
│   ├── ENG/
│   │   └── NetworkMonitor-ENG.py   # English version
│   └── TR/
│       └── NetworkMonitor-TR.py    # Turkish version
├── .gitignore
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
