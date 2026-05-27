# Minecraft Server Scanner 2.2.0

A Windows-first PyQt desktop scanner for discovering Minecraft Java and Bedrock servers on networks you own or have permission to test.

## What's New In 2.2

- Tabbed desktop workspace for Scan, Results, History, Profiles, and Settings
- Real Java and Bedrock status checks through `mcstatus`
- Target inputs for single hosts, IP ranges, CIDR blocks, and imported target files
- SQLite-backed scan history, saved profiles, favorites, and notes
- Bounded concurrent scanning with cancellation, retries, progress, and validation
- CSV and JSON exports with richer result fields
- Live Monitor for repeated profile scans and in-app change alerts
- MCScans search/import and dataset metadata browsing

## Requirements

- Python 3.10 or higher
- Windows OS recommended

## Local Setup

1. Create a virtual environment:
   ```powershell
   python -m venv .venv
   ```
2. Activate it:
   ```powershell
   .\.venv\Scripts\Activate.ps1
   ```
3. Install dependencies:
   ```powershell
   python -m pip install -r requirements.txt
   ```

## Usage

Run the GUI:
```powershell
python minecraft_scanner.py
```

Or use the package entrypoint:
```powershell
python -m minecraft_server_scanner
```

Optional startup flags:
```powershell
python minecraft_scanner.py --target "192.168.1.0/24" --ports "25565,19132-19133" --edition both
python minecraft_scanner.py --profile "Home LAN" --autostart
```

Target examples:

- `192.168.1.25`
- `192.168.1.1-192.168.1.255`
- `192.168.1.0/24`
- `play.example.net`
- `@C:\path\to\targets.txt`

## Data

Scan history and profiles are stored in SQLite at:

```powershell
%LOCALAPPDATA%\MinecraftServerScanner\scanner.sqlite3
```

You can override this for testing or portable runs:

```powershell
python minecraft_scanner.py --db .\scanner-dev.sqlite3
```

## Live Monitor

The Monitor tab repeatedly scans a saved profile while the app is open. Choose a profile, pick an interval of 1, 5, 15, 30, or 60 minutes, then start monitoring.

- The first monitor run captures a baseline and does not create alerts.
- Later runs compare against the previous monitor run.
- Alerts are created for new servers, servers that went offline or came back online, version changes, MOTD changes, player-count changes, and latency changes of 100 ms or more.
- Monitor alerts stay inside the app and can be acknowledged, copied, or used to load the related scan run.
- Monitoring pauses or stops when you choose those controls; it does not run as a background service.

## MCScans Integration

The MCScans tab can search the public MCScans API, move through result pages 20 servers at a time, import selected or all visible search results into local scan history, copy server addresses, and create target profiles from MCScans results.

Dataset browsing uses the MCScans dataset API and shows dataset IDs, file names, sizes, line counts, modified times, and direct download URLs. Dataset files can be very large, so the app copies URLs for intentional downloads instead of downloading them automatically.

## Verification

```powershell
python -m pip check
python -m py_compile minecraft_scanner.py
python -m pytest
```
## Download Here
https://github.com/TommySanzCode/MinecraftServerScanner/releases/tag/v2.2.0-alpha
## Notes

- Only scan networks you own or have permission to test.
- The app warns before scans that include public/non-private IP ranges.
- Large-scale internet scanning is intentionally not the default workflow.

## License

This project is open source and available under the MIT License.
