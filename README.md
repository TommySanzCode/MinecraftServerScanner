# Minecraft Server Scanner

A Windows application that scans for Minecraft servers in bulk on your local network.

## Features

- Scan a range of IP addresses for Minecraft servers
- Display server information including version and player count
- Multi-threaded scanning for faster results
- Simple and intuitive GUI
- Copy server details to clipboard

## Requirements

- Python 3.8 or higher
- Windows OS

## Installation

1. Clone or download this repository
2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```
   python mcscanner.py
   ```

2. Enter the IP range you want to scan (e.g., 192.168.1.1 to 192.168.1.255)
3. Enter the Minecraft server port (default is 25565)
4. Click "Start Scan" to begin scanning
5. Found servers will appear in the table below

## Screenshot

![Minecraft Server Scanner](screenshot.png)

## Notes

- The scanner uses multi-threading to scan multiple IPs simultaneously
- Only Java Edition servers are supported
- Scanning large IP ranges may take some time
- Be mindful of network policies when scanning networks you don't own

## License

This project is open source and available under the MIT License.
