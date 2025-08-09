# GTA V UDP Session Monitor

A real-time network monitoring tool that detects and tracks GTA V multiplayer sessions by analyzing UDP traffic patterns. Features an animated GUI interface with player geolocation, session statistics, and live traffic analysis.

## Features

- **Real-time Session Detection** - Monitors UDP traffic on GTA V ports (6672, 61455-61458)
- **Player Geolocation** - Shows approximate location of detected players
- **Live Statistics** - Active players, session totals, packet counts, and uptime
- **Animated Interface** - Nice looking GUI
- **Traffic Analysis** - Enhanced packet filtering and validation
- **Session Management** - Tracks player join/leave events with timestamps

## Screenshots

![GTA V Monitor Interface](https://via.placeholder.com/800x600/0a0a0a/00ff41?text=GTA+V+UDP+Monitor)

## Requirements

### System Requirements
- **Windows 10/11** (Required for network interface access)
- **Administrator privileges** (Required for packet capture)
- **Active internet connection** (For geolocation services)
- **Python 3.8+**

### Python Dependencies
```
tkinter (usually included with Python)
scapy
requests
```

## Installation

### Option 1: Standalone Executable (Recommended)

**No Python installation required!**

1. **Download the compiled executable**
   - Download `1y.exe` from the releases section
   - No Python or additional libraries needed

2. **Install Packet Capture Dependencies**
   - Download Npcap from [npcap.com](https://npcap.com/#download)
   - Run the installer **as Administrator**
   - During installation, check **"Install Npcap in WinPcap API-compatible Mode"**

3. **Run the Application**
   - Right-click `1y.exe` → "Run as administrator"
   - The application will start immediately

### Option 2: Python Source Code

If you prefer to run from source or want to modify the code:

#### Step 1: Install Python
1. Download Python 3.8+ from [python.org](https://www.python.org/downloads/)
2. During installation, **check "Add Python to PATH"**
3. Verify installation by opening Command Prompt and typing:
   ```cmd
   python --version
   ```

#### Step 2: Install Required Packages
Open **Command Prompt as Administrator** and run:
```cmd
pip install scapy requests
```

#### Step 3: Install Packet Capture Dependencies
For Windows, you'll need **Npcap** (WinPcap successor):
1. Download Npcap from [npcap.com](https://npcap.com/#download)
2. Run the installer **as Administrator**
3. During installation, check **"Install Npcap in WinPcap API-compatible Mode"**

#### Step 4: Download the Monitor
1. Clone this repository or download the Python file
2. Save it as `gta_monitor.py` in a folder of your choice

## Usage

### Starting the Monitor

#### Using the Executable (1y.exe)
1. **Right-click `1y.exe`** → **"Run as administrator"** (This is crucial!)
2. The application will launch immediately with the GUI interface

#### Using Python Source Code
1. **Run as Administrator** (This is crucial!)
   - Right-click Command Prompt → "Run as administrator"
   - Navigate to your script directory:
     ```cmd
     cd C:\path\to\your\script
     ```
   - Run the monitor:
     ```cmd
     python gta_monitor.py
     ```

2. **Alternative: Create Administrator Shortcut**
   - For executable: Right-click `1y.exe` → "Create shortcut" → Right-click shortcut → "Properties" → "Advanced" → Check "Run as administrator"
   - For Python: Right-click `gta_monitor.py` → "Create shortcut" → Right-click shortcut → "Properties" → Click "Advanced" → Check "Run as administrator"

### Using the Interface

1. **Select Network Interface**
   - Choose your active network adapter from the dropdown
   - Usually named something like "Ethernet" or "Wi-Fi"

2. **Start Monitoring**
   - Click **"◆ START"** to begin packet capture
   - The status will change to "MONITORING"

3. **Monitor Sessions**
   - Detected players appear in the "ACTIVE PLAYERS" section
   - Click on any IP address for detailed player information
   - Location data appears automatically (if enabled)

4. **Controls**
   - **◆ STOP** - Stop monitoring
   - **◇ CLEAR** - Clear the detection log
   - **⟲ RESTART** - Restart the entire application
   - **AUTO-SCROLL** - Toggle automatic log scrolling
   - **SHOW GEO** - Toggle geolocation display

### Reading the Interface

- **Green Text** - Active players and important information
- **Orange Text** - Warnings and status changes
- **Blue Text** - Informational messages and locations
- **Red Text** - Errors and critical actions

## Troubleshooting

### Common Issues

**❌ "Run as Administrator!" Error**
- Solution: Always run `1y.exe` or Python script as Administrator
- For executable: Right-click `1y.exe` → "Run as administrator"
- For Python: Run Command Prompt as Administrator first

**❌ "No module named 'scapy'" Error**
- Solution: Install scapy using `pip install scapy`

**❌ "Error loading interfaces" Message**
- Solution: Install Npcap and restart your computer

**❌ No Players Detected**
- Make sure GTA V Online is running
- Verify you're in an online session (not Story Mode)
- Try different network interfaces in the dropdown
- Check your firewall isn't blocking the application

**❌ Geolocation Not Working**
- Check your internet connection
- Some IPs may not have location data available
- VPN users may show incorrect locations

### Performance Tips

- **Close unnecessary programs** to reduce network noise
- **Disable VPN** while monitoring for accurate results
- **Use Ethernet connection** for better packet capture reliability
- **Monitor for 30+ seconds** to detect all session players

## How It Works

The monitor analyzes UDP network traffic to detect GTA V multiplayer sessions:

1. **Packet Capture** - Monitors network interfaces for UDP traffic
2. **Port Filtering** - Focuses on known GTA V ports (6672, 61455-61458)
3. **Traffic Validation** - Filters packets by size and content patterns
4. **IP Analysis** - Identifies public IP addresses (excludes local/private IPs)
5. **Geolocation** - Queries IP location databases for player locations
6. **Session Tracking** - Maintains active player lists with join/leave detection

## Privacy & Legal Notes

- **Local Operation** - All monitoring is performed on your local network traffic only
- **Public Data** - Only analyzes publicly routable IP addresses
- **No Game Modification** - Does not modify or interact with GTA V directly
- **Educational Purpose** - Intended for network analysis and educational use
- **Respect Privacy** - Use responsibly and respect other players' privacy

## Technical Details

### Monitored Ports
- **6672** - Primary GTA V multiplayer port
- **61455-61458** - Additional session ports

### Network Requirements
- Captures UDP traffic only
- Requires raw socket access (Administrator privileges)
- Filters private/local network ranges automatically

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is provided for educational purposes. Use responsibly and in accordance with your local laws and Rockstar Games' Terms of Service.

## Support

If you encounter issues:
1. Check the troubleshooting section above
2. Ensure all requirements are met
3. Verify Administrator privileges
4. Check that Npcap is properly installed

---

**⚠️ Important:** Always run this tool as Administrator and use it responsibly. This tool is for educational and network analysis purposes only.
