# CrackMate
<p align="center">
  <img src="https://github.com/Ale210501/CrackMate/blob/main/logo-png.png" alt="CrackMate Logo" width="300"/>
</p>

**CrackMate** is a Python desktop application designed for **Wi-Fi auditing**, particularly for detecting wireless networks and capturing/cracking WPA/WPA2 handshakes. The app follows a modular architecture, with a graphical user interface (GUI) built using `Tkinter` and background processes managed via `threading` to keep the interface responsive.



## Architecture

- **GUI:** Developed using `Tkinter` (with `ttk` for styled widgets).
- **Threading:** Heavy operations like scanning, capturing, and cracking are executed in separate threads.
- **Thread communication:** Achieved using `queue.Queue` to safely update the GUI from background processes.



## Technologies & Libraries

### Core Language
- Python 3.x

### Standard Libraries
- `os`, `glob`, `shutil`, `subprocess`, `threading`, `queue`, `csv`, `re`, `time`, `datetime`, `sqlite3`, `signal`, `webbrowser`, `traceback`, `shlex`, `io.StringIO`

### External Python Libraries
- `folium`, `pandas`, `Pillow` *(optional)*

### External Tools (used via `subprocess`)
- **aircrack-ng suite:**
  - `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`
- `iproute2` (`ip`)
- `iw`
- `adb` (for retrieving GPS coordinates from Android devices)
- `sudo` (required for elevated privileges)



## Features

- Scan for nearby Wi-Fi networks and clients
- Capture WPA/WPA2 handshake packets
- Crack handshakes using wordlists
- Visualize networks and GPS coordinates on interactive maps using Folium
- Save scan and attack results to local databases
- Export results in CSV format
- Real-time logging and multi-threaded operations
- Android GPS data retrieval via ADB for map tagging
- Responsive and user-friendly graphical interface



## Installation

### Requirements

- Python 3.6+
- Linux system with:
  - Wireless network card supporting monitor mode
  - `aircrack-ng`, `iw`, `iproute2`, `adb`, `sudo` installed
- Recommended: Virtual environment

### Install Dependencies

```bash
pip install -r requirements.txt
```

Make sure the following tools are installed:

```bash
sudo apt install aircrack-ng iw iproute2 adb
```



## Usage

1. **Run the application**

```bash
sudo python3 crackmate.py
```

2. **Start scanning**
   - Choose a wireless interface and enter monitor mode
   - Scan for networks and clients

3. **Capture handshakes**
   - Select a target network and capture WPA/WPA2 handshake

4. **Crack the handshake**
   - Load a wordlist and start cracking

5. **Visualize**
   - View collected GPS coordinates and networks on the map



## Disclaimer

This tool is intended for **educational and authorized security auditing** only. Unauthorized use against networks you do not own or have explicit permission to audit is illegal and unethical. The developers take no responsibility for misuse.



## Contact

For questions or contributions, please open an issue or submit a pull request.
